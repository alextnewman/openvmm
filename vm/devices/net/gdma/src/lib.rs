// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![forbid(unsafe_code)]
#![expect(missing_docs)]

mod bnic;
mod dma;
mod hwc;
mod queues;
pub mod resolver;

use chipset_device::ChipsetDevice;
use chipset_device::io::IoResult;
use chipset_device::mmio::MmioIntercept;
use chipset_device::mmio::RegisterMmioIntercept;
use chipset_device::pci::PciConfigSpace;
use chipset_device::poll_device::PollDevice;
use device_emulators::ReadWriteRequestType;
use device_emulators::read_as_u32_chunks;
use device_emulators::write_as_u32_chunks;
use futures::FutureExt;
use gdma_defs::CqEqDoorbellValue;
use gdma_defs::DB_CQ;
use gdma_defs::DB_EQ;
use gdma_defs::DB_RQ;
use gdma_defs::DB_RQ_CLIENT_DATA;
use gdma_defs::DB_SQ;
use gdma_defs::PAGE_SIZE64;
use gdma_defs::RegMap;
use gdma_defs::SMC_MSG_TYPE_DESTROY_HWC_VERSION;
use gdma_defs::SMC_MSG_TYPE_ESTABLISH_HWC_VERSION;
use gdma_defs::SMC_MSG_TYPE_REPORT_HWC_TIMEOUT_VERSION;
use gdma_defs::SmcMessageType;
use gdma_defs::SmcProtoHdr;
use gdma_defs::WqDoorbellValue;
use guestmem::GuestMemory;
use hwc::Devices;
use hwc::HwControl;
use inspect::Inspect;
use inspect::InspectMut;
use net_backend::Endpoint;
use net_backend_resources::mac_address::MacAddress;
use pci_core::capabilities::extended::PciExtendedCapability;
use pci_core::capabilities::extended::sriov::SriovExtendedCapability;
use pci_core::capabilities::msix::MsixEmulator;
use pci_core::capabilities::pci_express::FlrHandler;
use pci_core::capabilities::pci_express::PciExpressCapability;
use pci_core::cfg_space_emu::BarMemoryKind;
use pci_core::cfg_space_emu::ConfigSpaceType0Emulator;
use pci_core::cfg_space_emu::DeviceBars;
use pci_core::msi::MsiTarget;
use pci_core::spec::caps::pci_express::DevicePortType;
use pci_core::spec::hwid::ClassCode;
use pci_core::spec::hwid::HardwareIds;
use pci_core::spec::hwid::ProgrammingInterface;
use pci_core::spec::hwid::Subclass;
use queues::Queues;
use std::ops::Range;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use task_control::TaskControl;
use thiserror::Error;
use vmcore::device_state::ChangeDeviceState;
use vmcore::save_restore::RestoreError;
use vmcore::save_restore::SaveError;
use vmcore::save_restore::SaveRestore;
use vmcore::save_restore::SavedStateNotSupported;
use vmcore::vm_task::VmTaskDriverSource;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

const REGMAP: Range<usize> = 0..40;
const SHMEM: Range<usize> = 40..72;
const SHMEM_LEN: usize = SHMEM.end - SHMEM.start;
const DOORBELLS: Range<usize> = 4096..8192;

/// PF (bare-metal host) BAR0 register window, exposed only when the device is
/// presented as a physical function. It is disjoint from the VF [`RegMap`]
/// (which stays at [`REGMAP`]) and sits just above [`SHMEM`]; the highest
/// register the driver reads is the SR-IOV config base at
/// [`gdma_defs::pf_regs::SRIOV_REG_CFG_BASE_OFF`] (a `u64`), so the window ends
/// at `0x110`.
const PF_REGS: Range<usize> = 0x48..0x110;
const PF_REGS_LEN: usize = PF_REGS.end - PF_REGS.start;

/// Build the PF BAR0 register window that the Linux driver's
/// `mana_gd_init_pf_regs` reads. The driver computes
/// `shm_base = bar0 + sriov_base_off + sriov_shm_off` and
/// `db_page_base = bar0 + db_page_off`, then validates ranges/alignment. We
/// place the SR-IOV config base at BAR0 itself (`sriov_base_off = 0`), the
/// shared-memory window at [`SHMEM`], and the doorbell page at [`DOORBELLS`],
/// so the PF view resolves to the very same SMC/doorbell regions the VF map
/// exposes — keeping a single source of truth for the device's memory layout.
fn build_pf_regs() -> [u8; PF_REGS_LEN] {
    let mut regs = [0u8; PF_REGS_LEN];
    let mut put = |abs: usize, bytes: &[u8]| {
        let off = abs - PF_REGS.start;
        regs[off..off + bytes.len()].copy_from_slice(bytes);
    };
    // sriov_shm_off (relative to the SR-IOV base, which is 0): SHMEM start.
    put(
        gdma_defs::pf_regs::SHM_OFF,
        &(SHMEM.start as u64).to_ne_bytes(),
    );
    // Doorbell page region.
    put(
        gdma_defs::pf_regs::DB_PAGE_OFF,
        &(DOORBELLS.start as u64).to_ne_bytes(),
    );
    put(
        gdma_defs::pf_regs::DB_PAGE_SIZE,
        &(DOORBELLS.len() as u32).to_ne_bytes(),
    );
    // The SR-IOV register block is the BAR base itself.
    put(
        gdma_defs::pf_regs::SRIOV_REG_CFG_BASE_OFF,
        &0u64.to_ne_bytes(),
    );
    regs
}

/// Length of the PF capability register block (see [`pf_cap`]).
const PF_CAP_REGS_LEN: usize = 0x68;

/// True-PF (`pf_caps`) BAR0 register map.
///
/// A privileged "true PF" client reads a different BAR0 register surface than a
/// VF: a region-descriptor table at the base of BAR0, where each device
/// sub-region is described by a `{ u64 base_offset, u32 size }` pair (a handful
/// of regions share a single size field). The client validates that every
/// advertised region resolves inside BAR0 (`base_offset + size <= bar_len`), so
/// each descriptor must point within BAR0; regions the emulator does not
/// implement advertise size 0, which is in-bounds and read as "absent".
///
/// This surface is mutually exclusive with the VF [`RegMap`] (and the
/// `bm_hostmode` [`PF_REGS`] window), which is why it is only served when
/// `pf_caps` is set.
const PF_DESC: Range<usize> = 0..0x148;
const PF_DESC_LEN: usize = PF_DESC.end - PF_DESC.start;

/// Device version advertised in the true-PF descriptor table
/// ([`pf_desc::VERSION`]): major 2, minor 0, micro 0. The high byte selects the
/// emulated platform generation (2); a true-PF client accepts this and selects
/// its matching generation behavior. (Generation 1 is intentionally not
/// emulated.)
const PF_DESC_VERSION: u32 = 2 << 24;

/// Field offsets within the true-PF region-descriptor table ([`PF_DESC`]). Each
/// region is a `{ u64 base_offset, u32 size }` pair unless noted; `*_OFF` is the
/// base offset and `*_SZ` the size. The doorbell, capability, and SR-IOV regions
/// are the only ones the emulator populates; the rest advertise size 0.
mod pf_desc {
    /// Version dword: micro (bits 15:0), minor (bits 23:16), major (bits 31:24).
    pub const VERSION: usize = 0x00;
    pub const CAP_ZONE_OFF: usize = 0x48;
    pub const CAP_ZONE_SZ: usize = 0x50;
    /// Status and control regions reuse [`CAP_ZONE_SZ`] as their length.
    pub const STATUS_ZONE_OFF: usize = 0x58;
    pub const CONTROL_ZONE_OFF: usize = 0x60;
    pub const SEND_WQ_CTX_OFF: usize = 0x68;
    pub const SEND_WQ_CTX_SZ: usize = 0x70;
    pub const RECV_WQ_CTX_OFF: usize = 0x78;
    pub const RECV_WQ_CTX_SZ: usize = 0x80;
    pub const CQ_CTX_OFF: usize = 0x88;
    pub const CQ_CTX_SZ: usize = 0x90;
    pub const EQ_CTX_OFF: usize = 0x98;
    pub const EQ_CTX_SZ: usize = 0xA0;
    pub const DOORBELL_OFF: usize = 0xC8;
    pub const DOORBELL_SZ: usize = 0xD0;
    pub const CQ_MOD_CTX_OFF: usize = 0xD8;
    pub const CQ_MOD_CTX_SZ: usize = 0xE0;
    pub const SCHEDULER_OFF: usize = 0xE8;
    pub const SCHEDULER_SZ: usize = 0xF0;
    pub const XLATE_OFF: usize = 0xF8;
    pub const XLATE_SZ: usize = 0x100;
    pub const SRIOV_OFF: usize = 0x108;
    pub const SRIOV_SZ: usize = 0x110;
    pub const DEBUG_OFF: usize = 0x118;
    pub const DEBUG_SZ: usize = 0x120;
}

/// Field offsets within the PF capability register zone ([`PF_CAP_ZONE`]).
/// Each field occupies an aligned 8-byte slot and holds a `u32`.
mod pf_cap {
    pub const HW_CAPABILITIES: usize = 0x00;
    pub const FEATURE_FLAGS: usize = 0x04;
    pub const MAX_SEND_QUEUES: usize = 0x08;
    pub const MAX_RECEIVE_QUEUES: usize = 0x10;
    pub const MAX_COMPLETION_QUEUES: usize = 0x18;
    pub const MAX_EVENT_QUEUES: usize = 0x20;
    pub const MAX_CQ_MODERATION_CONTEXTS: usize = 0x28;
    pub const NUM_VIRTUAL_FUNCTIONS: usize = 0x30;
    pub const MAX_DOORBELL_PAGES: usize = 0x38;
    pub const MAX_MODERATED_COMPLETION_QUEUES: usize = 0x40;
    pub const MAX_TX_PAYLOAD_LEN: usize = 0x48;
    pub const NUM_PHYSICAL_FUNCTIONS: usize = 0x50;
    pub const MAX_MSIX_ENTRIES: usize = 0x58;
    pub const PF_MAX_MSIX_ENTRIES: usize = 0x60;
}

const PF_CAP_NUM_PHYSICAL_FUNCTIONS: u32 = 1;
const PF_CAP_NUM_VIRTUAL_FUNCTIONS: u32 = 0;
const PF_CAP_MAX_DOORBELL_PAGES: u32 = 1;
const PF_CAP_MAX_MSIX_ENTRIES: u32 = 64;
const PF_CAP_MAX_TX_PAYLOAD_LEN: u32 = 1514;

/// Build the PF capability register zone ([`PF_CAP_ZONE`]). The queue maxima
/// are taken from the live queue allocation so the zone stays consistent with
/// the `GDMA_QUERY_MAX_RESOURCES` response; the remaining limits are fixed.
fn build_pf_cap_regs(queues: &Queues) -> [u8; PF_CAP_REGS_LEN] {
    let mut regs = [0u8; PF_CAP_REGS_LEN];
    let mut put = |off: usize, value: u32| {
        regs[off..off + 4].copy_from_slice(&value.to_ne_bytes());
    };
    put(pf_cap::HW_CAPABILITIES, 0);
    put(pf_cap::FEATURE_FLAGS, 0);
    put(pf_cap::MAX_SEND_QUEUES, queues.max_sqs());
    put(pf_cap::MAX_RECEIVE_QUEUES, queues.max_rqs());
    put(pf_cap::MAX_COMPLETION_QUEUES, queues.max_cqs());
    put(pf_cap::MAX_EVENT_QUEUES, queues.max_eqs());
    put(pf_cap::MAX_CQ_MODERATION_CONTEXTS, 0);
    put(pf_cap::NUM_VIRTUAL_FUNCTIONS, PF_CAP_NUM_VIRTUAL_FUNCTIONS);
    put(pf_cap::MAX_DOORBELL_PAGES, PF_CAP_MAX_DOORBELL_PAGES);
    put(pf_cap::MAX_MODERATED_COMPLETION_QUEUES, 0);
    put(pf_cap::MAX_TX_PAYLOAD_LEN, PF_CAP_MAX_TX_PAYLOAD_LEN);
    put(
        pf_cap::NUM_PHYSICAL_FUNCTIONS,
        PF_CAP_NUM_PHYSICAL_FUNCTIONS,
    );
    put(pf_cap::MAX_MSIX_ENTRIES, PF_CAP_MAX_MSIX_ENTRIES);
    put(pf_cap::PF_MAX_MSIX_ENTRIES, PF_CAP_MAX_MSIX_ENTRIES);
    regs
}

/// True-PF capability register zone, placed above the descriptor table
/// ([`PF_DESC`]) and below [`DOORBELLS`]. Holds the resource-limit registers
/// built by [`build_pf_cap_regs`]; the descriptor table's capability descriptor
/// points a true-PF client here.
const PF_CAP_ZONE: Range<usize> = 0x200..0x200 + PF_CAP_REGS_LEN;

/// True-PF SR-IOV configuration register zone. A true-PF client reads the
/// SR-IOV descriptor from [`PF_DESC`] to locate this zone, then reads the
/// shared-memory descriptor within it ([`pf_sriov`]) to locate the SMC window.
const PF_SRIOV_ZONE: Range<usize> = 0x300..0x380;
const PF_SRIOV_ZONE_LEN: usize = PF_SRIOV_ZONE.end - PF_SRIOV_ZONE.start;

/// Field offsets within the SR-IOV configuration zone ([`PF_SRIOV_ZONE`]),
/// relative to the zone base. The shared-memory descriptor locates the SMC
/// window the client uses to bring up the hardware channel.
mod pf_sriov {
    /// `u64` SMC window offset, relative to the SR-IOV zone base.
    pub const SHARED_MEM_OFF: usize = 0x70;
    /// `u32` SMC window size.
    pub const SHARED_MEM_SZ: usize = 0x78;
}

/// True-PF SMC shared-memory window, pointed to by the SR-IOV zone's
/// shared-memory descriptor. This is the [`Shmem`] surface the hardware-channel
/// handshake runs over; in `pf_caps` mode `shmem_region` resolves here.
const PF_SRIOV_SHMEM: Range<usize> = 0x380..0x380 + SHMEM_LEN;

/// Build the true-PF region-descriptor table ([`PF_DESC`]). Advertises the
/// device version and locates the capability, doorbell, and SR-IOV regions
/// inside BAR0; every other region advertises size 0 ("absent"). Every
/// advertised region satisfies `base_offset + size <= bar_len`, so a client's
/// in-bounds check passes for all of them.
fn build_pf_desc() -> [u8; PF_DESC_LEN] {
    let mut d = [0u8; PF_DESC_LEN];
    let put64 = |d: &mut [u8], off: usize, v: u64| {
        d[off..off + 8].copy_from_slice(&v.to_ne_bytes());
    };
    let put32 = |d: &mut [u8], off: usize, v: u32| {
        d[off..off + 4].copy_from_slice(&v.to_ne_bytes());
    };
    // Version: the emulated platform generation.
    put32(&mut d, pf_desc::VERSION, PF_DESC_VERSION);
    // Capability register zone.
    put64(&mut d, pf_desc::CAP_ZONE_OFF, PF_CAP_ZONE.start as u64);
    put32(&mut d, pf_desc::CAP_ZONE_SZ, PF_CAP_ZONE.len() as u32);
    // Status and control regions reuse the capability size; point them at the
    // capability zone so the client's bounds check passes.
    put64(&mut d, pf_desc::STATUS_ZONE_OFF, PF_CAP_ZONE.start as u64);
    put64(&mut d, pf_desc::CONTROL_ZONE_OFF, PF_CAP_ZONE.start as u64);
    // Doorbell pages.
    put64(&mut d, pf_desc::DOORBELL_OFF, DOORBELLS.start as u64);
    put32(&mut d, pf_desc::DOORBELL_SZ, DOORBELLS.len() as u32);
    // SR-IOV configuration zone (contains the shared-memory descriptor).
    put64(&mut d, pf_desc::SRIOV_OFF, PF_SRIOV_ZONE.start as u64);
    put32(&mut d, pf_desc::SRIOV_SZ, PF_SRIOV_ZONE.len() as u32);
    // The send/receive WQ, completion/event queue, CQ-moderation, scheduler,
    // address-translation, and debug context regions are not implemented; they
    // advertise base 0 and size 0 ("absent"), which trivially satisfies the
    // client's in-bounds check. (The table is already zero-initialized; written
    // here explicitly to document each region the true-PF surface declares.)
    for (off, sz) in [
        (pf_desc::SEND_WQ_CTX_OFF, pf_desc::SEND_WQ_CTX_SZ),
        (pf_desc::RECV_WQ_CTX_OFF, pf_desc::RECV_WQ_CTX_SZ),
        (pf_desc::CQ_CTX_OFF, pf_desc::CQ_CTX_SZ),
        (pf_desc::EQ_CTX_OFF, pf_desc::EQ_CTX_SZ),
        (pf_desc::CQ_MOD_CTX_OFF, pf_desc::CQ_MOD_CTX_SZ),
        (pf_desc::SCHEDULER_OFF, pf_desc::SCHEDULER_SZ),
        (pf_desc::XLATE_OFF, pf_desc::XLATE_SZ),
        (pf_desc::DEBUG_OFF, pf_desc::DEBUG_SZ),
    ] {
        put64(&mut d, off, 0);
        put32(&mut d, sz, 0);
    }
    d
}

/// Build the SR-IOV configuration zone ([`PF_SRIOV_ZONE`]). Carries the
/// shared-memory descriptor (offset relative to the zone base, plus size) that
/// directs a true-PF client to the SMC window ([`PF_SRIOV_SHMEM`]).
fn build_pf_sriov_zone() -> [u8; PF_SRIOV_ZONE_LEN] {
    let mut z = [0u8; PF_SRIOV_ZONE_LEN];
    let shared_mem_off = (PF_SRIOV_SHMEM.start - PF_SRIOV_ZONE.start) as u64;
    z[pf_sriov::SHARED_MEM_OFF..][..8].copy_from_slice(&shared_mem_off.to_ne_bytes());
    z[pf_sriov::SHARED_MEM_SZ..][..4].copy_from_slice(&(SHMEM_LEN as u32).to_ne_bytes());
    z
}

pub struct GdmaDevice {
    config: ConfigSpaceType0Emulator,
    msix: MsixEmulator,
    regmap: RegMap,
    shmem: Shmem,
    /// BAR0 range of the SMC shared-memory window. Normally [`SHMEM`]; in
    /// `pf_caps` mode it is relocated to [`PF_SRIOV_SHMEM`], the window the
    /// true-PF SR-IOV shared-memory descriptor points at.
    shmem_region: Range<usize>,
    destroying_hwc: bool,
    queues: Arc<Queues>,
    hwc: TaskControl<Devices, HwControl>,
    /// Receives a notification when the guest initiates a PCIe Function Level
    /// Reset by writing the FLR bit in the PCI Express capability. The matching
    /// sender lives in [`GdmaFlrHandler`], owned by that capability. The FLR is
    /// serviced asynchronously from [`PollDevice::poll_device`] because the
    /// teardown is async while [`FlrHandler::initiate_flr`] is synchronous.
    flr_rx: mesh::Receiver<()>,
    /// Set once an FLR has been observed and cleared when the teardown
    /// completes. While set, [`PollDevice::poll_device`] keeps driving
    /// [`GdmaDevice::poll_flr_reset`] to completion across polls.
    flr_draining: bool,
    /// The PF BAR0 register window, present only when the device is presented
    /// as a bare-metal PF (`bm_hostmode`). `None` for a VF, keeping the VF
    /// register surface byte-identical.
    pf_regs: Option<[u8; PF_REGS_LEN]>,
    /// The true-PF region-descriptor table, present only when `pf_caps` is set.
    /// Served at the base of BAR0 ([`PF_DESC`]); it locates the capability,
    /// doorbell, and SR-IOV regions for a true-PF client.
    pf_desc: Option<[u8; PF_DESC_LEN]>,
    /// The true-PF SR-IOV configuration zone, present only when `pf_caps` is
    /// set. Served at [`PF_SRIOV_ZONE`]; carries the shared-memory descriptor.
    pf_sriov_zone: Option<[u8; PF_SRIOV_ZONE_LEN]>,
    /// The PF capability register window, present only when `pf_caps` is set.
    /// Served at [`PF_CAP_ZONE`]. `None` keeps the BAR0 register surface
    /// unchanged.
    pf_cap_regs: Option<[u8; PF_CAP_REGS_LEN]>,
}

/// Bridges the synchronous [`FlrHandler::initiate_flr`] callback (invoked from
/// the PCI config-space write path) to the device's asynchronous reset, which
/// is driven from [`PollDevice::poll_device`]. The callback only signals the
/// channel; the actual teardown runs on the device's poll context.
#[derive(Inspect)]
struct GdmaFlrHandler {
    #[inspect(skip)]
    flr_tx: mesh::Sender<()>,
}

impl FlrHandler for GdmaFlrHandler {
    fn initiate_flr(&self) {
        self.flr_tx.send(());
    }
}

impl InspectMut for GdmaDevice {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        req.respond()
            .field("bm_hostmode", self.pf_regs.is_some())
            .field("pf_caps", self.pf_cap_regs.is_some())
            .field("config", &self.config)
            .field("queues", &self.queues)
            .merge(&mut self.hwc);
    }
}

struct Shmem([u32; SHMEM_LEN / 4]);

trait ContainsRange<T> {
    fn contains_range(&self, _: &Range<T>) -> bool;
    fn overlaps_range(&self, _: &Range<T>) -> bool;
}

impl<T: Ord> ContainsRange<T> for Range<T> {
    fn contains_range(&self, r: &Range<T>) -> bool {
        r.start >= self.start && r.end <= self.end
    }

    fn overlaps_range(&self, r: &Range<T>) -> bool {
        // Half-open ranges `[a, b)` and `[c, d)` overlap iff `a < d && c < b`.
        // Using `>=` would treat *adjacent* ranges as overlapping, which makes
        // the SMC handler fire on a write to the dword just below the header
        // dword (see `write_shmem`), reading a not-yet-written header.
        r.end > self.start && self.end > r.start
    }
}

#[derive(Debug, Error)]
enum SmcError {
    #[error("request is a response")]
    RequestIsResponse,
    #[error("unsupported request version")]
    UnsupportedVersion,
    #[error("hwc is already active")]
    HwcAlreadyActive,
    #[error("failed to allocate queues")]
    QueueAlloc(#[source] queues::QueueAllocError),
    #[error("unsupported request {0:#x?}")]
    UnsupportedRequest(SmcMessageType),
}

pub use bnic::BnicConfig;

pub struct VportConfig {
    pub mac_address: MacAddress,
    pub endpoint: Box<dyn Endpoint>,
}

impl GdmaDevice {
    pub fn new(
        driver_source: &VmTaskDriverSource,
        gm: GuestMemory,
        msi_target: &MsiTarget,
        vports: Vec<VportConfig>,
        mmio_registration: &mut dyn RegisterMmioIntercept,
    ) -> Self {
        Self::new_with_config(
            driver_source,
            gm,
            msi_target,
            vports,
            mmio_registration,
            BnicConfig::default(),
        )
    }

    pub fn new_with_config(
        driver_source: &VmTaskDriverSource,
        gm: GuestMemory,
        msi_target: &MsiTarget,
        vports: Vec<VportConfig>,
        mmio_registration: &mut dyn RegisterMmioIntercept,
        bnic_config: BnicConfig,
    ) -> Self {
        let (msix, msix_capability) = MsixEmulator::new(4, 64, msi_target);

        // In bare-metal-host mode the device presents the PF PCI id and a PF
        // BAR0 register window; the BNIC reports `bm_hostmode=1`. The VF
        // register map stays in place either way (the PF window is disjoint and
        // the Linux PF driver never reads the VF offsets), so the in-tree
        // driver can still bring up the HW channel against a PF-mode device.
        let bm_hostmode = bnic_config.bm_hostmode;
        let pf_caps = bnic_config.pf_caps;
        // `bm_hostmode` and `pf_caps` are two distinct physical-function
        // presentations and are never combined.
        debug_assert!(
            !(bm_hostmode && pf_caps),
            "bm_hostmode and pf_caps are mutually exclusive"
        );
        let pf_regs = bm_hostmode.then(build_pf_regs);
        // In `pf_caps` mode the device serves the true-PF register surface: a
        // region-descriptor table at the base of BAR0 (shadowing the VF map),
        // a capability zone, and an SR-IOV zone whose shared-memory descriptor
        // points at the relocated SMC window. The SMC handshake therefore runs
        // over [`PF_SRIOV_SHMEM`] rather than [`SHMEM`].
        let shmem_region = if pf_caps { PF_SRIOV_SHMEM } else { SHMEM };
        let pf_desc = pf_caps.then(build_pf_desc);
        let pf_sriov_zone = pf_caps.then(build_pf_sriov_zone);
        if bm_hostmode {
            tracing::info!(
                device_id = format_args!("{:#06x}", gdma_defs::PF_DEVICE_ID),
                "presenting MANA device as bare-metal physical function (bm_hostmode)"
            );
        }
        if pf_caps {
            tracing::info!(
                device_id = format_args!("{:#06x}", gdma_defs::PF_DEVICE_ID),
                "presenting MANA device as physical function with capability registers (pf_caps)"
            );
        }

        // Route a guest-initiated PCIe Function Level Reset to the device's
        // async reset. The handler only signals `flr_rx`; `poll_device` runs
        // the teardown. MSI-X stays first in the capability list so it keeps
        // its expected configuration-space offset.
        let (flr_tx, flr_rx) = mesh::channel();
        let pci_express_capability = PciExpressCapability::new(
            DevicePortType::Endpoint,
            Some(Arc::new(GdmaFlrHandler { flr_tx })),
        );

        let hardware_ids = HardwareIds {
            vendor_id: gdma_defs::VENDOR_ID,
            device_id: if bm_hostmode || pf_caps {
                gdma_defs::PF_DEVICE_ID
            } else {
                gdma_defs::DEVICE_ID
            },
            revision_id: 1,
            prog_if: ProgrammingInterface::NETWORK_CONTROLLER_ETHERNET_GDMA,
            sub_class: Subclass::NETWORK_CONTROLLER_ETHERNET,
            base_class: ClassCode::NETWORK_CONTROLLER,
            type0_sub_vendor_id: 0,
            type0_sub_system_id: 0,
        };

        let capabilities = vec![
            Box::new(msix_capability) as _,
            Box::new(pci_express_capability) as _,
        ];

        // A physical-function client (pf_caps) requires an SR-IOV extended
        // capability to be present in config space before it will start. Expose
        // one advertising zero virtual functions so the client starts without
        // requesting any virtual-function infrastructure.
        let extended_capabilities: Vec<Box<dyn PciExtendedCapability>> = if pf_caps {
            vec![Box::new(SriovExtendedCapability::new()) as _]
        } else {
            Vec::new()
        };

        let bar0_mem = mmio_registration.new_io_region("regs", 8192);
        let bar2_mem = mmio_registration.new_io_region("msix", msix.bar_len());

        let config = ConfigSpaceType0Emulator::new(
            hardware_ids,
            capabilities,
            extended_capabilities,
            DeviceBars::new()
                .bar0(8192, BarMemoryKind::Intercept(bar0_mem))
                .bar4(msix.bar_len(), BarMemoryKind::Intercept(bar2_mem)),
        );

        let regmap = RegMap {
            micro_version_number: 1,
            minor_version_number: 0,
            major_version_number: 1,
            reserved: 0,
            vf_db_pages_zone_offset: DOORBELLS.start as u64,
            vf_db_page_sz: DOORBELLS.len() as u16,
            reserved2: 0,
            reserved3: 0,
            vf_gdma_sriov_shared_reg_start: shmem_region.start as u64,
            vf_gdma_sriov_shared_sz: shmem_region.len() as u16,
            reserved4: 0,
            reserved5: 0,
        };

        let queues = Arc::new(Queues::new(gm, driver_source.simple(), &msix));
        let pf_cap_regs = pf_caps.then(|| build_pf_cap_regs(&queues));

        Self {
            config,
            msix,
            shmem: Shmem(FromZeros::new_zeroed()),
            shmem_region,
            regmap,
            queues,
            destroying_hwc: false,
            hwc: TaskControl::new(Devices {
                bnic: bnic::BasicNic::new(vports, bnic_config),
            }),
            flr_rx,
            flr_draining: false,
            pf_regs,
            pf_desc,
            pf_sriov_zone,
            pf_cap_regs,
        }
    }

    fn read_regmap(&self, offset: usize, data: &mut [u8]) {
        data.copy_from_slice(&self.regmap.as_bytes()[offset..offset + data.len()]);
    }

    fn read_shmem(&mut self, offset: usize, data: &mut [u8]) {
        // If there is a pending DESTROY_HWC request, then poll whether the HWC
        // task has stopped.
        if self.destroying_hwc && self.hwc.stop().now_or_never().is_some() {
            if self.hwc.has_state() {
                let _ = self.hwc.remove();
            }
            self.destroying_hwc = false;
            self.complete_smc(0);
        }
        data.copy_from_slice(&self.shmem.0.as_bytes()[offset..offset + data.len()]);
    }

    fn write_shmem(&mut self, offset: usize, data: &[u8]) {
        self.shmem.0.as_mut_bytes()[offset..offset + data.len()].copy_from_slice(data);
        if (SHMEM_LEN - 4..SHMEM_LEN).overlaps_range(&(offset..offset + data.len())) {
            // The final-dword write hands shared-memory possession to the PF
            // (this device); the guest then polls for the possession bit to
            // clear, which `complete_smc` does once the request is serviced.
            // Holding possession here is what keeps the guest polling across an
            // asynchronous DESTROY_HWC instead of racing ahead and reading the
            // bare request header as if it were the response.
            let hdr = SmcProtoHdr::from(self.shmem.0[SHMEM_LEN / 4 - 1]).with_owner_is_pf(true);
            self.shmem.0[SHMEM_LEN / 4 - 1] = hdr.into();
            let status = match self.handle_smc() {
                Ok(true) => 0,
                Ok(false) => return,
                Err(err) => {
                    tracing::error!(error = &err as &dyn std::error::Error, "smc error");
                    1
                }
            };
            self.complete_smc(status);
        }
    }

    fn complete_smc(&mut self, status: u8) {
        let hdr = SmcProtoHdr::from(self.shmem.0[SHMEM_LEN / 4 - 1])
            .with_status(status)
            .with_is_response(true)
            .with_owner_is_pf(false);
        self.shmem.0[SHMEM_LEN / 4 - 1] = hdr.into();
    }

    /// Returns Ok(false) if the operation should remain pending.
    fn handle_smc(&mut self) -> Result<bool, SmcError> {
        let hdr = SmcProtoHdr::from(self.shmem.0[SHMEM_LEN / 4 - 1]);
        if hdr.is_response() {
            return Err(SmcError::RequestIsResponse);
        }
        match SmcMessageType(hdr.msg_type()) {
            SmcMessageType::SMC_MSG_TYPE_ESTABLISH_HWC => {
                if hdr.msg_version() != SMC_MSG_TYPE_ESTABLISH_HWC_VERSION {
                    return Err(SmcError::UnsupportedVersion);
                }
                if self.hwc.has_state() {
                    return Err(SmcError::HwcAlreadyActive);
                }
                let packed = self.shmem.0.as_bytes();
                let high = self.shmem.0[6] as u64;
                let msix = self.shmem.0[6] >> 16;
                let low_mask = 0xffff_ffff_ffff;
                let high_mask = 0xf_0000_0000_0000;
                let eq_gpn = (u64::from_ne_bytes(packed[0..8].try_into().unwrap()) & low_mask)
                    | ((high << 48) & high_mask);
                let cq_gpn = (u64::from_ne_bytes(packed[6..14].try_into().unwrap()) & low_mask)
                    | ((high << 44) & high_mask);
                let rq_gpn = (u64::from_ne_bytes(packed[12..20].try_into().unwrap()) & low_mask)
                    | ((high << 40) & high_mask);
                let sq_gpn = (u64::from_ne_bytes(packed[18..26].try_into().unwrap()) & low_mask)
                    | ((high << 36) & high_mask);
                let hwc = HwControl::new(
                    self.queues.clone(),
                    sq_gpn * PAGE_SIZE64,
                    rq_gpn * PAGE_SIZE64,
                    cq_gpn * PAGE_SIZE64,
                    eq_gpn * PAGE_SIZE64,
                    msix,
                )
                .map_err(SmcError::QueueAlloc)?;
                self.hwc.insert(&self.queues.driver, "gdma-hwc", hwc);
                self.hwc.start();
                Ok(true)
            }
            SmcMessageType::SMC_MSG_TYPE_DESTROY_HWC => {
                if hdr.msg_version() != SMC_MSG_TYPE_DESTROY_HWC_VERSION {
                    return Err(SmcError::UnsupportedVersion);
                }
                // Tell HWC to stop. When the guest reads shared memory, we will
                // poll whether it has stopped yet.
                self.hwc.stop().now_or_never();
                self.destroying_hwc = true;
                Ok(false)
            }
            SmcMessageType::SMC_MSG_TYPE_REPORT_HWC_TIMEOUT => {
                if hdr.msg_version() < SMC_MSG_TYPE_REPORT_HWC_TIMEOUT_VERSION {
                    return Err(SmcError::UnsupportedVersion);
                }
                let rqt = self.shmem.0[0];
                let sqt = self.shmem.0[1];
                let cqn = self.shmem.0[2];
                let eqn = self.shmem.0[3];
                let flags_wait = self.shmem.0[6];
                let wait_time_mask = 0xff_ffff;
                let wait_time = flags_wait & wait_time_mask;
                let cmd_failed_mask = 0x01_u32;
                let cmd_failed_shift = 24_u32;
                let cmd_failed = (flags_wait >> cmd_failed_shift) & cmd_failed_mask;
                tracing::warn!(
                    cmd_failed,
                    wait_time,
                    rqt,
                    sqt,
                    cqn,
                    eqn,
                    wait_time,
                    "report_hwc_timeout"
                );
                Ok(true)
            }
            req => Err(SmcError::UnsupportedRequest(req)),
        }
    }

    fn write_doorbell(&mut self, offset: usize, data: u64) {
        tracing::trace!(offset, value = ?CqEqDoorbellValue::from(data), "doorbell");
        match offset as u32 {
            DB_SQ => {
                self.queues.doorbell_sq(WqDoorbellValue::from(data));
            }
            DB_RQ => {
                self.queues.doorbell_rq(WqDoorbellValue::from(data));
            }
            DB_RQ_CLIENT_DATA => {}
            DB_CQ => {
                self.queues.doorbell_cq(CqEqDoorbellValue::from(data));
            }
            DB_EQ => {
                self.queues.doorbell_eq(CqEqDoorbellValue::from(data));
            }
            _ => {
                tracing::warn!(offset, data, "bad doorbell write");
            }
        }
    }

    fn read_reg(&mut self, offset: usize, data: &mut [u8]) {
        let range = offset..offset + data.len();
        if let Some(desc) = self
            .pf_desc
            .as_ref()
            .filter(|_| PF_DESC.contains_range(&range))
        {
            // True-PF region-descriptor table. It shadows the VF register map,
            // so it is checked first and the VF map is served only in its
            // absence.
            data.copy_from_slice(&desc[offset - PF_DESC.start..][..data.len()]);
        } else if self.shmem_region.contains_range(&range) {
            let base = self.shmem_region.start;
            self.read_shmem(offset - base, data);
        } else if self.pf_desc.is_none() && REGMAP.contains_range(&range) {
            self.read_regmap(offset, data);
        } else if let Some(pf) = self
            .pf_regs
            .as_ref()
            .filter(|_| PF_REGS.contains_range(&range))
        {
            data.copy_from_slice(&pf[offset - PF_REGS.start..][..data.len()]);
        } else if let Some(caps) = self
            .pf_cap_regs
            .as_ref()
            .filter(|_| PF_CAP_ZONE.contains_range(&range))
        {
            data.copy_from_slice(&caps[offset - PF_CAP_ZONE.start..][..data.len()]);
        } else if let Some(sriov) = self
            .pf_sriov_zone
            .as_ref()
            .filter(|_| PF_SRIOV_ZONE.contains_range(&range))
        {
            data.copy_from_slice(&sriov[offset - PF_SRIOV_ZONE.start..][..data.len()]);
        } else {
            tracing::warn!(offset, len = data.len(), "bad read");
            data.fill(!0);
        }
        tracing::trace!(offset, len = data.len(), value = ?data, "bar0 read");
    }

    fn write_reg(&mut self, offset: usize, data: &[u8]) {
        tracing::trace!(offset, len = data.len(), value = ?data, "bar0 write");
        let range = offset..offset + data.len();
        if self.shmem_region.contains_range(&range) {
            let base = self.shmem_region.start;
            self.write_shmem(offset - base, data);
        } else if DOORBELLS.contains_range(&range) && data.len() == 8 {
            self.write_doorbell(
                offset - DOORBELLS.start,
                u64::from_ne_bytes(data.try_into().unwrap()),
            );
        } else {
            tracing::warn!(offset, len = data.len(), "bad write");
        }
    }
}

impl ChangeDeviceState for GdmaDevice {
    fn start(&mut self) {}

    async fn stop(&mut self) {}

    async fn reset(&mut self) {
        // Return the device to its freshly-constructed state so the guest can
        // re-establish the HW channel after a reboot or function-level reset.
        // The guest may have disappeared without issuing DESTROY_HWC, so any
        // previously established channel, datapath tasks, and queue allocations
        // must be torn down here. Without this, a re-probe observes the stale
        // channel and ESTABLISH_HWC is rejected as already active.
        self.hwc.stop().await;
        self.hwc.task_mut().bnic.shutdown().await;
        if self.hwc.has_state() {
            self.hwc.remove();
        }
        self.queues.reset();
        self.destroying_hwc = false;
        self.shmem = Shmem(FromZeros::new_zeroed());
    }
}

impl GdmaDevice {
    /// Poll-driven function-level-reset teardown.
    ///
    /// This mirrors [`GdmaDevice::reset`] but is expressed as a state machine
    /// that makes forward progress across `poll_device` invocations, because an
    /// FLR is triggered synchronously from the guest's config-space write while
    /// the teardown (stopping the HW channel and datapath tasks) is async. It
    /// additionally resets PCI configuration state, which a real FLR does and
    /// the VM-reset path deliberately does not: after this the guest must
    /// re-enumerate the function (re-program BARs, command, MSI-X) before it
    /// can drive the device again, exactly as it would after a hardware FLR.
    fn poll_flr_reset(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        std::task::ready!(self.hwc.poll_stop(cx));
        std::task::ready!(self.hwc.task_mut().bnic.poll_shutdown(cx));
        if self.hwc.has_state() {
            self.hwc.remove();
        }
        self.queues.reset();
        self.destroying_hwc = false;
        self.shmem = Shmem(FromZeros::new_zeroed());
        self.config.reset();
        Poll::Ready(())
    }
}

impl PollDevice for GdmaDevice {
    fn poll_device(&mut self, cx: &mut Context<'_>) {
        loop {
            // Pick up a guest-initiated FLR. The handler signals `flr_rx` from
            // the synchronous config-space write path; the teardown runs here.
            if !self.flr_draining {
                match self.flr_rx.poll_recv(cx) {
                    Poll::Ready(Ok(())) => self.flr_draining = true,
                    // The sender lives as long as the device, so a closed
                    // channel means there is nothing more to service.
                    Poll::Ready(Err(_)) => return,
                    Poll::Pending => return,
                }
            }
            if self.poll_flr_reset(cx).is_pending() {
                return;
            }
            self.flr_draining = false;
            // Loop to re-arm `flr_rx` for the next FLR: like every pollable
            // device, this must leave a waker registered before returning, or
            // a later FLR would not wake the poller.
        }
    }
}

impl ChipsetDevice for GdmaDevice {
    fn supports_mmio(&mut self) -> Option<&mut dyn MmioIntercept> {
        Some(self)
    }

    fn supports_pci(&mut self) -> Option<&mut dyn PciConfigSpace> {
        Some(self)
    }

    fn supports_poll_device(&mut self) -> Option<&mut dyn PollDevice> {
        Some(self)
    }
}

impl SaveRestore for GdmaDevice {
    // This device should be constructed with `omit_saved_state`.
    type SavedState = SavedStateNotSupported;

    fn save(&mut self) -> Result<Self::SavedState, SaveError> {
        Err(SaveError::NotSupported)
    }

    fn restore(&mut self, state: Self::SavedState) -> Result<(), RestoreError> {
        match state {}
    }
}

impl MmioIntercept for GdmaDevice {
    fn mmio_read(&mut self, address: u64, data: &mut [u8]) -> IoResult {
        if let Some((bar, offset)) = self.config.find_bar(address) {
            match bar {
                0 => self.read_reg(offset as usize, data),
                4 => read_as_u32_chunks(offset, data, |offset| self.msix.read_u32(offset)),
                _ => unreachable!(),
            }
        }
        IoResult::Ok
    }

    fn mmio_write(&mut self, address: u64, data: &[u8]) -> IoResult {
        if let Some((bar, offset)) = self.config.find_bar(address) {
            match bar {
                0 => self.write_reg(offset as usize, data),
                4 => write_as_u32_chunks(offset, data, |offset, ty| match ty {
                    ReadWriteRequestType::Read => Some(self.msix.read_u32(offset)),
                    ReadWriteRequestType::Write(val) => {
                        self.msix.write_u32(offset, val);
                        None
                    }
                }),
                _ => unreachable!(),
            }
        }
        IoResult::Ok
    }
}

impl PciConfigSpace for GdmaDevice {
    fn pci_cfg_read(&mut self, offset: u16, value: &mut u32) -> IoResult {
        self.config.read_u32(offset, value)
    }

    fn pci_cfg_write(&mut self, offset: u16, value: u32) -> IoResult {
        self.config.write_u32(offset, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SMC handler must fire only when a guest write actually touches the
    /// final header dword `[SHMEM_LEN - 4, SHMEM_LEN)`. The driver fills the
    /// shared-memory aperture one dword at a time and writes the header dword
    /// last, so a write to the immediately-preceding dword is *adjacent* to the
    /// trigger range, not overlapping it. Treating adjacency as overlap makes
    /// the device read the not-yet-written (all-zero) header and reject it as
    /// `msg_type` 0, emitting a spurious "unsupported request 0x0" error just
    /// before the real ESTABLISH_HWC.
    #[test]
    fn smc_trigger_excludes_adjacent_dword() {
        let trigger = (SHMEM_LEN - 4)..SHMEM_LEN;

        // Writes that genuinely touch the header dword must trigger the handler.
        assert!(trigger.overlaps_range(&((SHMEM_LEN - 4)..SHMEM_LEN)));
        assert!(trigger.overlaps_range(&((SHMEM_LEN - 4)..(SHMEM_LEN - 3))));
        assert!(trigger.overlaps_range(&(0..SHMEM_LEN)));

        // The dword immediately below the header is adjacent, not overlapping,
        // and must NOT trigger the handler.
        assert!(!trigger.overlaps_range(&((SHMEM_LEN - 8)..(SHMEM_LEN - 4))));
        assert!(!trigger.overlaps_range(&(0..4)));
    }

    /// `contains_range` is likewise half-open: a sub-range that ends exactly at
    /// the container's end is contained, but one byte past is not.
    #[test]
    fn contains_range_is_half_open() {
        let region = 0..SHMEM_LEN;
        assert!(region.contains_range(&((SHMEM_LEN - 4)..SHMEM_LEN)));
        assert!(region.contains_range(&(0..SHMEM_LEN)));
        assert!(!region.contains_range(&(0..(SHMEM_LEN + 1))));
    }
}
