// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![expect(missing_docs)]
#![cfg(all(target_os = "macos", guest_is_native, guest_arch = "aarch64"))]

//! A hypervisor backend using macos's Hypervisor framework.

// UNSAFETY: Calling Hypervisor framework APIs and manually managing memory.
#![expect(unsafe_code)]

mod abi;
mod hypercall;
mod vp_actor;
mod vp_state;
#[cfg(test)]
mod wake_loop_tests;

use crate::hypercall::HvfHypercallHandler;
use aarch64defs::Cpsr64;
use aarch64defs::ExceptionClass;
use aarch64defs::IssDataAbort;
use aarch64defs::IssSystem;
use aarch64defs::MpidrEl1;
use aarch64defs::SystemReg;
use aarch64defs::Vendor;
use aarch64defs::smccc::FastCall;
use aarch64defs::smccc::PsciError;
use aarch64defs::smccc::SmcCall;
use abi::HvfError;
use anyhow::Context;
use guestmem::GuestMemory;
use hv1_emulator::synic::GlobalSynic;
use hv1_emulator::synic::ProcessorSynic;
use hvdef::HvMessage;
use hvdef::HvMessageType;
use hvdef::Vtl;
use inspect::Inspect;
use inspect::InspectMut;
use memory_range::MemoryRange;
use parking_lot::Mutex;
use parking_lot::RwLock;
use std::convert::Infallible;
use std::future::poll_fn;
use std::ops::Deref;
use std::ops::Range;
use std::ptr::null_mut;
use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::task::Poll;
use std::time::Duration;
use thiserror::Error;
use virt::BindProcessor;
use virt::NeedsYield;
use virt::Processor;
use virt::StopVp;
use virt::VpHaltReason;
use virt::VpIndex;
use virt::aarch64::Aarch64PartitionCapabilities;
use virt::aarch64::vm::AccessVmState;
use virt::io::CpuIo;
use virt::state::StateElement;
use virt::vp::AccessVpState;
use virt_support_gic as gic;
use vm_topology::processor::aarch64::Aarch64VpInfo;
use vmcore::interrupt::Interrupt;
use vmcore::reference_time::GetReferenceTime;
use vmcore::reference_time::ReferenceTimeResult;
use vmcore::reference_time::ReferenceTimeSource;
use vmcore::synic::GuestEventPort;
use vmcore::vmtime::VmTime;
use vmcore::vmtime::VmTimeAccess;

const HV_ARM64_HVC_SMCCC_IDENTIFIER: u32 = (1 << 30) | (6 << 24) | 1;

#[derive(Debug)]
pub struct HvfHypervisor;

#[derive(Debug, Error)]
#[error(transparent)]
pub struct Error(#[from] anyhow::Error);

impl From<HvfError> for Error {
    fn from(value: HvfError) -> Self {
        <Result<(), _>>::Err(value)
            .context("hypervisor framework error")
            .unwrap_err()
            .into()
    }
}

impl virt::Hypervisor for HvfHypervisor {
    type ProtoPartition<'a> = HvfProtoPartition<'a>;
    type Partition = HvfPartition;
    type Error = Error;

    fn platform_info(&self) -> virt::PlatformInfo {
        virt::PlatformInfo {
            platform_gsiv: None,
            supports_gic_v3: true,
            supports_its: false,
        }
    }

    fn new_partition<'a>(
        &'a mut self,
        config: virt::ProtoPartitionConfig<'a>,
    ) -> Result<Self::ProtoPartition<'a>, Self::Error> {
        Ok(HvfProtoPartition { config })
    }
}

pub struct HvfProtoPartition<'a> {
    config: virt::ProtoPartitionConfig<'a>,
}

impl virt::ProtoPartition for HvfProtoPartition<'_> {
    type Partition = HvfPartition;
    type ProcessorBinder = HvfProcessorBinder;
    type Error = Error;

    fn build(
        self,
        config: virt::PartitionConfig<'_>,
    ) -> Result<(Self::Partition, Vec<Self::ProcessorBinder>), Self::Error> {
        use vm_topology::processor::aarch64::GicVersion;

        let gic_redistributors_base = match self.config.processor_topology.gic_version() {
            GicVersion::V3 {
                redistributors_base,
            } => redistributors_base,
            GicVersion::V2 { .. } => {
                return Err(
                    anyhow::anyhow!("HVF does not support GICv2; only GICv3 is supported").into(),
                );
            }
        };

        // Create the VM. By default we use HVF's native Apple-Silicon 16KB
        // intermediate-physical-address (stage-2) granule via a NULL config.
        //
        // With the off-by-default `hvf-4kb-ipa` feature we instead request a 4KB
        // IPA granule (macOS 26.0+) so the host stage-2 granule matches a 4KB
        // guest stage-1. This was investigated as a Windows-on-ARM64 fix: it is a
        // correct, AZL-3-validated configuration but does NOT resolve the CloudMOS
        // `0x1E` spurious stage-1 store-translation livelock. That fault is raised
        // by Apple's nested stage-1 walker independent of the configured granule
        // (a matched 4KB/4KB nesting wedges identically — see the session's
        // cloudmos_livelock_analysis.md). The feature is therefore off by default
        // to avoid raising the runtime floor to macOS 26 for the Linux/MANA dev
        // loop, while preserving the lever for opportunistic future re-tests.
        #[cfg(feature = "hvf-4kb-ipa")]
        {
            // SAFETY: no safety requirements.
            let vm_config = unsafe { abi::hv_vm_config_create() };
            // SAFETY: `vm_config` is a valid config object from `hv_vm_config_create`.
            unsafe { abi::hv_vm_config_set_ipa_granule(vm_config, abi::HvIpaGranule::SIZE_4KB) }
                .chk()?;
            // SAFETY: `vm_config` is a valid config object; the single config is
            // intentionally leaked (one VM per process).
            unsafe { abi::hv_vm_create(vm_config.cast_const().cast()) }.chk()?;
        }
        // SAFETY: no safety requirements. NULL config selects HVF defaults
        // (16KB IPA granule on Apple Silicon).
        #[cfg(not(feature = "hvf-4kb-ipa"))]
        unsafe {
            abi::hv_vm_create(null_mut())
        }
        .chk()?;

        let hv1 = HvfHv1State::new(self.config.processor_topology.vp_count());
        let hv1_vps = self
            .config
            .processor_topology
            .vps()
            .map(|vp_info| hv1.synic.add_vp(vp_info.vp_index))
            .collect::<Vec<_>>();

        let mut gicd = gic::Distributor::new(
            self.config.processor_topology.gic_distributor_base(),
            MemoryRange::new(
                gic_redistributors_base
                    ..gic_redistributors_base
                        + aarch64defs::GIC_REDISTRIBUTOR_SIZE
                            * self.config.processor_topology.vp_count() as u64,
            ),
            self.config.processor_topology.gic_nr_irqs(),
        );
        let gicrs = self
            .config
            .processor_topology
            .vps_arch()
            .map(|vp_info| gicd.add_redistributor(vp_info.mpidr.into(), true))
            .collect::<Vec<_>>();

        let inner = Arc::new(HvfPartitionInner {
            caps: Aarch64PartitionCapabilities {
                isolation: virt::IsolationType::None,
                // Apple Silicon does not support aarch32.
                supports_aarch32_el0: false,
                vendor: Vendor::ARM,
            },
            virt_timer_ppi: self.config.processor_topology.virt_timer_ppi(),
            vps: self
                .config
                .processor_topology
                .vps_arch()
                .map(|vp_info| HvfVpInner {
                    needs_yield: NeedsYield::new(),
                    message_queues: hv1_emulator::message_queues::MessageQueues::new(),
                    actor: vp_actor::VpActor::new(),
                    vp_info,
                    cpu_on: Default::default(),
                })
                .collect(),
            gicd,
            guest_memory: config.guest_memory.clone(),
            vmtime: self.config.vmtime.access("hvf"),
            hv1,
            mappings: Default::default(),
            synic_ports: Default::default(),
            gic_msi: self.config.processor_topology.gic_msi(),
        });

        let mut vps = Vec::new();
        for ((vp, hv1), gicr) in self
            .config
            .processor_topology
            .vps_arch()
            .zip(hv1_vps)
            .zip(gicrs)
        {
            vps.push(HvfProcessorBinder {
                partition: inner.clone(),
                vp_index: vp.base.vp_index,
                state: Some(VpInitState {
                    gicr,
                    hv1,
                    vmtime: self
                        .config
                        .vmtime
                        .access(format!("vp{}", vp.base.vp_index.index())),
                    gicr_range: {
                        // Guaranteed to be Some since we validated GICv3 above.
                        let gicr = vp.gicr.unwrap();
                        gicr..gicr + aarch64defs::GIC_REDISTRIBUTOR_SIZE
                    },
                }),
            });
        }

        let synic_ports = Arc::new(virt::synic::SynicPorts::new(inner.clone()));

        let partition = HvfPartition { inner, synic_ports };
        Ok((partition, vps))
    }

    fn max_physical_address_size(&self) -> u8 {
        // TODO
        40
    }
}

#[derive(Inspect)]
#[inspect(transparent)]
pub struct HvfPartition {
    inner: Arc<HvfPartitionInner>,
    #[inspect(skip)]
    synic_ports: Arc<virt::synic::SynicPorts<HvfPartitionInner>>,
}

impl Drop for HvfPartitionInner {
    fn drop(&mut self) {
        // SAFETY: no safety requirements.
        unsafe { abi::hv_vm_destroy() }.chk().unwrap();
    }
}

impl virt::Partition for HvfPartition {
    fn supports_reset(
        &self,
    ) -> Option<&dyn virt::ResetPartition<Error = <Self as virt::Hv1>::Error>> {
        Some(self)
    }

    fn caps(&self) -> &Aarch64PartitionCapabilities {
        &self.inner.caps
    }

    fn request_msi(&self, _vtl: Vtl, _request: virt::irqcon::MsiRequest) {
        tracelimit::warn_ratelimited!("msis not supported");
    }

    fn as_signal_msi(&self, _minimum_vtl: Vtl) -> Option<Arc<dyn pci_core::msi::SignalMsi>> {
        let v2m = match &self.inner.gic_msi {
            vm_topology::processor::aarch64::GicMsiController::V2m(v2m) => v2m,
            _ => return None,
        };
        let irqcon = self.inner.clone() as Arc<dyn virt::irqcon::ControlGic>;
        Some(Arc::new(virt::aarch64::gic_v2m::GicV2mSignalMsi::new(
            v2m, irqcon,
        )))
    }

    fn request_yield(&self, vp_index: VpIndex) {
        let vp = &self.inner.vps[vp_index.index() as usize];
        if vp.needs_yield.request_yield() {
            vp.cancel_run();
        }
    }
}

impl virt::ResetPartition for HvfPartition {
    type Error = Error;

    /// Resets VM-wide emulated device state to its initial values. Per-VP state
    /// (per-VP synic, redistributor, PMU, run flags) is scrubbed separately by
    /// [`HvfProcessor::reset`] on each VP thread, and the guest's boot registers
    /// are re-applied afterward by the firmware reload (`set_initial_regs`), so
    /// this only needs to clear partition-level device/interrupt state.
    fn reset(&self) -> Result<(), Self::Error> {
        self.inner.gicd.reset();
        self.inner.hv1.guest_os_id.store(0, Ordering::Relaxed);
        Ok(())
    }
}

impl virt::Aarch64Partition for HvfPartition {
    fn control_gic(&self, _vtl: Vtl) -> Arc<dyn virt::irqcon::ControlGic> {
        self.inner.clone()
    }
}

impl virt::Hv1 for HvfPartition {
    type Error = Error;
    type Device = virt::aarch64::gic_software_device::GicSoftwareDevice;

    fn reference_time_source(&self) -> Option<ReferenceTimeSource> {
        Some(ReferenceTimeSource::from(
            self.inner.clone() as Arc<dyn GetReferenceTime>
        ))
    }

    fn new_virtual_device(
        &self,
    ) -> Option<&dyn virt::DeviceBuilder<Device = Self::Device, Error = Self::Error>> {
        Some(self)
    }

    fn synic(&self) -> anyhow::Result<Arc<dyn vmcore::synic::SynicPortAccess>> {
        Ok(self.synic_ports.clone())
    }
}

impl virt::DeviceBuilder for HvfPartition {
    fn build(&self, _vtl: Vtl, _device_id: u64) -> Result<Self::Device, Self::Error> {
        Ok(virt::aarch64::gic_software_device::GicSoftwareDevice::new(
            self.inner.clone(),
        ))
    }
}

impl GetReferenceTime for HvfPartitionInner {
    fn now(&self) -> ReferenceTimeResult {
        ReferenceTimeResult {
            ref_time: self.vmtime.now().as_100ns(),
            system_time: None,
        }
    }
}

impl virt::irqcon::ControlGic for HvfPartitionInner {
    fn set_spi_irq(&self, irq_id: u32, high: bool) {
        if let Some(vp) = self.gicd.set_pending(irq_id, high) {
            if let Some(vp) = self.vps.get(vp as usize) {
                vp.notify();
            }
        }
    }
}

impl virt::synic::Synic for HvfPartitionInner {
    fn port_map(&self) -> &virt::synic::SynicPortMap {
        &self.synic_ports
    }

    fn post_message(&self, _vtl: Vtl, vp: VpIndex, sint: u8, typ: u32, payload: &[u8]) {
        if let Some(vp) = self.vps.get(vp.index() as usize) {
            if vp
                .message_queues
                .enqueue_message(sint, &HvMessage::new(HvMessageType(typ), 0, payload))
            {
                vp.notify();
            }
        }
    }

    fn new_guest_event_port(
        self: Arc<Self>,
        _vtl: Vtl,
        vp: u32,
        sint: u8,
        flag: u16,
    ) -> Box<dyn GuestEventPort> {
        Box::new(HvfEventPort {
            partition: Arc::downgrade(&self),
            params: Arc::new(RwLock::new(HvfEventPortParams {
                vp: VpIndex::new(vp),
                sint,
                flag,
            })),
        })
    }

    fn prefer_os_events(&self) -> bool {
        false
    }
}

struct HvfEventPort {
    partition: Weak<HvfPartitionInner>,
    params: Arc<RwLock<HvfEventPortParams>>,
}

struct HvfEventPortParams {
    vp: VpIndex,
    sint: u8,
    flag: u16,
}

impl GuestEventPort for HvfEventPort {
    fn interrupt(&self) -> Interrupt {
        let partition = self.partition.clone();
        let params = self.params.clone();
        Interrupt::from_fn(move || {
            if let Some(partition) = partition.upgrade() {
                let params = params.read();
                let HvfEventPortParams { vp, sint, flag } = *params;
                let _ =
                    partition
                        .hv1
                        .synic
                        .signal_event(vp, sint, flag, &mut |vector, _auto_eoi| {
                            let newly_pending = partition.gicd.raise_ppi(vp, vector);
                            if newly_pending {
                                partition.vps[vp.index() as usize].notify();
                            }
                        });
            }
        })
    }

    fn set_target_vp(&mut self, vp: u32) -> Result<(), vmcore::synic::HypervisorError> {
        self.params.write().vp = VpIndex::new(vp);
        Ok(())
    }
}

impl virt::PartitionMemoryMapper for HvfPartition {
    fn memory_mapper(&self, vtl: Vtl) -> Arc<dyn virt::PartitionMemoryMap> {
        assert_eq!(vtl, Vtl::Vtl0);
        self.inner.clone()
    }
}

impl virt::PartitionMemoryMap for HvfPartitionInner {
    fn unmap_range(&self, addr: u64, size: u64) -> anyhow::Result<()> {
        let range = MemoryRange::new(addr..addr + size);
        self.mappings.lock().retain(|mapping| {
            if !range.overlaps(mapping) {
                return true;
            }
            assert!(range.contains(mapping));
            // SAFETY: no safety requirements.
            unsafe { abi::hv_vm_unmap(mapping.start(), mapping.len() as usize) }
                .chk()
                .expect("cannot fail");
            false
        });
        Ok(())
    }

    unsafe fn map_range(
        &self,
        data: *mut u8,
        size: usize,
        addr: u64,
        writable: bool,
        exec: bool,
    ) -> anyhow::Result<()> {
        let mut mappings = self.mappings.lock();
        let mut flags = abi::HvMemoryFlags::READ.0;
        if writable {
            flags |= abi::HvMemoryFlags::WRITE.0;
        }
        if exec {
            flags |= abi::HvMemoryFlags::EXEC.0;
        }
        // SAFETY: the caller guarantees that the memory pointed to by data is
        // valid until `unmap_range` is called (or the partition is destroyed).
        unsafe { abi::hv_vm_map(data.cast(), addr, size, flags) }.chk()?;
        mappings.push(MemoryRange::new(addr..addr + size as u64));
        Ok(())
    }
}

impl virt::PartitionAccessState for HvfPartition {
    type StateAccess<'a>
        = HvfPartitionStateAccess<'a>
    where
        Self: 'a;

    fn access_state(&self, _vtl: Vtl) -> Self::StateAccess<'_> {
        HvfPartitionStateAccess {
            partition: &self.inner,
        }
    }
}

pub struct HvfPartitionStateAccess<'a> {
    partition: &'a HvfPartitionInner,
}

impl AccessVmState for HvfPartitionStateAccess<'_> {
    type Error = Error;

    fn caps(&self) -> &Aarch64PartitionCapabilities {
        &self.partition.caps
    }

    fn commit(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Inspect)]
struct HvfPartitionInner {
    caps: Aarch64PartitionCapabilities,
    virt_timer_ppi: u32,
    #[inspect(skip)]
    vps: Vec<HvfVpInner>,
    gicd: gic::Distributor,
    guest_memory: GuestMemory,
    vmtime: VmTimeAccess,
    hv1: HvfHv1State,
    #[inspect(with = "|x| inspect::adhoc(|req| inspect::iter_by_index(&*x.lock()).inspect(req))")]
    mappings: Mutex<Vec<MemoryRange>>,
    synic_ports: virt::synic::SynicPortMap,
    gic_msi: vm_topology::processor::aarch64::GicMsiController,
}

#[derive(Inspect)]
struct HvfHv1State {
    guest_os_id: AtomicU64,
    synic: GlobalSynic,
}

impl HvfHv1State {
    fn new(max_vp_count: u32) -> Self {
        Self {
            guest_os_id: 0.into(),
            synic: GlobalSynic::new(max_vp_count),
        }
    }
}

#[derive(Debug, Inspect)]
struct HvfVpInner {
    #[inspect(skip)]
    needs_yield: NeedsYield,
    vp_info: Aarch64VpInfo,
    message_queues: hv1_emulator::message_queues::MessageQueues,
    /// The per-vCPU wake actor: the entire race-free wake/park state machine.
    /// See [`vp_actor`].
    #[inspect(skip)]
    actor: vp_actor::VpActor,
    cpu_on: Mutex<Option<CpuOnState>>,
}

#[derive(Debug, Inspect)]
struct CpuOnState {
    pc: u64,
    x0: u64,
}

impl HvfVpInner {
    /// Forces this vCPU to yield out of `hv_vcpu_run`. Used by the generic
    /// `Partition::request_yield` path (stop, inspection, save/restore).
    fn cancel_run(&self) {
        self.actor.cancel_run();
    }

    /// Requests this vCPU to observe cross-VP work (an interrupt now pending in
    /// virtual GIC state, a queued synic message, a pending `CPU_ON`). The work
    /// must already be published; this is the single wake entry point that
    /// replaces the old `wake`/`cancel_run`/`kick` trio.
    fn notify(&self) {
        self.actor.notify();
    }
}

pub struct HvfProcessorBinder {
    partition: Arc<HvfPartitionInner>,
    vp_index: VpIndex,
    state: Option<VpInitState>,
}

#[derive(Inspect)]
struct VpInitState {
    gicr: gic::Redistributor,
    hv1: ProcessorSynic,
    vmtime: VmTimeAccess,
    #[inspect(debug)]
    gicr_range: Range<u64>,
}

/// `ID_AA64PFR0_EL1.GIC` field (bits [27:24]); the value `0b0001` advertises the
/// GICv3/v4 system-register CPU interface (ICC_* sysregs) to the guest.
const ID_AA64PFR0_EL1_GIC_CPUIF: u64 = 1 << 24;

/// `ID_AA64PFR0_EL1.GIC` field mask (bits [27:24]). Used to set the GIC field
/// via read-modify-write without disturbing the exception-level, FP, AdvSIMD,
/// RAS or SVE fields the guest also reads from this register.
const ID_AA64PFR0_EL1_GIC: u64 = 0xf << 24;

/// `ID_AA64MMFR0_EL1.PARange` field (bits [3:0]) — supported physical-address
/// range. Masked so we can pin only this field to match the stage-2 IPA size
/// this backend configures, leaving the rest of Apple's real MMFR0 intact.
const ID_AA64MMFR0_EL1_PARANGE: u64 = 0xf << 0;

/// `ID_AA64MMFR0_EL1.PARange == 0b0010` ⇒ 40-bit (1 TiB) physical addresses,
/// matching `HvfPartition::max_physical_address_size`.
const ID_AA64MMFR0_EL1_PARANGE_40BIT: u64 = 0b0010;

/// `ID_AA64DFR0_EL1.PMUVer` field (bits [11:8]); cleared to hide the PMU from the
/// guest (see the PMU rationale in `bind`).
const ID_AA64DFR0_EL1_PMUVER: u64 = 0xf << 8;

/// `ID_AA64MMFR2_EL1.CnP` field (bits [3:0]) — FEAT_TTCNP "Common-not-Private"
/// translations. Cleared so the guest cannot set `TTBR0/1_EL1.CnP` and thereby
/// declare that all PEs share identical translation tables. Apple silicon is
/// asymmetric (P-cores + E-cores) and HVF migrates vCPUs across them; with CnP
/// enabled the hardware may share TLB entries across physical cores running the
/// same ASID/VMID, but during early SMP bring-up two VPs transiently hold
/// different tables under the same ASID, so a shared entry from one VP is
/// applied to the other and a concurrent access takes a spurious translation
/// fault. Clearing CnP forces private (per-PE) translations, which is always
/// correct (only marginally less TLB-efficient).
const ID_AA64MMFR2_EL1_CNP: u64 = 0xf << 0;

/// `ID_AA64MMFR2_EL1.NV` field (bits [27:24]) — FEAT_NV/NV2 nested
/// virtualization. Cleared because this backend does not trap-and-emulate EL2
/// execution for the guest: even though we present `ID_AA64PFR0_EL1.EL2` as
/// implemented (so the guest recognizes a Microsoft-compatible HV#1 platform —
/// see `ID_AA64PFR0_EL1_EL2_IMP`), the guest itself never runs at EL2; it uses
/// hypercalls, exactly like every real Hyper-V ARM64 guest, which likewise
/// report EL2 implemented but NV == 0. Advertising nested-virt we do not honor
/// would be an incoherent ID the guest must never see.
const ID_AA64MMFR2_EL1_NV: u64 = 0xf << 24;

/// `ID_AA64PFR0_EL1.EL2` field mask (bits [11:8]). Used to isolate the field for
/// a read-modify-write; the value we install is `ID_AA64PFR0_EL1_EL2_IMP`.
const ID_AA64PFR0_EL1_EL2: u64 = 0xf << 8;

/// `ID_AA64PFR0_EL1.EL2` value `0b0001` — EL2 implemented, AArch64-only. HVF
/// hides EL2 from an EL1 guest (it reports this field as 0), but a
/// Microsoft-compatible HV#1 *guest* is expected to observe EL2 as implemented.
/// Windows' HAL (`HalpDetectHypervisor`, hvarm64.c) gates HV#1 detection on
/// `(ID_AA64PFR0_EL1 & 0xF00) != 0`; with EL2 == 0 it falls back to the
/// bare-metal GIC extension, which reserves SGIs 8-15 and therefore never
/// registers the synic/vmbus interrupt lines (INTIDs 4-10) — so the first synic
/// SGI delivered (INTID 8 = VMBus2) hits an unregistered line and bugchecks
/// 0x5C (HAL_INITIALIZATION_FAILED). Presenting EL2 as implemented restores the
/// HV-guest truth HVF elides; the guest still runs only at EL1 and nested virt
/// stays off (see `ID_AA64MMFR2_EL1_NV`).
const ID_AA64PFR0_EL1_EL2_IMP: u64 = 0b0001 << 8;

/// `ID_AA64PFR0_EL1.EL3` field (bits [15:12]); cleared so the guest sees no
/// secure monitor (EL3), which this backend does not model.
const ID_AA64PFR0_EL1_EL3: u64 = 0xf << 12;

/// `ID_AA64PFR0_EL1.SVE` field (bits [35:32]); cleared because this backend does
/// not allocate or context-switch SVE vector state across vCPU scheduling, so
/// advertising SVE would let the guest silently corrupt that state. (Apple cores
/// report SVE=0 today; the clear is defensive for any host that does not.)
const ID_AA64PFR0_EL1_SVE: u64 = 0xf << 32;

/// `ID_AA64PFR1_EL1.SME` field (bits [27:24]); cleared for the same reason as
/// SVE — the SME/ZA streaming-vector state is neither allocated nor
/// context-switched here, and Apple silicon reports SME present, so this clear
/// is load-bearing rather than defensive.
const ID_AA64PFR1_EL1_SME: u64 = 0xf << 24;

/// Installs the guest-visible AArch64 feature ID registers for one virtual CPU.
///
/// The policy is **host-clamped**: each register starts from the value HVF
/// reports on the underlying core (the capability upper bound — we can never
/// advertise a feature the host cannot execute) and we then subtract the
/// features this VMM does not model, add the one feature it provides beyond the
/// bare core (the GICv3 system-register CPU interface), and pin the
/// physical-address range to the stage-2 IPA size. Because every value derives
/// from the live host register, the result is automatically correct across
/// Apple silicon generations: an older core that lacks a feature reports a lower
/// field here and the policy follows it, so we never hardcode one machine's
/// capabilities into another's.
///
/// Fields deliberately left as host pass-through (FP/AdvSIMD, DIT, CSV2/CSV3,
/// BTI, RAS, the entire ISAR0/ISAR1 instruction menu, the MMFR1 MMU features,
/// the MMFR0 ASID size and translation-granule support, and the debug
/// breakpoint/watchpoint counts) are either pure compute/ISA features HVF runs
/// natively or system features this backend models faithfully. Notably RAS is
/// *kept* (it is mandatory from ARMv8.2 and passive; hiding it would present an
/// oddly old CPU) and the 4KB/16KB/64KB granule-support fields are passed
/// through unchanged (the host already reports 64KB unsupported; the guest
/// defaults to 4KB regardless).
fn sanitize_id_registers(vcpu: &mut HvfVcpu) -> Result<(), HvfError> {
    // Write `want` to `reg`, read it back, and log whether HVF honored the
    // write. HVF may treat some feature ID registers as read-only; a refused or
    // ignored write is logged but must not fail vCPU bring-up.
    fn install(vcpu: &mut HvfVcpu, reg: abi::HvSysReg, want: u64, name: &str) {
        if let Err(err) = vcpu.set_sys_reg(reg, want) {
            tracing::warn!(
                name,
                want = format!("{want:#x}"),
                error = %err,
                "HVF rejected ID register write; guest will see the host value"
            );
            return;
        }
        match vcpu.sys_reg(reg) {
            Ok(got) if got == want => {}
            Ok(got) => tracing::warn!(
                name,
                want = format!("{want:#x}"),
                got = format!("{got:#x}"),
                "ID register write did not stick (HVF clamped it)"
            ),
            Err(err) => tracing::warn!(name, error = %err, "ID register readback failed"),
        }
    }

    // PFR0: start from the host's real value and change only the fields where
    // our virtual platform genuinely diverges from it. Advertise the GICv3
    // sysreg CPU interface (we model it; Apple exposes none) and present EL2 as
    // implemented (HVF hides it, but an HV#1 guest must observe it — without it
    // Windows' HAL misdetects the platform and bugchecks 0x5C; see
    // `ID_AA64PFR0_EL1_EL2_IMP`). Hide EL3 (no secure monitor) and SVE (no
    // vector-state save/restore). FP, AdvSIMD, RAS, DIT, CSV2, CSV3 pass through.
    let pfr0_host = vcpu.sys_reg(abi::HvSysReg::ID_AA64PFR0_EL1)?;
    let pfr0 = (pfr0_host
        & !(ID_AA64PFR0_EL1_GIC
            | ID_AA64PFR0_EL1_EL2
            | ID_AA64PFR0_EL1_EL3
            | ID_AA64PFR0_EL1_SVE))
        | ID_AA64PFR0_EL1_GIC_CPUIF
        | ID_AA64PFR0_EL1_EL2_IMP;
    install(vcpu, abi::HvSysReg::ID_AA64PFR0_EL1, pfr0, "ID_AA64PFR0_EL1");

    // PFR1: hide SME (no streaming-vector state management). BTI and the rest
    // pass through.
    let pfr1_host = vcpu.sys_reg(abi::HvSysReg::ID_AA64PFR1_EL1)?;
    let pfr1 = pfr1_host & !ID_AA64PFR1_EL1_SME;
    install(vcpu, abi::HvSysReg::ID_AA64PFR1_EL1, pfr1, "ID_AA64PFR1_EL1");

    // DFR0: hide the PMU (PMUVer=0). Windows drives PMU sysregs when PMUVer != 0,
    // which this backend does not model and which wedges early boot. DebugVer and
    // the breakpoint/watchpoint counts (which HVF context-switches) are kept.
    let dfr0_host = vcpu.sys_reg(abi::HvSysReg::ID_AA64DFR0_EL1)?;
    let dfr0 = dfr0_host & !ID_AA64DFR0_EL1_PMUVER;
    install(vcpu, abi::HvSysReg::ID_AA64DFR0_EL1, dfr0, "ID_AA64DFR0_EL1");

    // MMFR0: pin only PARange to the stage-2 IPA size (40-bit); preserve the ASID
    // size and translation-granule support exactly as the host reports them.
    let mmfr0_host = vcpu.sys_reg(abi::HvSysReg::ID_AA64MMFR0_EL1)?;
    let mmfr0 = (mmfr0_host & !ID_AA64MMFR0_EL1_PARANGE) | ID_AA64MMFR0_EL1_PARANGE_40BIT;
    install(vcpu, abi::HvSysReg::ID_AA64MMFR0_EL1, mmfr0, "ID_AA64MMFR0_EL1");

    // MMFR2: clear CnP (unsafe under Apple P/E asymmetry with vCPU migration) and
    // NV (we present EL2 as implemented but never trap-and-emulate EL2 for the
    // guest, exactly like a real Hyper-V guest: EL2 implemented, NV == 0).
    // Everything else — UAO, IESB, AT, IDS, BBM, ... — passes through from the host.
    let mmfr2_host = vcpu.sys_reg(abi::HvSysReg::ID_AA64MMFR2_EL1)?;
    let mmfr2 = mmfr2_host & !(ID_AA64MMFR2_EL1_CNP | ID_AA64MMFR2_EL1_NV);
    install(vcpu, abi::HvSysReg::ID_AA64MMFR2_EL1, mmfr2, "ID_AA64MMFR2_EL1");

    tracing::info!(
        pfr0 = format!("{pfr0:#x}"),
        pfr1 = format!("{pfr1:#x}"),
        dfr0 = format!("{dfr0:#x}"),
        mmfr0 = format!("{mmfr0:#x}"),
        mmfr2 = format!("{mmfr2:#x}"),
        "installed OpenVMM virtual-CPU ID registers (host-clamped)"
    );
    Ok(())
}

/// Diagnostic: walk the EL1 stage-1 (`TTBR1_EL1`) translation for `far`,
/// reading each descriptor out of guest memory, and log every level plus the
/// leaf. This distinguishes the two possible causes of the early CloudMOS
/// bugcheck (a write translation fault to a high kernel VA):
///
///   * **leaf VALID** — the page *is* mapped in the guest's own tables, so a
///     hardware translation fault on it is **spurious**: the hardware page-table
///     walker did not observe the guest's PTE. That implicates an
///     OpenVMM/HVF-side walker-coherency problem (stage-2 memory attributes, or
///     a TLB/`SyncContext`/`FlushTlb` enlightenment we mis-handle), which is
///     fixable on the hypervisor side.
///   * **leaf INVALID** — the page is genuinely unmapped in the guest tables, so
///     the fault is "real" and the guest reached this VA because it was fed bad
///     input (memory map / ACPI / register state), a different class of bug.
///
/// Derives the granule, starting level, and the (possibly reduced) top-level
/// index width from `TCR_EL1.{T1SZ,TG1}`, so the walk is correct even when the
/// guest does not use the canonical 48-bit / start-L0 layout. Windows-on-ARM64
/// runs `T1SZ=17`, which makes the high-half input address 47 bits: the L0 index
/// is only **8 bits** (`VA[46:39]`) and the root table is 2 KiB-aligned, not
/// 4 KiB — getting either wrong silently reads the wrong descriptor.
pub(crate) fn diag_walk_ttbr1(gm: &GuestMemory, ttbr1: u64, tcr: u64, far: u64) {
    const TABLE_ADDR_MASK: u64 = 0x0000_ffff_ffff_f000;
    let t1sz = (tcr >> 16) & 0x3f;
    let tg1 = (tcr >> 30) & 0x3;

    // 4 KiB granule level base bits: L0=[47:39], L1=[38:30], L2=[29:21],
    // L3=[20:12]. The top translated VA bit is `63 - T1SZ`; the start level is
    // the highest (lowest-numbered) level whose base bit it reaches.
    let level_base = [39u32, 30, 21, 12];
    let top_bit = 63u32.saturating_sub(t1sz as u32);
    let start_level = level_base.iter().position(|&b| b <= top_bit).unwrap_or(3);
    let start_base_bit = level_base[start_level];
    let start_width = (top_bit - start_base_bit + 1).min(9);
    // The start-level table holds `2^start_width` 8-byte descriptors and
    // `TTBR1.BADDR` is aligned to that table's size (smaller than 4 KiB when the
    // top index is reduced), so do not blindly mask to 4 KiB.
    let start_table_bytes = 8u64 << start_width;
    let mut table = (ttbr1 & 0x0000_ffff_ffff_ffff) & !(start_table_bytes - 1);

    tracing::info!(
        far = format!("{far:#x}"),
        ttbr1 = format!("{ttbr1:#x}"),
        tcr = format!("{tcr:#x}"),
        t1sz,
        tg1,
        top_bit,
        start_level,
        start_width,
        root_table = format!("{table:#x}"),
        "stage-1 TTBR1 walk (4KiB granule)"
    );
    if tg1 != 0b10 {
        tracing::warn!(
            tg1,
            "TCR_EL1.TG1 is not 0b10 (4KiB); the 4KiB walk assumption may not hold"
        );
    }

    for level in start_level..=3 {
        let base_bit = level_base[level];
        let width = if level == start_level { start_width } else { 9 };
        let index = (far >> base_bit) & ((1u64 << width) - 1);
        let entry_gpa = table + index * 8;
        let mut buf = [0u8; 8];
        if let Err(e) = gm.read_at(entry_gpa, &mut buf) {
            tracing::error!(
                level,
                entry_gpa = format!("{entry_gpa:#x}"),
                error = %e,
                "stage-1 walk: failed to read descriptor from guest memory"
            );
            return;
        }
        let desc = u64::from_le_bytes(buf);
        let valid = desc & 1 != 0;
        let low2 = desc & 0x3;
        tracing::info!(
            level,
            index,
            width,
            table_base = format!("{table:#x}"),
            entry_gpa = format!("{entry_gpa:#x}"),
            descriptor = format!("{desc:#x}"),
            valid,
            low2,
            "stage-1 walk: level descriptor"
        );
        if !valid {
            tracing::error!(
                level,
                descriptor = format!("{desc:#x}"),
                "stage-1 walk: INVALID descriptor -> translation fault at this level; \
                 the page is genuinely UNMAPPED in the guest's own tables"
            );
            return;
        }
        if level < 3 {
            if low2 == 0b01 {
                tracing::info!(
                    level,
                    descriptor = format!("{desc:#x}"),
                    "stage-1 walk: BLOCK descriptor (valid) -> VA mapped by a block; leaf is VALID"
                );
                return;
            }
            // Table descriptor (0b11); descend.
            table = desc & TABLE_ADDR_MASK;
        } else if low2 == 0b11 {
            let pa = (desc & TABLE_ADDR_MASK) | (far & 0xfff);
            tracing::error!(
                descriptor = format!("{desc:#x}"),
                pa = format!("{pa:#x}"),
                "stage-1 walk: L3 PAGE descriptor is VALID -> the page IS mapped in guest RAM; \
                 a hardware translation fault here is SPURIOUS (OpenVMM/HVF walker-coherency bug)"
            );
        } else {
            tracing::error!(
                descriptor = format!("{desc:#x}"),
                "stage-1 walk: L3 descriptor has valid bit but is not a page (0b01 reserved)"
            );
        }
    }
}

/// Non-logging companion to [`diag_walk_ttbr1`]: returns `Some(true)` if `far`
/// translates through TTBR1 to a VALID leaf, `Some(false)` on an invalid
/// descriptor, `None` if guest memory could not be read. Used by the run-loop
/// sampler to capture the leaf state **at fault time**. The later crash-time
/// walk can disagree if the guest resolved a genuine demand fault in between —
/// that difference is exactly what distinguishes a spurious fault (valid at both
/// times: the page was always mapped, the HW walker just didn't see it) from a
/// real demand fault (invalid at fault time, valid once the guest paged it in).
pub(crate) fn diag_walk_leaf_valid(gm: &GuestMemory, ttbr1: u64, tcr: u64, far: u64) -> Option<bool> {
    const TABLE_ADDR_MASK: u64 = 0x0000_ffff_ffff_f000;
    let t1sz = (tcr >> 16) & 0x3f;
    let level_base = [39u32, 30, 21, 12];
    let top_bit = 63u32.saturating_sub(t1sz as u32);
    let start_level = level_base.iter().position(|&b| b <= top_bit).unwrap_or(3);
    let start_width = (top_bit - level_base[start_level] + 1).min(9);
    let mut table = (ttbr1 & 0x0000_ffff_ffff_ffff) & !((8u64 << start_width) - 1);
    for level in start_level..=3 {
        let width = if level == start_level { start_width } else { 9 };
        let index = (far >> level_base[level]) & ((1u64 << width) - 1);
        let mut buf = [0u8; 8];
        gm.read_at(table + index * 8, &mut buf).ok()?;
        let desc = u64::from_le_bytes(buf);
        if desc & 1 == 0 {
            return Some(false);
        }
        if level < 3 {
            if desc & 0x3 == 0b01 {
                return Some(true); // block descriptor
            }
            table = desc & TABLE_ADDR_MASK;
        } else {
            return Some(desc & 0x3 == 0b11); // L3 page descriptor
        }
    }
    Some(true)
}

/// Translate a high-half (TTBR1) guest VA to its guest-physical address by
/// walking the guest's own stage-1 tables, mirroring [`diag_walk_leaf_valid`]
/// but returning the resolved GPA (honoring block descriptors and the page
/// offset). Returns `None` if any level is invalid or unreadable. Used by
/// [`diag_decode_bugcheck`] to read the EXCEPTION_RECORD/CONTEXT that a Windows
/// bugcheck references by virtual address.
pub(crate) fn diag_translate_ttbr1(gm: &GuestMemory, ttbr1: u64, tcr: u64, va: u64) -> Option<u64> {
    const TABLE_ADDR_MASK: u64 = 0x0000_ffff_ffff_f000;
    let t1sz = (tcr >> 16) & 0x3f;
    let level_base = [39u32, 30, 21, 12];
    let top_bit = 63u32.saturating_sub(t1sz as u32);
    let start_level = level_base.iter().position(|&b| b <= top_bit).unwrap_or(3);
    let start_width = (top_bit - level_base[start_level] + 1).min(9);
    let mut table = (ttbr1 & 0x0000_ffff_ffff_ffff) & !((8u64 << start_width) - 1);
    for level in start_level..=3 {
        let width = if level == start_level { start_width } else { 9 };
        let base_bit = level_base[level];
        let index = (va >> base_bit) & ((1u64 << width) - 1);
        let mut buf = [0u8; 8];
        gm.read_at(table + index * 8, &mut buf).ok()?;
        let desc = u64::from_le_bytes(buf);
        if desc & 1 == 0 {
            return None;
        }
        if level < 3 {
            if desc & 0x3 == 0b01 {
                // Block descriptor: output[47:base_bit] from desc, low bits from VA.
                let block_off_mask = (1u64 << base_bit) - 1;
                return Some((desc & TABLE_ADDR_MASK & !block_off_mask) | (va & block_off_mask));
            }
            table = desc & TABLE_ADDR_MASK;
        } else if desc & 0x3 == 0b11 {
            return Some((desc & TABLE_ADDR_MASK) | (va & 0xfff));
        } else {
            return None;
        }
    }
    None
}

/// Given a high-half kernel VA that lies inside a loaded PE image, scan downward
/// page-by-page for the `MZ`/`PE\0\0` header and extract the module name from the
/// image's export directory. Turns the anonymous return addresses in a bugcheck
/// backtrace into module names (e.g. `ntoskrnl.exe`, `vmbus.sys`), which names
/// the subsystem that received the NULL. Returns `(image_base, name)`.
pub(crate) fn diag_identify_module(
    gm: &GuestMemory,
    ttbr1: u64,
    tcr: u64,
    va: u64,
) -> Option<(u64, String)> {
    let rd16 = |a: u64| -> Option<u16> {
        let pa = diag_translate_ttbr1(gm, ttbr1, tcr, a)?;
        let mut b = [0u8; 2];
        gm.read_at(pa, &mut b).ok()?;
        Some(u16::from_le_bytes(b))
    };
    let rd32 = |a: u64| -> Option<u32> {
        let pa = diag_translate_ttbr1(gm, ttbr1, tcr, a)?;
        let mut b = [0u8; 4];
        gm.read_at(pa, &mut b).ok()?;
        Some(u32::from_le_bytes(b))
    };

    let rd_cstr = |a: u64, max: u64| -> String {
        let mut s = String::new();
        for i in 0..max {
            match rd16(a + i) {
                Some(w) => {
                    let c = (w & 0xff) as u8;
                    if c == 0 {
                        break;
                    }
                    if c.is_ascii_graphic() {
                        s.push(c as char);
                    }
                }
                None => break,
            }
        }
        s
    };

    let mut page = va & !0xfff;
    // Cover ntoskrnl-sized images (~16 MiB) worth of downward scan.
    for _ in 0..4096u32 {
        if rd16(page) == Some(0x5a4d) {
            // Candidate DOS header; validate the PE signature via e_lfanew.
            if let Some(e_lfanew) = rd32(page + 0x3c) {
                if e_lfanew < 0x1000 && rd32(page + e_lfanew as u64) == Some(0x0000_4550) {
                    // PE32+ optional header: DataDirectory begins at +0x70 after
                    // the 4-byte signature + 20-byte file header. Export = index 0,
                    // Debug = index 6.
                    let datadir = page + e_lfanew as u64 + 4 + 20 + 0x70;

                    // Parse the CodeView (RSDS) record first: it yields the PDB
                    // basename AND the Microsoft symbol-server key (GUID+Age) so the
                    // exact matching PDB can be fetched offline. Present on both
                    // drivers (no export table) and ntoskrnl. Emit the sympath here
                    // so every module on the stack is fetchable regardless of whether
                    // it also has an export name.
                    let mut pdb_name: Option<String> = None;
                    if let (Some(dbg_rva), Some(dbg_size)) =
                        (rd32(datadir + 6 * 8), rd32(datadir + 6 * 8 + 4))
                    {
                        if dbg_rva != 0 {
                            let count = (dbg_size / 28).min(32);
                            for i in 0..count as u64 {
                                let e = page + dbg_rva as u64 + i * 28;
                                if rd32(e + 12) == Some(2) {
                                    // IMAGE_DEBUG_TYPE_CODEVIEW → AddressOfRawData@20.
                                    if let Some(cv_rva) = rd32(e + 20) {
                                        let cv = page + cv_rva as u64;
                                        // "RSDS" magic, then GUID(16)+Age(4), name@24.
                                        if rd32(cv) == Some(0x5344_5352) {
                                            let pdb = rd_cstr(cv + 24, 64);
                                            let base = pdb
                                                .rsplit(['\\', '/'])
                                                .next()
                                                .unwrap_or(&pdb)
                                                .to_string();
                                            // GUID stored as {Data1:u32 LE}{Data2:u16 LE}
                                            // {Data3:u16 LE}{Data4:8 raw bytes}; the
                                            // server key is D1(8)D2(4)D3(4)D4(16)+Age(hex).
                                            if let (Some(d1), Some(d2), Some(d3), Some(age)) = (
                                                rd32(cv + 4),
                                                rd16(cv + 8),
                                                rd16(cv + 10),
                                                rd32(cv + 20),
                                            ) {
                                                let mut d4 = [0u8; 8];
                                                let mut ok = true;
                                                for (i, b) in d4.iter_mut().enumerate() {
                                                    match rd16(cv + 12 + i as u64) {
                                                        Some(w) => *b = (w & 0xff) as u8,
                                                        None => ok = false,
                                                    }
                                                }
                                                if ok && !base.is_empty() {
                                                    let d4hex: String = d4
                                                        .iter()
                                                        .map(|b| format!("{b:02X}"))
                                                        .collect();
                                                    let sig = format!(
                                                        "{d1:08X}{d2:04X}{d3:04X}{d4hex}{age:X}"
                                                    );
                                                    tracing::error!(
                                                        pdb = base,
                                                        sig = sig,
                                                        image_base = format!("{page:#x}"),
                                                        sympath = format!("{base}/{sig}/{base}"),
                                                        "bugcheck decode: module PDB signature"
                                                    );
                                                }
                                            }
                                            if !base.is_empty() {
                                                pdb_name = Some(base);
                                            }
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Prefer the export directory's module name for display (present
                    // on ntoskrnl and most DLLs); else fall back to the PDB basename.
                    if let Some(export_rva) = rd32(datadir) {
                        if export_rva != 0 {
                            if let Some(name_rva) = rd32(page + export_rva as u64 + 0x0c) {
                                if name_rva != 0 {
                                    let name = rd_cstr(page + name_rva as u64, 64);
                                    if !name.is_empty() {
                                        return Some((page, name));
                                    }
                                }
                            }
                        }
                    }

                    return Some((page, pdb_name.unwrap_or_else(|| String::from("<unknown>"))));
                }
            }
        }
        if page < 0xffff_0000_0000_1000 {
            break;
        }
        page -= 0x1000;
    }
    None
}

/// Decode a Windows bugcheck's reference structures at crash time. Windows hands
/// the host the bugcheck code (P0) plus, for exception-class stops, the faulting
/// PC and the on-stack `EXCEPTION_RECORD`/`CONTEXT` by virtual address (P2..P4).
/// Translating and reading them turns an opaque stop code into: the faulting
/// instruction word, the access type + faulting VA (for `0xC0000005`), and the
/// full integer register file at fault time — which names the register that held
/// the bad pointer. All high-half kernel VAs translate through the live TTBR1
/// (the bugcheck runs in the faulting thread's context and never switches the
/// high-half mappings, which are global across address spaces).
pub(crate) fn diag_decode_bugcheck(
    gm: &GuestMemory,
    ttbr1: u64,
    tcr: u64,
    code: u64,
    p2: u64,
    p3: u64,
    p4: u64,
) {
    const HIGH_HALF: u64 = 0xffff_0000_0000_0000;

    // Faulting instruction word at the exception PC (P2). Valid for the
    // exception-class stops (0x7E/0x8E/0x1E) where P2 is the fault address.
    if p2 >= HIGH_HALF {
        if let Some(pa) = diag_translate_ttbr1(gm, ttbr1, tcr, p2) {
            let mut ib = [0u8; 4];
            if gm.read_at(pa, &mut ib).is_ok() {
                tracing::error!(
                    pc = format!("{p2:#x}"),
                    instr = format!("{:#010x}", u32::from_le_bytes(ib)),
                    "bugcheck decode: faulting instruction word"
                );
            }
        }
    }

    // SYSTEM_THREAD_EXCEPTION_NOT_HANDLED: P3 = EXCEPTION_RECORD*, P4 = CONTEXT*.
    if code != 0x7e && code != 0x1000_007e {
        return;
    }

    // EXCEPTION_RECORD: ExceptionCode@0x00, NumberParameters@0x18,
    // ExceptionInformation[]@0x20 ([0]=access kind, [1]=faulting VA).
    if p3 >= HIGH_HALF {
        if let Some(pa) = diag_translate_ttbr1(gm, ttbr1, tcr, p3) {
            let mut er = [0u8; 0x40];
            if gm.read_at(pa, &mut er).is_ok() {
                let exc_code = u32::from_le_bytes(er[0x00..0x04].try_into().unwrap());
                let nparams = u32::from_le_bytes(er[0x18..0x1c].try_into().unwrap());
                let info0 = u64::from_le_bytes(er[0x20..0x28].try_into().unwrap());
                let info1 = u64::from_le_bytes(er[0x28..0x30].try_into().unwrap());
                let access = match info0 {
                    0 => "read",
                    1 => "write",
                    8 => "execute",
                    _ => "other",
                };
                tracing::error!(
                    exception_code = format!("{exc_code:#010x}"),
                    number_parameters = nparams,
                    access_type = access,
                    faulting_va = format!("{info1:#x}"),
                    "bugcheck decode: EXCEPTION_RECORD"
                );
            }
        }
    }

    // CONTEXT (ARM64): Cpsr@0x04, X0..X30@0x08 (31 regs), Sp@0x100, Pc@0x108.
    if p4 >= HIGH_HALF {
        if let Some(pa) = diag_translate_ttbr1(gm, ttbr1, tcr, p4) {
            let mut cx = [0u8; 0x110];
            if gm.read_at(pa, &mut cx).is_ok() {
                let rd = |off: usize| u64::from_le_bytes(cx[off..off + 8].try_into().unwrap());
                for base in (0..31usize).step_by(6) {
                    let end = (base + 6).min(31);
                    let regs = (base..end)
                        .map(|i| format!("x{i}={:#x}", rd(0x08 + i * 8)))
                        .collect::<Vec<_>>()
                        .join(" ");
                    tracing::error!(regs = regs, "bugcheck decode: CONTEXT gpr");
                }
                let sp = rd(0x100);
                let pc = rd(0x108);
                let fp = rd(0x08 + 29 * 8);
                let lr = rd(0x08 + 30 * 8);
                let cpsr = u32::from_le_bytes(cx[0x04..0x08].try_into().unwrap());
                tracing::error!(
                    sp = format!("{sp:#x}"),
                    pc = format!("{pc:#x}"),
                    cpsr = format!("{cpsr:#x}"),
                    "bugcheck decode: CONTEXT sp/pc/cpsr"
                );

                // Instruction window around the faulting PC (aligned): reach back
                // far enough to capture where the indirect-call target (x8) and the
                // NULL destination (x0) are set up, plus the faulting store.
                let win_start = pc.saturating_sub(0x60) & !0x3;
                for i in 0..28u64 {
                    let ia = win_start + i * 4;
                    if let Some(ipa) = diag_translate_ttbr1(gm, ttbr1, tcr, ia) {
                        let mut ib = [0u8; 4];
                        if gm.read_at(ipa, &mut ib).is_ok() {
                            let marker = if ia == pc { " <== FAULT" } else { "" };
                            let word = u32::from_le_bytes(ib);
                            // Decode a direct BL (opcode 100101) and resolve its
                            // target's module+offset — the branch just before the
                            // faulting store is the helper that returned NULL, so
                            // naming it identifies the missing dependency.
                            let mut branch = String::new();
                            if word >> 26 == 0b10_0101 {
                                let imm = ((word & 0x03ff_ffff) as i32) << 6 >> 6; // sign-extend imm26
                                let target = ia.wrapping_add((imm as i64 as u64) << 2);
                                let sym = diag_identify_module(gm, ttbr1, tcr, target)
                                    .map(|(b, n)| format!("{n}+{:#x}", target - b))
                                    .unwrap_or_else(|| String::from("?"));
                                branch = format!(" bl->{target:#x} ({sym})");
                            }
                            tracing::error!(
                                addr = format!("{ia:#x}"),
                                word = format!("{word:#010x}"),
                                "bugcheck decode: code window{marker}{branch}"
                            );
                        }
                    }
                }

                // Frame-pointer backtrace: Windows ARM64 uses x29 as the frame
                // pointer with standard {fp,lr} frame records ([fp]=prev fp,
                // [fp+8]=saved lr). Saved LRs carry a PAC (pointer-auth) signature
                // in the upper VA bits (bits >= 64-T1SZ), so strip it to recover
                // the canonical kernel VA, then resolve each to its module so the
                // subsystem that passed the NULL destination is named.
                let t1sz = (tcr >> 16) & 0x3f;
                let va_bits = 64u64.saturating_sub(t1sz);
                let va_mask = (1u64 << va_bits) - 1;
                let strip_pac = |v: u64| (v & va_mask) | !va_mask;

                let mut named: std::collections::BTreeMap<u64, String> =
                    std::collections::BTreeMap::new();
                let mut name_of = |addr: u64| -> String {
                    if let Some((base, name)) = diag_identify_module(gm, ttbr1, tcr, addr) {
                        named.entry(base).or_insert_with(|| name.clone());
                        format!("{name}+{:#x}", addr - base)
                    } else {
                        String::from("?")
                    }
                };

                let leaf = strip_pac(lr);
                tracing::error!(
                    lr = format!("{leaf:#x}"),
                    module = name_of(leaf),
                    "bugcheck decode: backtrace #0 (leaf lr)"
                );
                let mut cur = fp;
                for depth in 1..=16u32 {
                    if cur < HIGH_HALF || cur & 0x7 != 0 {
                        break;
                    }
                    let Some(fpa) = diag_translate_ttbr1(gm, ttbr1, tcr, cur) else {
                        break;
                    };
                    let mut rec = [0u8; 16];
                    if gm.read_at(fpa, &mut rec).is_err() {
                        break;
                    }
                    let next_fp = u64::from_le_bytes(rec[0..8].try_into().unwrap());
                    let ret = strip_pac(u64::from_le_bytes(rec[8..16].try_into().unwrap()));
                    if ret == 0 || ret < HIGH_HALF {
                        break;
                    }
                    tracing::error!(
                        ret = format!("{ret:#x}"),
                        module = name_of(ret),
                        fp = format!("{cur:#x}"),
                        "bugcheck decode: backtrace #{depth}"
                    );
                    if next_fp <= cur {
                        break;
                    }
                    cur = next_fp;
                }
                for (base, name) in named {
                    tracing::error!(base = format!("{base:#x}"), name, "bugcheck decode: module");
                }
                let _ = sp;
            }
        }
    }
}

/// Live frame-pointer backtrace + P3 resolution for a bugcheck
/// whose parameters are NOT the 0x7E EXCEPTION_RECORD/CONTEXT shape (e.g. the
/// 0x5C HAL_INITIALIZATION_FAILED, where P3 is a bare kernel VA and P4 an
/// interrupt id). Seeds the walk from the *live* guest registers at the crash
/// MSR write, so the chain runs current -> KeBugCheck2 -> KeBugCheckEx -> the
/// routine that invoked it. Windows ARM64 uses x29 as the frame pointer with
/// {fp,lr} records; saved LRs carry a PAC signature in the high VA bits
/// (stripped here). Also resolves P3 to its module.
#[expect(clippy::too_many_arguments)]
pub(crate) fn diag_backtrace_live(
    gm: &GuestMemory,
    ttbr1: u64,
    tcr: u64,
    pc: u64,
    fp: u64,
    lr: u64,
    p3: u64,
) {
    const HIGH_HALF: u64 = 0xffff_0000_0000_0000;
    let t1sz = (tcr >> 16) & 0x3f;
    let va_bits = 64u64.saturating_sub(t1sz);
    let va_mask = (1u64 << va_bits) - 1;
    let strip_pac = |v: u64| (v & va_mask) | !va_mask;

    let mut named: std::collections::BTreeMap<u64, String> = std::collections::BTreeMap::new();
    let mut name_of = |addr: u64| -> String {
        if let Some((base, name)) = diag_identify_module(gm, ttbr1, tcr, addr) {
            named.entry(base).or_insert_with(|| name.clone());
            format!("{name}+{:#x}", addr - base)
        } else {
            String::from("?")
        }
    };

    // Resolve P3 (the HAL passes a kernel VA of interest here).
    if p3 >= HIGH_HALF {
        tracing::error!(
            p3 = format!("{p3:#x}"),
            module = name_of(p3),
            "bugcheck backtrace: P3 resolves to"
        );
    }

    let pcs = strip_pac(pc);
    tracing::error!(
        frame = 0u32,
        addr = format!("{pcs:#x}"),
        module = name_of(pcs),
        "bugcheck backtrace: pc"
    );
    let leaf = strip_pac(lr);
    tracing::error!(
        frame = 1u32,
        addr = format!("{leaf:#x}"),
        module = name_of(leaf),
        "bugcheck backtrace: leaf lr"
    );
    let mut cur = fp;
    for depth in 2..=24u32 {
        if cur < HIGH_HALF || cur & 0x7 != 0 {
            break;
        }
        let Some(fpa) = diag_translate_ttbr1(gm, ttbr1, tcr, cur) else {
            break;
        };
        let mut rec = [0u8; 16];
        if gm.read_at(fpa, &mut rec).is_err() {
            break;
        }
        let next_fp = u64::from_le_bytes(rec[0..8].try_into().unwrap());
        let ret = strip_pac(u64::from_le_bytes(rec[8..16].try_into().unwrap()));
        if ret == 0 || ret < HIGH_HALF {
            break;
        }
        tracing::error!(
            frame = depth,
            addr = format!("{ret:#x}"),
            module = name_of(ret),
            fp = format!("{cur:#x}"),
            "bugcheck backtrace: frame"
        );
        if next_fp <= cur {
            break;
        }
        cur = next_fp;
    }
    for (base, name) in named {
        tracing::error!(base = format!("{base:#x}"), name, "bugcheck backtrace: module");
    }
}

/// Diagnostic ring of the most-recent distinct in-guest EL1 data aborts as
/// `(ESR_EL1, FAR_EL1, ELR_EL1, leaf_valid_at_fault_time)`, populated by the
/// run-loop sampler and drained at crash time by [`diag_dump_fault_ring`]. The
/// validity code is `1` (valid), `0` (invalid), or `2` (unknown/low-half/walk
/// failed).
static DIAG_FAULT_RING: Mutex<std::collections::VecDeque<(u64, u64, u64, u8)>> =
    Mutex::new(std::collections::VecDeque::new());

/// Drains and logs the recorded in-guest EL1 data-abort ring, walking each
/// high-half (TTBR1) faulting VA's stage-1 translation with the live
/// `ttbr1`/`tcr`. Called at crash time so the fault chain leading to the
/// bugcheck — from the original trigger through to the final unhandled fault —
/// is visible together with whether each leaf was mapped at fault time (spurious
/// HW fault) or absent (a real, unresolved fault).
pub(crate) fn diag_dump_fault_ring(gm: &GuestMemory, ttbr1: u64, tcr: u64) {
    let entries: Vec<(u64, u64, u64, u8)> = {
        let mut ring = DIAG_FAULT_RING.lock();
        ring.drain(..).collect()
    };
    tracing::error!(
        count = entries.len(),
        "in-guest EL1 data-abort chain leading to crash (oldest first)"
    );
    for (i, (esr, far, elr, fault_time_valid)) in entries.iter().enumerate() {
        let ec = (esr >> 26) & 0x3f;
        let dfsc = esr & 0x3f;
        let wnr = (esr >> 6) & 1;
        let fault_time_leaf = match fault_time_valid {
            1 => "VALID",
            0 => "INVALID",
            _ => "unknown",
        };
        tracing::error!(
            seq = i,
            esr = format!("{esr:#x}"),
            ec = format!("{ec:#x}"),
            dfsc = format!("{dfsc:#x}"),
            wnr,
            far = format!("{far:#x}"),
            elr = format!("{elr:#x}"),
            fault_time_leaf,
            "fault-chain entry"
        );
        // Only high-half VAs translate through TTBR1; a low-half (user/TTBR0)
        // FAR would walk the wrong root, so skip the walk for those.
        if *far >= 0xffff_0000_0000_0000 {
            diag_walk_ttbr1(gm, ttbr1, tcr, *far);
        }
    }
}

/// `PMCR_EL0.E` (bit 0) — cycle counter enable.
const PMCR_EL0_E: u64 = 1 << 0;
/// `PMCR_EL0.C` (bit 2) — cycle counter reset (write-1 action).
const PMCR_EL0_C: u64 = 1 << 2;
/// `PMCR_EL0.LC` (bit 6) — 64-bit (long) cycle counter.
const PMCR_EL0_LC: u64 = 1 << 6;

impl BindProcessor for HvfProcessorBinder {
    type Processor<'a> = HvfProcessor<'a>;
    type Error = Error;

    fn bind(&mut self) -> Result<Self::Processor<'_>, Self::Error> {
        let mut vcpu = HvfVcpu::new()?;

        let state = self.state.take().unwrap();
        let inner = &self.partition.vps[self.vp_index.index() as usize];

        // Initialize the guest-visible AArch64 feature ID registers. First log
        // the full raw menu HVF exposes on this host: this is the UPPER BOUND of
        // what we may advertise to the virtual CPU. We can hide/clear features
        // the VMM does not model, but must never advertise a feature the
        // underlying core cannot execute — which also makes the policy portable
        // across Apple silicon generations (an older core that lacks a feature
        // simply reports a lower value here, and the clamp follows it).
        tracing::info!(
            midr = format!("{:#x}", vcpu.sys_reg(abi::HvSysReg::MIDR_EL1)?),
            pfr0 = format!("{:#x}", vcpu.sys_reg(abi::HvSysReg::ID_AA64PFR0_EL1)?),
            pfr1 = format!("{:#x}", vcpu.sys_reg(abi::HvSysReg::ID_AA64PFR1_EL1)?),
            dfr0 = format!("{:#x}", vcpu.sys_reg(abi::HvSysReg::ID_AA64DFR0_EL1)?),
            dfr1 = format!("{:#x}", vcpu.sys_reg(abi::HvSysReg::ID_AA64DFR1_EL1)?),
            isar0 = format!("{:#x}", vcpu.sys_reg(abi::HvSysReg::ID_AA64ISAR0_EL1)?),
            isar1 = format!("{:#x}", vcpu.sys_reg(abi::HvSysReg::ID_AA64ISAR1_EL1)?),
            mmfr0 = format!("{:#x}", vcpu.sys_reg(abi::HvSysReg::ID_AA64MMFR0_EL1)?),
            mmfr1 = format!("{:#x}", vcpu.sys_reg(abi::HvSysReg::ID_AA64MMFR1_EL1)?),
            mmfr2 = format!("{:#x}", vcpu.sys_reg(abi::HvSysReg::ID_AA64MMFR2_EL1)?),
            "raw AArch64 ID-register menu from HVF (host capability upper bound)"
        );
        // Install the OpenVMM virtual-CPU ID-register policy (host-clamped).
        sanitize_id_registers(&mut vcpu)?;
        // Set the MPIDR.
        vcpu.set_sys_reg(abi::HvSysReg::MPIDR_EL1, inner.vp_info.mpidr.into())?;

        // Record the live HVF vcpu id in the wake actor (enables the
        // running-state `hv_vcpus_exit` wake).
        inner.actor.set_vcpu(vcpu.vcpu);

        let mut vp = HvfProcessor {
            partition: &self.partition,
            inner,
            vcpu,
            wfi: false,
            on: inner.vp_info.base.vp_index.is_bsp(),
            gicr: state.gicr,
            hv1: state.hv1,
            vmtime: state.vmtime,
            pmu: PmuState::default(),
            crash_params: [0; 5],
        };

        // Set initial register state.
        let mut state = vp.access_state(Vtl::Vtl0);
        state
            .set_registers(&StateElement::at_reset(
                &self.partition.caps,
                &inner.vp_info,
            ))
            .unwrap();

        Ok(vp)
    }
}

/// Minimal PMUv3 cycle-counter model for `virt_hvf`.
///
/// Windows-on-ARM64 programs the cycle counter during early HAL bring-up
/// (PMCR_EL0/PMCNTENSET_EL0 with the cycle-counter bit) and then busy-waits on
/// PMCCNTR_EL0 to calibrate its delay loops. The PMU is otherwise unmodeled, so
/// without this the counter reads as a constant zero, the guest derives a bogus
/// cycle frequency (or spins waiting for the counter to advance), and early boot
/// wedges. Hiding `ID_AA64DFR0_EL1.PMUVer` is not sufficient on its own: this
/// guest drives the cycle counter regardless.
///
/// We back PMCCNTR_EL0 with the VM's monotonic time so it advances at a steady
/// rate; the guest then calibrates a stable frequency and its delays resolve in
/// real time. Event counters are reported as absent (PMCR_EL0.N == 0); the other
/// PMU registers are modeled as architectural RAZ/WI state so the accesses no
/// longer fall through to the unknown-register path.
#[derive(Debug, Default, Inspect)]
struct PmuState {
    /// PMCR_EL0.E (bit 0) — whether the cycle counter is currently counting.
    enabled: bool,
    /// Logical PMCCNTR_EL0 value captured at the last re-base point.
    cycle_offset: u64,
    /// VM time (100ns units) captured at the last re-base point.
    cycle_base_100ns: u64,
    /// PMCNTENSET_EL0/PMCNTENCLR_EL0 (cycle-counter bit 31 + event bits).
    counter_enable: u32,
    /// PMINTENSET_EL1/PMINTENCLR_EL1.
    int_enable: u32,
    /// PMUSERENR_EL0 (EL0 access controls).
    userenr: u32,
    /// PMCCFILTR_EL0.
    ccfiltr: u32,
    /// PMSELR_EL0 counter selector.
    selr: u32,
}

impl PmuState {
    /// Cycles attributed per 100ns of VM time (≈3 GHz). The absolute rate is
    /// immaterial because guests calibrate the cycle counter against the
    /// architected timer; only a steady, monotonic advance matters.
    const CYCLES_PER_100NS: u64 = 300;

    /// Current PMCCNTR_EL0 value at the given VM time.
    fn pmccntr(&self, now_100ns: u64) -> u64 {
        if self.enabled {
            let elapsed = now_100ns.wrapping_sub(self.cycle_base_100ns);
            self.cycle_offset
                .wrapping_add(elapsed.wrapping_mul(Self::CYCLES_PER_100NS))
        } else {
            self.cycle_offset
        }
    }

    /// Re-base the counter so that `pmccntr(now)` reads `value` going forward.
    fn rebase(&mut self, value: u64, now_100ns: u64) {
        self.cycle_offset = value;
        self.cycle_base_100ns = now_100ns;
    }

    /// Handle a PMU system-register read. Returns `None` if `reg` is not a PMU
    /// register this model owns (so the caller can fall through).
    fn read_sysreg(&self, reg: SystemReg, now_100ns: u64) -> Option<u64> {
        let value = match reg {
            // The load-bearing register: must advance.
            SystemReg::PMCCNTR_EL0 => self.pmccntr(now_100ns),
            // Report a 64-bit cycle counter (LC, bit 6) and no event counters
            // (N == 0); reflect only the enable bit.
            SystemReg::PMCR_EL0 => PMCR_EL0_LC | if self.enabled { PMCR_EL0_E } else { 0 },
            SystemReg::PMCNTENSET_EL0 | SystemReg::PMCNTENCLR_EL0 => self.counter_enable.into(),
            SystemReg::PMINTENSET_EL1 | SystemReg::PMINTENCLR_EL1 => self.int_enable.into(),
            SystemReg::PMUSERENR_EL0 => self.userenr.into(),
            SystemReg::PMCCFILTR_EL0 => self.ccfiltr.into(),
            SystemReg::PMSELR_EL0 => self.selr.into(),
            // No counter ever overflows and no events are implemented.
            SystemReg::PMOVSSET_EL0 | SystemReg::PMOVSCLR_EL0 => 0,
            SystemReg::PMCEID0_EL0 | SystemReg::PMCEID1_EL0 => 0,
            _ => return None,
        };
        Some(value)
    }

    /// Handle a PMU system-register write. Returns `false` if `reg` is not a PMU
    /// register this model owns (so the caller can fall through).
    fn write_sysreg(&mut self, reg: SystemReg, value: u64, now_100ns: u64) -> bool {
        match reg {
            SystemReg::PMCR_EL0 => {
                // Snapshot the current count, then re-base, so toggling the
                // enable bit never makes the counter jump.
                let cur = self.pmccntr(now_100ns);
                self.enabled = value & PMCR_EL0_E != 0;
                self.rebase(cur, now_100ns);
                // C (bit 2): reset the cycle counter to zero.
                if value & PMCR_EL0_C != 0 {
                    self.rebase(0, now_100ns);
                }
            }
            SystemReg::PMCCNTR_EL0 => self.rebase(value, now_100ns),
            SystemReg::PMCNTENSET_EL0 => self.counter_enable |= value as u32,
            SystemReg::PMCNTENCLR_EL0 => self.counter_enable &= !(value as u32),
            SystemReg::PMINTENSET_EL1 => self.int_enable |= value as u32,
            SystemReg::PMINTENCLR_EL1 => self.int_enable &= !(value as u32),
            SystemReg::PMUSERENR_EL0 => self.userenr = value as u32,
            SystemReg::PMCCFILTR_EL0 => self.ccfiltr = value as u32,
            SystemReg::PMSELR_EL0 => self.selr = value as u32,
            // Write-to-clear overflow status / unused selects: accept and ignore
            // (no counters are modeled).
            SystemReg::PMOVSSET_EL0 | SystemReg::PMOVSCLR_EL0 => {}
            _ => return false,
        }
        true
    }
}

/// Returns `true` when an A64 trapped-instruction transfer-register field
/// (the data-abort `SRT` or the system-register `Rt`) encodes `XZR` rather than
/// a general-purpose register.
///
/// Per the A64 ISA, register number `0b11111` (31) designates `XZR`/`WZR` in
/// the load/store and `MSR`/`MRS` encodings — *not* the stack pointer. Reads of
/// `XZR` return zero and writes are discarded. This matters because
/// [`HvfProcessorRunner::vcpu`]'s `gp`/`set_gp` follow the *other* A64
/// convention where register 31 aliases `SP`: feeding `gp(31)` into a
/// `msr <sysreg>, xzr` would inject the guest's stack pointer (observed as
/// bogus `ICC_AP{0,1}R0_EL1` values during GIC init), and `set_gp(31, ..)` for
/// `mrs xzr, <sysreg>` would clobber it. Both the data-abort and
/// system-register trap paths route their register-number decisions through
/// this helper so they cannot diverge.
fn reg_is_xzr(reg: u8) -> bool {
    reg == 31
}

#[cfg(test)]
mod xzr_tests {
    use super::reg_is_xzr;

    /// Register number 31 decodes as `XZR` in the trapped load/store (`SRT`)
    /// and `MSR`/`MRS` (`Rt`) encodings; 0..=30 are real GP registers. This is
    /// the invariant that keeps `msr <sysreg>, xzr` from injecting the guest
    /// stack pointer and `mrs xzr, <sysreg>` from clobbering it — the bug that
    /// surfaced as bogus `ICC_AP{0,1}R0_EL1` writes during GIC init.
    #[test]
    fn only_reg_31_is_xzr() {
        for reg in 0..=30u8 {
            assert!(!reg_is_xzr(reg), "reg {reg} must be a GP register, not XZR");
        }
        assert!(reg_is_xzr(31), "reg 31 must decode as XZR");
    }
}

/// Reflects the host physical counter for guests that trap `CNTPCT_EL0` /
/// `CNTVCT_EL0`.
///
/// Apple's hypervisor traps physical-counter reads; left unhandled the guest
/// observes a counter frozen at zero, which breaks any guest that derives time
/// from `CNTPCT_EL0` (e.g. Windows' HAL reads it during timer bring-up). The
/// host counter advances at the same architected `CNTFRQ` rate the guest
/// already observes (HVF passes the virtual counter through untrapped), so
/// reflecting it yields a real, monotonic physical counter.
fn read_counter_sysreg(reg: SystemReg) -> Option<u64> {
    match reg {
        SystemReg::CNTPCT_EL0 | SystemReg::CNTVCT_EL0 => {
            let count: u64;
            // SAFETY: CNTVCT_EL0 is unprivileged-readable on AArch64 and has no
            // side effects.
            unsafe {
                core::arch::asm!(
                    "mrs {}, cntvct_el0",
                    out(reg) count,
                    options(nomem, nostack, preserves_flags),
                );
            }
            Some(count)
        }
        _ => None,
    }
}

/// Reads the counter frequency (`CNTFRQ_EL0`) in Hz — the tick rate shared by
/// `CNTVCT_EL0` and the guest's virtual timer.
fn read_cntfrq() -> u64 {
    let freq: u64;
    // SAFETY: CNTFRQ_EL0 is unprivileged-readable on AArch64 with no side effects.
    unsafe {
        core::arch::asm!(
            "mrs {}, cntfrq_el0",
            out(reg) freq,
            options(nomem, nostack, preserves_flags),
        );
    }
    freq
}


#[derive(InspectMut)]
pub struct HvfProcessor<'a> {
    #[inspect(skip)]
    partition: &'a HvfPartitionInner,
    #[inspect(flatten)]
    inner: &'a HvfVpInner,
    gicr: gic::Redistributor,
    hv1: ProcessorSynic,
    vmtime: VmTimeAccess,
    #[inspect(flatten)]
    vcpu: HvfVcpu,
    wfi: bool,
    on: bool,
    pmu: PmuState,
    /// Hyper-V guest-crash enlightenment parameters (`GuestCrashP0..P4`).
    /// Sticky registers latched by `HvSetVpRegisters`; reported when the guest
    /// writes `GuestCrashCtl` at `KeBugCheckEx` time.
    #[inspect(skip)]
    crash_params: [u64; 5],
}

#[derive(Debug, Inspect)]
struct HvfVcpu {
    vcpu: u64,
    #[inspect(skip)]
    exit: ExitPtr,
}

#[derive(Debug)]
struct ExitPtr(*mut abi::HvVcpuExit);

impl Deref for ExitPtr {
    type Target = abi::HvVcpuExit;

    fn deref(&self) -> &Self::Target {
        // SAFETY: the data pointed to is known to be valid and in fact
        // exclusively owned by us at this point.
        unsafe { &*self.0 }
    }
}

impl HvfVcpu {
    fn new() -> Result<Self, HvfError> {
        let mut vcpu = 0;
        let mut exit = null_mut();
        // SAFETY: `vcpu` and `exit` are valid buffers to receive the output parameters.
        unsafe { abi::hv_vcpu_create(&mut vcpu, &mut exit, null_mut()) }.chk()?;
        Ok(Self {
            vcpu,
            exit: ExitPtr(exit),
        })
    }

    fn cpsr(&self) -> Cpsr64 {
        let cpsr = Cpsr64::from(
            self.reg(abi::HvReg::CPSR)
                .expect("unrecoverable error getting CPSR"),
        );
        assert!(!cpsr.aa32(), "ARM32 not supported");
        cpsr
    }

    fn gp(&self, n: u8) -> u64 {
        if n < 31 {
            self.reg(abi::HvReg(abi::HvReg::X0.0 + n as u32))
                .expect("unrecoverable error getting GP")
        } else {
            let reg = if self.cpsr().sp() {
                abi::HvSysReg::SP_EL1
            } else {
                abi::HvSysReg::SP_EL0
            };
            self.sys_reg(reg).expect("unrecoverable error getting SP")
        }
    }

    fn set_gp(&mut self, n: u8, value: u64) {
        if n < 31 {
            self.set_reg(abi::HvReg(abi::HvReg::X0.0 + n as u32), value)
                .expect("unrecoverable failure to set GP")
        } else {
            let reg = if self.cpsr().sp() {
                abi::HvSysReg::SP_EL1
            } else {
                abi::HvSysReg::SP_EL0
            };
            self.set_sys_reg(reg, value)
                .expect("unrecoverable failure to set SP")
        }
    }

    fn pc(&self) -> u64 {
        self.reg(abi::HvReg::PC)
            .expect("unrecoverable error getting PC")
    }

    fn set_pc(&mut self, pc: u64) {
        self.set_reg(abi::HvReg::PC, pc)
            .expect("unrecoverable failure to set PC")
    }

    fn reg(&self, reg: abi::HvReg) -> Result<u64, HvfError> {
        let mut value = 0;
        // SAFETY: `value` is a valid buffer to receive the output.
        unsafe {
            abi::hv_vcpu_get_reg(self.vcpu, reg, &mut value).chk()?;
        }
        Ok(value)
    }

    fn sys_reg(&self, reg: abi::HvSysReg) -> Result<u64, HvfError> {
        let mut value = 0;
        // SAFETY: `value` is a valid buffer to receive the output.
        unsafe {
            abi::hv_vcpu_get_sys_reg(self.vcpu, reg, &mut value).chk()?;
        }
        Ok(value)
    }

    fn set_reg(&mut self, reg: abi::HvReg, value: u64) -> Result<(), HvfError> {
        // SAFETY: no special rquirements
        unsafe {
            abi::hv_vcpu_set_reg(self.vcpu, reg, value).chk()?;
        }
        Ok(())
    }

    fn set_sys_reg(&mut self, reg: abi::HvSysReg, value: u64) -> Result<(), HvfError> {
        // SAFETY: no special rquirements
        unsafe {
            abi::hv_vcpu_set_sys_reg(self.vcpu, reg, value).chk()?;
        }
        Ok(())
    }
}

impl Drop for HvfVcpu {
    fn drop(&mut self) {
        // SAFETY: no special requirements
        unsafe { abi::hv_vcpu_destroy(self.vcpu) }
            .chk()
            .expect("vcpu destroy cannot fail");
    }
}

impl HvfProcessor<'_> {
    fn hypercall(&mut self, _dev: &impl CpuIo, smccc: bool) {
        // HVF is a non-isolating development hypervisor: it is a dev vehicle for
        // desktop virtualization, not a confidential-computing host. We never
        // advertise VTL/CVM isolation (see `IsolationConfiguration` in
        // `hypercall.rs`, which reports `HvPartitionIsolationType::NONE`), so
        // all guest memory is plainly host-accessible at all times.
        //
        // Modern `vmbus.sys`/NT on ARM64 nonetheless exercise a small family of
        // private hypercalls during early boot and channel bring-up. We answer
        // the ones this non-isolating backend can honestly satisfy as semantic
        // no-ops. The identities below are from the private hvgdk/hvhdk headers;
        // note they are NOT the contiguous "host-visibility band" an earlier
        // revision assumed — 0x00D6 in particular is a TLB-maintenance call, and
        // the real ModifySparseGpaPageHostVisibility is 0x00DB (see below):
        //
        //   0x00D6  HvCallFlushTlb                       (enlightened TLB shootdown)
        //   0x00D7  HvCallAcquireSparseSpaPageHostAccess (SPA host access)
        //   0x00D8  HvCallReleaseSparseSpaPageHostAccess (SPA host access)
        //
        // 0x00D6 HvCallFlushTlb — the ARM64 enlightened TLB-shootdown call. The
        // header's HV_PARTITION_INFO_PAGE documents the contract: "if TlbInUse is
        // non-zero, the guest, when issuing a broadcast TLB invalidation, must in
        // addition issue a FlushTlb hypercall" — i.e. also flush the *hypervisor-
        // saved* TLB state of VPs that are descheduled when the architectural
        // `TLBI ..., IS` broadcast fires. Under HVF there is no such separate
        // hypervisor TLB: a vCPU that is not currently running has no live TLB
        // entries, and the guest's inner-shareable TLBI broadcast (which it always
        // issues) is honored by the hardware across every PE running the VMID. So
        // there is genuinely nothing extra to flush and SUCCESS is the correct
        // emulation, not an appeasement. This is consistent with — and depends on
        // — our keeping the TLB enlightenment *disabled*: `hypercall.rs` now
        // publishes `HV_PARTITION_INFO_PAGE.TlbInUse = 0` into the page the guest
        // registers via `PartitionInfoPage` (0x90015) and reads back `TlbiControl`
        // (0x90016) as `TlbiEnlightened = 0`, so a well-behaved guest relies on
        // its architectural `TLBI ..., IS` broadcast and need not issue this call
        // at all. (Apple's ARM64 HVF exposes no guest-TLB-invalidation primitive,
        // so the architectural broadcast is in any case the only path that can
        // actually maintain stage-1 coherence here.)
        //
        // 0x00D7/0x00D8 Acquire/ReleaseSparseSpaPageHostAccess — SLAT host-access
        // calls. For a non-isolated partition the host already has access to every
        // SPA page, so "(re)acquire / release host access" is trivially satisfied.
        //
        // (0x00DB HvCallModifySparseGpaPageHostVisibility — the call the earlier
        // revision mis-attributed to 0x00D6 — is the CVM page share/unshare call.
        // A non-isolated guest has no reason to issue it, so we deliberately do
        // NOT fake it; it stays `InvalidHypercallCode` until/unless observed.)
        //
        // Returning `InvalidHypercallCode` (our default for unknown codes) for the
        // calls the guest DOES make wedges boot: `vmbus.sys`/NT treat the failure
        // as fatal and storm the call (~1500/s) into a boot-loop.
        const HV_CALL_FLUSH_TLB: u16 = 0x00D6;
        const HV_CALL_ACQUIRE_SPARSE_SPA_PAGE_HOST_ACCESS: u16 = 0x00D7;
        const HV_CALL_RELEASE_SPARSE_SPA_PAGE_HOST_ACCESS: u16 = 0x00D8;

        // The hypervisor-assisted context-synchronization band. The NT kernel
        // and `vmbus.sys` issue these on ARM64 to broadcast an ISB-equivalent
        // barrier to a set of VPs after mutating shared state (e.g. the
        // code-integrity / hot-patch path):
        //
        //   0x0019  HvCallSyncContext    (Flags + UINT64 ProcessorMask)
        //   0x001A  HvCallSyncContextEx  (Flags + HV_VP_SET ProcessorSet)
        //
        // Both take a small input and return NO output; their sole effect is to
        // force the targeted VPs to context-synchronize. Under HVF every VP is a
        // native, cache-coherent core and every VM exit/entry world switch is
        // itself a context-synchronization event, so the requested barrier is
        // already satisfied — acknowledging SUCCESS is the correct emulation,
        // not merely an appeasement. (Returning `InvalidHypercallCode` instead
        // makes the guest treat the barrier as failed and boot-loop, storming
        // the call ~15k times/boot before each reset.)
        const HV_CALL_SYNC_CONTEXT: u16 = 0x0019;
        const HV_CALL_SYNC_CONTEXT_EX: u16 = 0x001A;

        // Control is X0 for the Hyper-V convention (hvc #1), X1 for SMCCC.
        let control = hvdef::hypercall::Control::from(self.vcpu.gp(smccc as u8));
        match control.code() {
            HV_CALL_FLUSH_TLB => {
                // Enlightened TLB shootdown — nothing to flush under HVF (see the
                // band comment above). Report any rep elements as processed so the
                // guest observes a clean, complete success. The ARM HVC
                // instruction already advanced PC (`pre_advanced`), so we only
                // write the output word into X0 (the result register).
                let output = hvdef::hypercall::HypercallOutput::SUCCESS
                    .with_elements_processed(control.rep_count());
                self.vcpu.set_gp(0, u64::from(output));
                tracelimit::info_ratelimited!(
                    code = control.code(),
                    reps = control.rep_count(),
                    "no-op success for enlightened FlushTlb hypercall"
                );
                return;
            }
            HV_CALL_ACQUIRE_SPARSE_SPA_PAGE_HOST_ACCESS
            | HV_CALL_RELEASE_SPARSE_SPA_PAGE_HOST_ACCESS => {
                // Non-isolated: the host already has access to every SPA page.
                // These are rep hypercalls; report every element processed so the
                // guest observes a clean, complete success. The ARM HVC
                // instruction already advanced PC (`pre_advanced`), so we only
                // write the output word into X0 (the result register).
                let output = hvdef::hypercall::HypercallOutput::SUCCESS
                    .with_elements_processed(control.rep_count());
                self.vcpu.set_gp(0, u64::from(output));
                tracelimit::event_ratelimited!(
                    tracing::Level::DEBUG,
                    code = control.code(),
                    reps = control.rep_count(),
                    "non-isolated no-op success for SPA host-access hypercall"
                );
                return;
            }
            HV_CALL_SYNC_CONTEXT | HV_CALL_SYNC_CONTEXT_EX => {
                // Not a rep hypercall and no output structure, so a plain
                // SUCCESS (zero elements processed) is the complete response.
                self.vcpu
                    .set_gp(0, u64::from(hvdef::hypercall::HypercallOutput::SUCCESS));
                tracelimit::event_ratelimited!(
                    tracing::Level::DEBUG,
                    code = control.code(),
                    "non-isolated no-op success for context-synchronization hypercall"
                );
                return;
            }
            _ => {}
        }

        let guest_memory = &self.partition.guest_memory;
        let handler = HvfHypercallHandler::new(self);
        HvfHypercallHandler::DISPATCHER.dispatch(
            guest_memory,
            hv1_hypercall::Arm64RegisterIo::new(handler, true, smccc),
        );
    }

    fn deliver_sints(&mut self, sints: u16) {
        self.inner
            .message_queues
            .post_pending_messages(sints, |sint, message| {
                self.hv1
                    .post_message(sint, message, &mut |vector, _auto_eoi| {
                        self.gicr.raise(vector)
                    })
            });
    }

    /// Computes the precise `vmtime` deadline at which this vCPU's virtual timer
    /// (CNTV) is due, for use while the guest is parked in WFI *outside*
    /// `hv_vcpu_run` — where HVF cannot raise `VTIMER_ACTIVATED` on its own.
    ///
    /// The guest's virtual counter is defined by HVF (`hv_vcpu.h`) as
    /// `CNTVCT_EL0 == mach_absolute_time() - vtimer_offset`. The deadline math
    /// therefore MUST align `CNTV_CVAL_EL0` against [`abi::mach_absolute_time`],
    /// *not* the host EL0 `CNTVCT_EL0` (which reads `mach_continuous_time` and
    /// includes host sleep the guest counter never saw). Mixing the two makes
    /// every idle guest read as "already expired" and hot-spin.
    ///
    /// * `None` — the vtimer is disabled or masked, so it cannot wake the guest;
    ///   nothing to wait for on its account.
    /// * `Some(now)` — it has already expired (ISTATUS set, or CVAL is in the
    ///   past): wake immediately so we re-enter the guest and HVF delivers the
    ///   genuine timer interrupt.
    /// * `Some(future)` — the exact time the timer will fire, converted from
    ///   counter ticks to a `vmtime` instant at the architected frequency.
    fn vtimer_deadline(&self) -> Option<VmTime> {
        const ENABLE: u64 = 1 << 0;
        const IMASK: u64 = 1 << 1;
        const ISTATUS: u64 = 1 << 2;

        let ctl = self.vcpu.sys_reg(abi::HvSysReg::CNTV_CTL_EL0).ok()?;
        if ctl & ENABLE == 0 || ctl & IMASK != 0 {
            return None;
        }
        if ctl & ISTATUS != 0 {
            return Some(self.vmtime.now());
        }

        let cval = self.vcpu.sys_reg(abi::HvSysReg::CNTV_CVAL_EL0).ok()?;

        // Align to the guest counter: CNTVCT_EL0 == mach_absolute_time() - offset.
        let mut offset = 0u64;
        // SAFETY: `offset` is a valid out-param.
        unsafe { abi::hv_vcpu_get_vtimer_offset(self.vcpu.vcpu, &mut offset) }
            .chk()
            .ok()?;
        // SAFETY: no requirements.
        let guest_now = unsafe { abi::mach_absolute_time() }.wrapping_sub(offset);

        if cval <= guest_now {
            return Some(self.vmtime.now());
        }

        let freq = read_cntfrq();
        if freq == 0 {
            return None;
        }
        let ticks = cval - guest_now;
        let secs = ticks / freq;
        let nanos = ((ticks % freq) as u128 * 1_000_000_000 / freq as u128) as u32;
        Some(self.vmtime.now().wrapping_add(Duration::new(secs, nanos)))
    }

    fn handle_smccc(&mut self, fc: FastCall) {
        match SmcCall(fc.with_hint(false).with_smc64(false)) {
            SmcCall::SMCCC_VERSION => {
                self.vcpu.set_gp(0, (1 << 16) | 1);
            }
            SmcCall::SMCCC_ARCH_FEATURES => {
                let feature_bits =
                    match SmcCall(FastCall::from(self.vcpu.gp(1) as u32).with_smc64(false)) {
                        SmcCall::SMCCC_ARCH_FEATURES => Some(0),
                        _ => None,
                    };
                self.vcpu.set_gp(0, feature_bits.unwrap_or(!0));
            }
            call => {
                tracelimit::warn_ratelimited!(?call, "ignoring unknown SMCCC call");
                self.vcpu.set_gp(0, !0);
            }
        }
    }

    fn handle_psci(&mut self, fc: FastCall) -> Result<(), VpHaltReason> {
        let mask = if fc.smc64() {
            u64::MAX
        } else {
            u32::MAX as u64
        };
        let r = match SmcCall(fc.with_smc64(false).with_hint(false)) {
            SmcCall::PSCI_VERSION => 1 << 16,
            SmcCall::PSCI_FEATURES => {
                let feature_bits =
                    match SmcCall(FastCall::from(self.vcpu.gp(1) as u32).with_smc64(false)) {
                        SmcCall::SMCCC_VERSION => Some(0),
                        SmcCall::CPU_SUSPEND => Some(0),
                        SmcCall::CPU_ON => Some(0),
                        SmcCall::CPU_OFF => Some(0),
                        SmcCall::AFFINITY_INFO => Some(0),
                        SmcCall::SYSTEM_OFF => Some(0),
                        SmcCall::SYSTEM_RESET => Some(0),
                        SmcCall::PSCI_FEATURES => Some(0),
                        _ => None,
                    };
                feature_bits.unwrap_or(PsciError::NOT_SUPPORTED.0)
            }
            SmcCall::CPU_SUSPEND => PsciError::INVALID_PARAMETERS.0,
            SmcCall::CPU_ON => {
                let target_cpu = self.vcpu.gp(1) & mask;
                let entry_point = self.vcpu.gp(2) & mask;
                let context_id = self.vcpu.gp(3) & mask;
                if let Some(vp) = self.partition.vps.iter().find(|vp| {
                    u64::from(vp.vp_info.mpidr) & u64::from(MpidrEl1::AFFINITY_MASK) == target_cpu
                }) {
                    let target_vp_index = vp.vp_info.base.vp_index.index();
                    let mut cpu_on = vp.cpu_on.lock();
                    if cpu_on.is_some() {
                        tracing::info!(
                            target_cpu,
                            target_vp_index,
                            "PSCI CPU_ON: request already pending (ON_PENDING)"
                        );
                        PsciError::ON_PENDING.0
                    } else {
                        // TODO check already on
                        *cpu_on = Some(CpuOnState {
                            pc: entry_point,
                            x0: context_id,
                        });
                        drop(cpu_on);
                        vp.notify();
                        tracing::info!(
                            target_cpu,
                            target_vp_index,
                            entry_point = format!("{entry_point:#x}"),
                            context_id,
                            "PSCI CPU_ON: starting secondary VP (SUCCESS)"
                        );
                        PsciError::SUCCESS.0
                    }
                } else {
                    tracing::warn!(
                        target_cpu,
                        "PSCI CPU_ON: no VP matches target affinity (INVALID_PARAMETERS)"
                    );
                    PsciError::INVALID_PARAMETERS.0
                }
            }
            SmcCall::CPU_OFF => {
                tracing::info!("PSCI CPU_OFF (returning DENIED)");
                PsciError::DENIED.0
            }
            SmcCall::AFFINITY_INFO => {
                let target_affinity = self.vcpu.gp(1) & mask;
                let lowest_affinity_level = self.vcpu.gp(2) & mask;
                tracelimit::warn_ratelimited!(
                    target_affinity,
                    lowest_affinity_level,
                    "PSCI AFFINITY_INFO (returning INVALID_PARAMETERS - unimplemented)"
                );
                PsciError::INVALID_PARAMETERS.0
            }
            SmcCall::SYSTEM_RESET => {
                return Err(VpHaltReason::Reset);
            }
            SmcCall::SYSTEM_OFF => return Err(VpHaltReason::PowerOff),
            SmcCall::MIGRATE_INFO_TYPE => PsciError::NOT_SUPPORTED.0,
            call => {
                tracelimit::warn_ratelimited!(?call, "ignoring unknown PSCI32 call");
                PsciError::NOT_SUPPORTED.0
            }
        };
        self.vcpu.set_gp(0, r as u64);
        Ok(())
    }

    fn handle_vendor_hyp(&mut self, fc: FastCall) {
        match SmcCall(fc.with_hint(false).with_smc64(false)) {
            SmcCall::VENDOR_HYP_UID => {
                for (i, &v) in hvdef::VENDOR_HYP_UID_MS_HYPERVISOR.iter().enumerate() {
                    self.vcpu.set_gp(i as u8, v.into());
                }
            }
            call => {
                tracelimit::warn_ratelimited!(?call, "ignoring unknown VENDOR_HYP call");
                self.vcpu.set_gp(0, !0);
            }
        }
    }
}

/// Whether the default-off SMP-bringup diagnostic trace is enabled, gated on a
/// non-empty `OPENVMM_HVF_SMP_TRACE` environment variable.
///
/// The intermittent hang we chase wedges right after the first secondary comes
/// online: a vCPU stalls in WFI because `gicd.irq_pending` reports nothing
/// deliverable, so the per-CPU timer PPI / rescheduling SGI it is waiting on is
/// never taken, and the primary blocks forever in the CPU-up handshake. Host
/// stack samples only reveal parked-vs-spinning, not *why* delivery is gated.
/// This trace makes the gate observable: at each park it emits the parking VP's
/// redistributor snapshot (`PpiDiag`: pending/active/enable/group, PMR, group
/// enables, BPR, active-priority words, per-intid priority) so a pending PPI
/// blocked by a masked PMR, a disabled group, or a stuck active-priority bit is
/// visible directly, and secondaries still awaiting their `CPU_ON` are
/// distinguished from ones that came online and then stalled.
///
/// It additionally emits a rate-limited `hvf_pcdiag` record at each VM exit with
/// the guest PC/ELR/CPSR, so a vCPU that is *not* parked but busy-spinning in a
/// guest `cpu_relax`/YIELD loop (which host samples render only as opaque
/// `hv_trap`) reveals the recurring PC of the stuck loop.
fn smp_trace_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        let on = std::env::var("OPENVMM_HVF_SMP_TRACE")
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        if on {
            tracing::warn!(
                "HVF SMP-bringup trace ENABLED (OPENVMM_HVF_SMP_TRACE): emitting \
                 rate-limited `hvf_smpdiag` park records (CPU_ON wait + WFI gate) \
                 and `hvf_pcdiag` guest-exit PC records (busy-spin localization)"
            );
        }
        on
    })
}

impl<'p> Processor for HvfProcessor<'p> {
    type StateAccess<'a>
        = vp_state::HvfVpStateAccess<'a, 'p>
    where
        Self: 'a;

    fn set_debug_state(
        &mut self,
        _vtl: Vtl,
        _state: Option<&virt::x86::DebugState>,
    ) -> Result<(), <vp_state::HvfVpStateAccess<'_, 'p> as AccessVpState>::Error> {
        Ok(())
    }

    /// Resets per-VP emulated device state back to its post-boot baseline.
    ///
    /// Called on the VP's own thread while all VPs are stopped, after
    /// [`virt::ResetPartition::reset`] has scrubbed the partition-level state.
    /// The guest's boot registers are re-applied afterward by the firmware
    /// reload (`set_initial_regs`), so this only clears device/interrupt state:
    /// the per-VP redistributor, the synic (which also clears the shared synic
    /// state referenced by the partition's `GlobalSynic`), queued synic
    /// messages, the PMU model, any pending PSCI `CPU_ON` request, and the
    /// WFI/online run flags (the BSP comes back online; secondaries park until
    /// the guest powers them on again).
    fn reset(&mut self) -> Result<(), impl std::error::Error + Send + Sync + 'static> {
        self.gicr.reset();
        self.hv1.reset();
        self.pmu = PmuState::default();
        self.inner.message_queues.clear();
        *self.inner.cpu_on.lock() = None;
        self.wfi = false;
        self.on = self.inner.vp_info.base.vp_index.is_bsp();
        Ok::<(), Infallible>(())
    }

    async fn run_vp(
        &mut self,
        stop: StopVp<'_>,
        dev: &impl CpuIo,
    ) -> Result<Infallible, VpHaltReason> {
        let vp_index = self.inner.vp_info.base.vp_index;

        loop {
            self.inner.needs_yield.maybe_yield().await;

            poll_fn(|cx| {
                loop {
                    stop.check()?;

                    // Begin a fresh decision pass: reset the wake actor to
                    // RUNNING and consume any pending must-exit latch, so the
                    // work re-scan below observes everything a producer published
                    // before latching it.
                    self.inner.actor.begin_pass();

                    if let Some(cpu_on) = self.inner.cpu_on.lock().take() {
                        if self.on {
                            todo!("block this");
                        } else {
                            self.vcpu.set_gp(0, cpu_on.x0);
                            self.vcpu.set_pc(cpu_on.pc);
                            self.on = true;
                            tracing::info!(
                                vp_index = vp_index.index(),
                                pc = format!("{:#x}", cpu_on.pc),
                                "secondary VP came online (consumed CPU_ON)"
                            );
                        }
                    }

                    if !self.on {
                        // Secondary vCPU not yet powered on: park until a
                        // PSCI CPU_ON publishes a start request and notifies us.
                        match self
                            .inner
                            .actor
                            .try_park(cx.waker(), || self.inner.cpu_on.lock().is_none())
                        {
                            vp_actor::ParkDecision::Parked => {
                                if smp_trace_enabled() {
                                    tracelimit::info_ratelimited!(
                                        vp_index = vp_index.index(),
                                        "hvf_smpdiag: parking: secondary still awaiting PSCI CPU_ON"
                                    );
                                }
                                return Poll::Pending;
                            }
                            vp_actor::ParkDecision::Rescan => continue,
                        }
                    }

                    self.hv1
                        .request_sint_readiness(self.inner.message_queues.pending_sints());

                    let ref_time_now = self.vmtime.now().as_100ns();
                    let (ready_sints, next_ref_time) =
                        self.hv1.scan(ref_time_now, &mut |ppi, _auto_eoi| {
                            tracing::debug!(ppi, "ppi from message");
                            self.gicr.raise(ppi);
                        });

                    if let Some(next_ref_time) = next_ref_time {
                        // Convert from reference timer basis to vmtime basis via
                        // difference of programmed timer and current reference time.
                        const NUM_100NS_IN_SEC: u64 = 10 * 1000 * 1000;
                        let ref_diff = next_ref_time.saturating_sub(ref_time_now);
                        let ref_duration = Duration::new(
                            ref_diff / NUM_100NS_IN_SEC,
                            (ref_diff % NUM_100NS_IN_SEC) as u32 * 100,
                        );
                        let timeout = self.vmtime.now().wrapping_add(ref_duration);
                        self.vmtime.set_timeout_if_before(timeout);
                    }

                    if ready_sints != 0 {
                        self.deliver_sints(ready_sints);
                        continue;
                    }

                    if self.partition.gicd.irq_pending(&self.gicr) {
                        // SAFETY: no requirements.
                        unsafe {
                            abi::hv_vcpu_set_pending_interrupt(
                                self.vcpu.vcpu,
                                abi::HvInterruptType::IRQ,
                                true,
                            )
                        }
                        .chk()
                        .unwrap();
                        self.wfi = false;
                    }

                    if self.wfi {
                        // The guest is idle in WFI, parked *outside* hv_vcpu_run,
                        // where HVF cannot itself raise VTIMER_ACTIVATED. Arm the
                        // precise virtual-timer deadline (if the guest has the
                        // vtimer enabled+unmasked) alongside any synic-timer
                        // deadline set above, then wait on the earliest.
                        if let Some(deadline) = self.vtimer_deadline() {
                            self.vmtime.set_timeout_if_before(deadline);
                        }
                        if self.vmtime.poll_timeout(cx).is_ready() {
                            // A deadline (vtimer or synic) is due: clear the WFI
                            // wait and re-enter the guest. The vtimer is unmasked
                            // before hv_vcpu_run (below), so HVF delivers a
                            // *genuine* VTIMER_ACTIVATED iff it truly expired; the
                            // loop head re-scans SynIC/SPI/SGI sources first.
                            self.wfi = false;
                            continue;
                        }
                        // Idle with a future (or absent) deadline: park until a
                        // producer notifies us. poll_timeout above already
                        // registered our waker for the deadline; try_park stores
                        // the same waker for the producer path, and the fused ctl
                        // latch guarantees no wake is lost in between.
                        match self
                            .inner
                            .actor
                            .try_park(cx.waker(), || !self.partition.gicd.irq_pending(&self.gicr))
                        {
                            vp_actor::ParkDecision::Parked => {
                                if smp_trace_enabled() {
                                    tracelimit::info_ratelimited!(
                                        vp_index = vp_index.index(),
                                        diag = ?self.gicr.ppi_diag(),
                                        "hvf_smpdiag: parking: idle in WFI, no interrupt admitted"
                                    );
                                }
                                return Poll::Pending;
                            }
                            vp_actor::ParkDecision::Rescan => continue,
                        }
                    }

                    break Poll::Ready(Result::<_, VpHaltReason>::Ok(()));
                }
            })
            .await?;

            if !self
                .gicr
                .is_pending_or_active(self.partition.virt_timer_ppi)
            {
                // SAFETY: no requirements.
                unsafe {
                    abi::hv_vcpu_set_vtimer_mask(self.vcpu.vcpu, false)
                        .chk()
                        .unwrap();
                }
            }

            // SAFETY: we are not concurrently accessing `exit`.
            unsafe { abi::hv_vcpu_run(self.vcpu.vcpu) }
                .chk()
                .map_err(|err| dev.fatal_error(err.into()))?;

            // DIAGNOSTIC (guest-spin localization, default-off, gated on
            // OPENVMM_HVF_SMP_TRACE): a wedged guest vCPU that busy-spins in a
            // `cpu_relax`/YIELD loop — the boot CPU stuck in an SMP or spinlock
            // handshake, or a driver polling a memory-backed completion — never
            // stops exiting, because the periodic vtimer/preemption exit still
            // returns here. Host stack samples only ever show `hv_trap` for such
            // a vCPU (opaque guest execution); emitting the *recurring* guest PC
            // (with ELR + CPSR for the EL and DAIF interrupt-mask state)
            // pinpoints the stuck loop. Rate-limited so a hot-spinning CPU logs
            // roughly once per second, not once per exit.
            if smp_trace_enabled() {
                tracelimit::info_ratelimited!(
                    vp_index = vp_index.index(),
                    pc = format!("{:#x}", self.vcpu.pc()),
                    elr = format!(
                        "{:#x}",
                        self.vcpu.sys_reg(abi::HvSysReg::ELR_EL1).unwrap_or(0)
                    ),
                    cpsr = format!(
                        "{:#x}",
                        self.vcpu.reg(abi::HvReg::CPSR).unwrap_or(0)
                    ),
                    exit = self.vcpu.exit.reason.0,
                    "hvf_pcdiag: guest exit PC (spin localization)"
                );
            }

            // DIAGNOSTIC (CloudMOS bugcheck): record the guest's most-recent EL1
            // synchronous data abort (EC=0x25) at each exit into a small ring, so
            // the in-guest fault chain immediately preceding a bugcheck can be
            // dumped + page-table-walked at the GuestCrashCtl read. Those faults
            // are taken and resolved entirely at EL1 and never exit to HVF, so
            // this exit-time `ESR_EL1` snapshot is the only window onto them.
            if let (Ok(esr), Ok(far)) = (
                self.vcpu.sys_reg(abi::HvSysReg::ESR_EL1),
                self.vcpu.sys_reg(abi::HvSysReg::FAR_EL1),
            ) {
                if (esr >> 26) & 0x3f == 0x25 {
                    let mut ring = DIAG_FAULT_RING.lock();
                    if ring.back().map(|&(_, f, _, _)| f) != Some(far) {
                        let elr = self.vcpu.sys_reg(abi::HvSysReg::ELR_EL1).unwrap_or(0);
                        // Capture whether the faulting VA's leaf is mapped *now*,
                        // at fault time (vs. the later crash-time walk).
                        let fault_time_valid = if far >= 0xffff_0000_0000_0000 {
                            match (
                                self.vcpu.sys_reg(abi::HvSysReg::TTBR1_EL1),
                                self.vcpu.sys_reg(abi::HvSysReg::TCR_EL1),
                            ) {
                                (Ok(ttbr1), Ok(tcr)) => match diag_walk_leaf_valid(
                                    &self.partition.guest_memory,
                                    ttbr1,
                                    tcr,
                                    far,
                                ) {
                                    Some(true) => 1,
                                    Some(false) => 0,
                                    None => 2,
                                },
                                _ => 2,
                            }
                        } else {
                            2
                        };
                        ring.push_back((esr, far, elr, fault_time_valid));
                        while ring.len() > 16 {
                            ring.pop_front();
                        }
                    }
                }
            }

            match self.vcpu.exit.reason {
                abi::HvExitReason::CANCELED => {
                    continue;
                }
                abi::HvExitReason::EXCEPTION => {
                    let exception = self.vcpu.exit.exception;
                    tracing::trace!(
                        esr = u64::from(exception.syndrome),
                        va = exception.virtual_address,
                        pa = exception.physical_address,
                        "exception"
                    );
                    let advance = |vcpu: &mut HvfVcpu| {
                        let instr_len = if exception.syndrome.il() { 4 } else { 2 };
                        let pc = vcpu.pc();
                        vcpu.set_pc(pc.wrapping_add(instr_len));
                    };
                    match ExceptionClass(exception.syndrome.ec()) {
                        ExceptionClass::DATA_ABORT_LOWER => {
                            let iss = IssDataAbort::from(exception.syndrome.iss());
                            if !iss.isv() {
                                return Err(dev.fatal_error(
                                    anyhow::anyhow!("can't handle data abort without isv: {iss:?}")
                                        .into(),
                                ));
                            }
                            let len = 1 << iss.sas();
                            let sign_extend = iss.sse();

                            // Per "AArch64 System Register Descriptions/D23.2 General system control registers"
                            // the SRT field is defined as
                            //
                            // > The register number of the Wt/Xt/Rt operand of the faulting
                            // > instruction.
                            //
                            // In the A64 ISA TRM, Wt/Xt/Rt is used to designate the register number where the SP
                            // register is not used whereas the addition of `|SP` tells that the SP register might
                            // be used. Hence, the SRT field uses `0b11111` to encode `xzr`.
                            //
                            // Writing to `xzr` has no arch-observable effects, reading returns the all-zero's bit
                            // pattern.
                            let reg = iss.srt();

                            if iss.wnr() {
                                let data = if reg_is_xzr(reg) {
                                    0
                                } else {
                                    self.vcpu.gp(reg)
                                }
                                .to_ne_bytes();
                                if !self
                                    .partition
                                    .gicd
                                    .write(exception.physical_address, &data[..len])
                                {
                                    dev.write_mmio(
                                        vp_index,
                                        exception.physical_address,
                                        &data[..len],
                                    )
                                    .await;
                                }
                            } else if !reg_is_xzr(reg) {
                                let mut data = [0; 8];
                                if !self
                                    .partition
                                    .gicd
                                    .read(exception.physical_address, &mut data[..len])
                                {
                                    dev.read_mmio(
                                        vp_index,
                                        exception.physical_address,
                                        &mut data[..len],
                                    )
                                    .await;
                                }
                                let mut data = u64::from_ne_bytes(data);
                                if sign_extend {
                                    let shift = 64 - len * 8;
                                    data = ((data as i64) << shift >> shift) as u64;
                                    if !iss.sf() {
                                        data &= 0xffffffff;
                                    }
                                }
                                self.vcpu.set_gp(reg, data);
                            }
                            advance(&mut self.vcpu);
                        }
                        ExceptionClass::SYSTEM => {
                            let iss = IssSystem::from(exception.syndrome.iss());
                            let reg = iss.system_reg();
                            let now = self.vmtime.now().as_100ns();
                            if iss.direction() {
                                let value = if let Some(value) =
                                    self.partition.gicd.read_sysreg(&mut self.gicr, reg)
                                {
                                    value
                                } else if let Some(value) = read_counter_sysreg(reg) {
                                    value
                                } else if let Some(value) = self.pmu.read_sysreg(reg, now) {
                                    value
                                } else if reg == SystemReg::OSLSR_EL1 {
                                    // ARMv8 mandates the OS Lock; its reset value is
                                    // OSLM=0b10 (bits[3,0]) ⇒ 0x8, OSLK=0 (unlocked).
                                    // Previously this fell through and returned 0
                                    // (OSLM=0b00 = "OS Lock not implemented"), which
                                    // is architecturally invalid. Report the lock as
                                    // implemented-and-unlocked so the guest's debug
                                    // init sees a sane register.
                                    0x8
                                } else {
                                    tracing::warn!(
                                        ?reg,
                                        pc = self.vcpu.pc(),
                                        "returning zero for unknown system register"
                                    );
                                    0
                                };
                                // `mrs xzr, <sysreg>` discards the result: skip
                                // the write-back (see `reg_is_xzr`). The read
                                // above still runs for its side effects, e.g.
                                // ICC_IAR1_EL1 acknowledge.
                                if !reg_is_xzr(iss.rt()) {
                                    self.vcpu.set_gp(iss.rt(), value);
                                }
                            } else {
                                // `msr <sysreg>, xzr` writes zero, not the stack
                                // pointer that `gp(31)` would return (see
                                // `reg_is_xzr`); this was the source of the bogus
                                // `msr ICC_AP{0,1}R0_EL1, xzr` values seen at GIC
                                // init.
                                let value = if reg_is_xzr(iss.rt()) {
                                    0
                                } else {
                                    self.vcpu.gp(iss.rt())
                                };
                                let handled_by_gic = self.partition.gicd.write_sysreg(
                                    &mut self.gicr,
                                    reg,
                                    value,
                                    |index| self.partition.vps[index].notify(),
                                );
                                if !handled_by_gic && !self.pmu.write_sysreg(reg, value, now) {
                                    tracing::warn!(
                                        ?reg,
                                        value,
                                        pc = self.vcpu.pc(),
                                        "ignoring write to unknown system register"
                                    );
                                }
                            }
                            advance(&mut self.vcpu);
                        }
                        ec @ (ExceptionClass::HVC | ExceptionClass::SMC) => {
                            // HVC automatically advances pc.
                            let mut advance_pc = ec == ExceptionClass::SMC;
                            match exception.syndrome.iss() as u16 {
                                0 => {
                                    let x0 = self.vcpu.gp(0) as u32;
                                    let fc = FastCall::from(x0);
                                    let handled = 'handle: {
                                        if fc.fast() {
                                            match fc.service() {
                                                aarch64defs::smccc::Service::SMCCC => {
                                                    self.handle_smccc(fc);
                                                }
                                                aarch64defs::smccc::Service::PSCI => {
                                                    self.handle_psci(fc)?
                                                }
                                                aarch64defs::smccc::Service::VENDOR_HYP => {
                                                    self.handle_vendor_hyp(fc);
                                                }
                                                _ => break 'handle false,
                                            }
                                        } else {
                                            match x0 {
                                                HV_ARM64_HVC_SMCCC_IDENTIFIER
                                                    if ec == ExceptionClass::HVC =>
                                                {
                                                    self.hypercall(dev, true);
                                                    advance_pc = false;
                                                }
                                                _ => break 'handle false,
                                            }
                                        }
                                        true
                                    };
                                    if !handled {
                                        tracing::warn!(x0, ?ec, "ignoring SMCCC HVC/SMC");
                                        // Set not supported error.
                                        self.vcpu.set_gp(0, !0);
                                    }
                                }
                                1 => self.hypercall(dev, false),
                                immed => {
                                    tracing::warn!(immed, ?ec, "ignoring HVC/SMC");
                                    self.vcpu.set_gp(0, !0);
                                }
                            }
                            if advance_pc {
                                advance(&mut self.vcpu);
                            }
                        }
                        ExceptionClass::WFI => {
                            self.wfi = true;
                            advance(&mut self.vcpu);
                        }
                        class => {
                            return Err(dev.fatal_error(
                                anyhow::anyhow!(
                                    "unsupported exception class: {class:?} {iss:#x}",
                                    iss = exception.syndrome.iss()
                                )
                                .into(),
                            ));
                        }
                    }
                }
                abi::HvExitReason::VTIMER_ACTIVATED => {
                    self.gicr.raise(self.partition.virt_timer_ppi);
                }
                reason => {
                    return Err(dev.fatal_error(
                        anyhow::anyhow!("unsupported exit reason: {reason:?}").into(),
                    ));
                }
            }
        }
    }

    fn flush_async_requests(&mut self) {}

    fn access_state(&mut self, vtl: Vtl) -> Self::StateAccess<'_> {
        assert_eq!(vtl, Vtl::Vtl0);
        vp_state::HvfVpStateAccess { processor: self }
    }
}
