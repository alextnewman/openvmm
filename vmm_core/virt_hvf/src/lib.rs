// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![expect(missing_docs)]
#![cfg(all(target_os = "macos", guest_is_native, guest_arch = "aarch64"))]

//! A hypervisor backend using macos's Hypervisor framework.

// UNSAFETY: Calling Hypervisor framework APIs and manually managing memory.
#![expect(unsafe_code)]

mod abi;
mod hypercall;
mod vp_state;

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
use std::task::Waker;
use std::task::ready;
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
                    vcpu: (!0).into(),
                    message_queues: hv1_emulator::message_queues::MessageQueues::new(),
                    waker: Default::default(),
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
                vp.kick();
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
                vp.kick();
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
                            if partition.gicd.raise_ppi(vp, vector) {
                                tracing::debug!(vector, "ppi from event");
                                partition.vps[vp.index() as usize].kick();
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
    #[inspect(skip)]
    vcpu: AtomicU64,
    message_queues: hv1_emulator::message_queues::MessageQueues,
    #[inspect(skip)]
    waker: RwLock<Option<Waker>>,
    cpu_on: Mutex<Option<CpuOnState>>,
}

#[derive(Debug, Inspect)]
struct CpuOnState {
    pc: u64,
    x0: u64,
}

impl HvfVpInner {
    fn cancel_run(&self) {
        let vcpu: u64 = self.vcpu.load(Ordering::SeqCst);
        if vcpu != !0 {
            // SAFETY: `&vcpu` points to a list of vcpu IDs of length 1.
            unsafe { abi::hv_vcpus_exit(&vcpu, 1) }.chk().unwrap();
        }
    }

    fn wake(&self) {
        if let Some(waker) = &*self.waker.read() {
            waker.wake_by_ref();
        }
    }

    /// Forces the target vCPU to observe a cross-VP event (interrupt, IPI,
    /// synic message): re-arm its async waker in case it is parked, *and* force
    /// it out of `hv_vcpu_run` via `cancel_run` in case it is executing guest
    /// code. Using only `wake()` loses the wakeup whenever the target is
    /// actively running, which deadlocks SMP interrupt/IPI delivery under
    /// contention.
    fn kick(&self) {
        self.wake();
        self.cancel_run();
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

/// `ID_AA64DFR0_EL1.PMUVer` field (bits [11:8]); cleared to hide the PMU from the
/// guest (see the PMU rationale in `bind`).
const ID_AA64DFR0_EL1_PMUVER: u64 = 0xf << 8;

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

        // Initialize configuration registers.
        // Set 40 bit physical address width.
        vcpu.set_sys_reg(abi::HvSysReg::ID_AA64MMFR0_EL1, 2)?;
        // Enable GICv3 system registers.
        vcpu.set_sys_reg(abi::HvSysReg::ID_AA64PFR0_EL1, ID_AA64PFR0_EL1_GIC_CPUIF)?;
        // Hide the PMU from the guest. Windows-on-ARM64 reads
        // ID_AA64DFR0_EL1.PMUVer and, when it is non-zero, drives PMU system
        // registers (PMCR_EL0, PMCCNTR_EL0, ...) that this backend does not
        // model, which wedges early boot. Clear only PMUVer[11:8] via
        // read-modify-write so DebugVer and the other mandatory debug ID fields
        // are preserved.
        let dfr0 = vcpu.sys_reg(abi::HvSysReg::ID_AA64DFR0_EL1)?;
        vcpu.set_sys_reg(abi::HvSysReg::ID_AA64DFR0_EL1, dfr0 & !ID_AA64DFR0_EL1_PMUVER)?;
        // Set the MPIDR.
        vcpu.set_sys_reg(abi::HvSysReg::MPIDR_EL1, inner.vp_info.mpidr.into())?;

        // Store the vcpu index in the partition.
        inner.vcpu.store(vcpu.vcpu, Ordering::Relaxed);

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
            e0_last_wfi_pc: !0,
            e0_wfi_count: 0,
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

/// Reads the guest virtual-timer state (CNTV_CTL_EL0, CNTV_CVAL_EL0), the
/// current virtual count, and the HVF vtimer mask, for diagnosing why a WFI is
/// not woken. Returns a compact human-readable summary. Logging-only.
fn vtimer_diag(vcpu: u64) -> String {
    let mut ctl = 0u64;
    let mut cval = 0u64;
    let mut masked = false;
    // SAFETY: simple register reads with out-params; no aliasing requirements.
    unsafe {
        let _ = abi::hv_vcpu_get_sys_reg(vcpu, abi::HvSysReg::CNTV_CTL_EL0, &mut ctl);
        let _ = abi::hv_vcpu_get_sys_reg(vcpu, abi::HvSysReg::CNTV_CVAL_EL0, &mut cval);
        let _ = abi::hv_vcpu_get_vtimer_mask(vcpu, &mut masked);
    }
    let now: u64;
    // SAFETY: CNTVCT_EL0 is unprivileged-readable with no side effects.
    unsafe {
        core::arch::asm!("mrs {}, cntvct_el0", out(reg) now, options(nomem, nostack, preserves_flags));
    }
    let enable = ctl & 1 != 0;
    let imask = ctl & 2 != 0;
    let istatus = ctl & 4 != 0;
    let delta = cval.wrapping_sub(now) as i64;
    format!(
        "vtimer{{ ctl={ctl:#x} en={enable} imask={imask} istatus={istatus} \
         cval={cval:#x} cntvct={now:#x} cval-now={delta} hvf_masked={masked} }}"
    )
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
    /// E0 evidence-gate diagnostic state: last WFI guest-PC + a running WFI
    /// count, used to dedup WFI-stall logging (collapse a spin to one line +
    /// periodic heartbeat). Throwaway instrumentation — revert/fold before O5.
    #[inspect(skip)]
    e0_last_wfi_pc: u64,
    #[inspect(skip)]
    e0_wfi_count: u64,
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
        // — our keeping the TLB enlightenment *disabled*: `hypercall.rs` returns 0
        // for `PartitionInfoPage` (0x90015 → Enabled=0/TlbInUse=0) and
        // `TlbiControl` (0x90016 → TlbiEnlightened=0), so a well-behaved guest
        // relies on the architectural broadcast regardless of this call.
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
                tracelimit::info_ratelimited!(
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
                tracelimit::info_ratelimited!(
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
                        vp.wake();
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
        let mut last_waker = None;

        loop {
            self.inner.needs_yield.maybe_yield().await;

            poll_fn(|cx| {
                loop {
                    stop.check()?;

                    if !last_waker
                        .as_ref()
                        .is_some_and(|waker| cx.waker().will_wake(waker))
                    {
                        last_waker = Some(cx.waker().clone());
                        self.inner.waker.write().clone_from(&last_waker);
                    }

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
                        break Poll::Pending;
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
                        self.vmtime.set_timeout_if_before(
                            self.vmtime.now().wrapping_add(Duration::from_millis(2)),
                        );
                        ready!(self.vmtime.poll_timeout(cx));
                        // The 2ms vtimer backstop fired. HVF cannot raise
                        // VTIMER_ACTIVATED while the vCPU is parked in WFI (it
                        // only delivers as an exit *from* hv_vcpu_run), so the
                        // VMM must periodically wake the guest. Rather than
                        // blind-injecting the timer PPI here — a spurious
                        // interrupt that a real guest OS (e.g. Windows) rejects
                        // because CNTV_CTL.ISTATUS is still 0, wedging boot — we
                        // clear the WFI wait and re-enter the guest. The WFI PC
                        // was already advanced, so the guest resumes its idle
                        // loop; before re-running we unmask the vtimer (below),
                        // letting HVF deliver a *genuine* VTIMER_ACTIVATED iff
                        // the virtual timer has actually expired. The loop head
                        // re-scans SynIC/SPI/SGI wake sources before we break.
                        self.wfi = false;
                        continue;
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
                                let data = match reg {
                                    0..=30 => self.vcpu.gp(reg),
                                    31 => 0,
                                    _ => unreachable!(),
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
                            } else if reg != 31 {
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
                                // E0 evidence gate: trace generic-timer *control*
                                // reads (CRn==14, CRm!=0 excludes the high-frequency
                                // CNTxCT/CNTFRQ counters) to see what timer state
                                // Windows queries while wedged.
                                if reg.0.crn() == 14 && reg.0.crm() != 0 {
                                    tracing::info!(
                                        target: "e0_timer",
                                        ?reg,
                                        value,
                                        pc = self.vcpu.pc(),
                                        "E0 timer-sysreg READ"
                                    );
                                }
                                self.vcpu.set_gp(iss.rt(), value);
                            } else {
                                let value = self.vcpu.gp(iss.rt());
                                // E0 evidence gate: trace generic-timer *control*
                                // writes (CRn==14, CRm!=0 → CNTP_*/CNTV_*/CNTKCTL, not
                                // the counters). A guest that arms CNTP_CVAL/CTL here
                                // and then WFIs is the smoking gun for CNTP starvation
                                // (→ O5 is the Windows-unblock).
                                if reg.0.crn() == 14 && reg.0.crm() != 0 {
                                    tracing::info!(
                                        target: "e0_timer",
                                        ?reg,
                                        value,
                                        pc = self.vcpu.pc(),
                                        "E0 timer-sysreg WRITE"
                                    );
                                }
                                let handled_by_gic = self.partition.gicd.write_sysreg(
                                    &mut self.gicr,
                                    reg,
                                    value,
                                    |index| self.partition.vps[index].kick(),
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
                            // E0 evidence gate: trace the WFI stall location, deduped
                            // by guest PC (collapse a WFI spin to one line + a periodic
                            // heartbeat) so we can tell whether Windows is parked
                            // waiting on a timer interrupt that never arrives. Dump the
                            // GIC SGI/PPI + CPU-interface state alongside so we can see
                            // exactly which interrupt the guest enabled and is awaiting
                            // (e.g. INTID 27 = architectural CNTV vs our 20).
                            let pc = self.vcpu.pc();
                            self.e0_wfi_count = self.e0_wfi_count.wrapping_add(1);
                            if pc != self.e0_last_wfi_pc {
                                tracing::info!(
                                    target: "e0_wfi",
                                    pc,
                                    count = self.e0_wfi_count,
                                    vtimer = %vtimer_diag(self.vcpu.vcpu),
                                    diag = ?self.gicr.ppi_diag(),
                                    "E0 WFI (pc changed)"
                                );
                                self.e0_last_wfi_pc = pc;
                            } else if self.e0_wfi_count % 512 == 0 {
                                tracing::info!(
                                    target: "e0_wfi",
                                    pc,
                                    count = self.e0_wfi_count,
                                    vtimer = %vtimer_diag(self.vcpu.vcpu),
                                    diag = ?self.gicr.ppi_diag(),
                                    "E0 WFI (spin heartbeat)"
                                );
                            }
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
