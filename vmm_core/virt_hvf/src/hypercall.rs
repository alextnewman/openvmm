// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hypercall exit handling.

use crate::HvfProcessor;
use hv1_hypercall::Arm64RegisterState;
use hv1_hypercall::GetVpRegisters;
use hv1_hypercall::HvRepResult;
use hv1_hypercall::PostMessage;
use hv1_hypercall::SetVpRegisters;
use hv1_hypercall::SignalEvent;
use hvdef::HvArm64RegisterName;
use hvdef::HvError;
use hvdef::HvPartitionPrivilege;
use hvdef::Vtl;
use hvdef::hypercall::HvRegisterAssoc;
use std::sync::atomic::Ordering;

/// The partition privileges this backend actually provides, advertised through
/// the low 64 bits of `PrivilegesAndFeaturesInfo` (the AArch64 analogue of the
/// x64 `HV_FEATURES` CPUID leaf 0x40000003).
///
/// This is deliberately a strict *subset* of `hv1_emulator`'s
/// `SUPPORTED_PRIVILEGES`: we advertise only what `virt_hvf` genuinely backs, so
/// the self-description stays coherent with observable behavior. In particular
/// `access_partition_reference_tsc` is **false** — we return 0 for the
/// `ReferenceTsc` register and do not implement the reference TSC page. We
/// present the Hyper-V guest ABI (synic, interrupt control, hypercalls,
/// synthetic timers, reference counter, vp index); we are not the Hyper-V
/// hypervisor, so VSM, debugging, partition management, and hardware-assist
/// privileges all remain false.
///
/// `access_apic_msrs` (bit 4) is REQUIRED even though there are no APIC MSRs on
/// ARM64: that bit position is the architecture-neutral "interrupt control
/// registers" privilege, spelled `AccessIntrCtrlRegs` in the ARM64
/// `HV_PARTITION_PRIVILEGE_MASK`. `winhv.sys`'s `WinHvpCheckPartitionPrivileges`
/// gates its entire hypervisor connection on this bit (together with the synic,
/// synthetic-timer, reference-counter, hypercall, and vp-index bits); if it is
/// clear, winhv leaves `WinHvpConnected = FALSE`, never runs
/// `WinHvpInitializeSynicSupport`, and every later `WinHvGetSintEventFlags`
/// returns NULL — which is exactly what makes `vmbus.sys` bugcheck 0x7E on a
/// NULL event-flags page during its root `PrepareHardware`. We back the
/// synthetic interrupt controller (SCONTROL/EOM/SINTx and GIC-routed delivery),
/// so advertising it is honest.
///
/// The privilege mask (`_HV_PARTITION_PRIVILEGE_MASK`) is architecture-neutral —
/// the same 64-bit union on x64 and ARM64 — so reusing `HvPartitionPrivilege`
/// here is correct. The *feature* dword that follows it is NOT (see
/// `arm64_privileges_and_features` below).
const PROVIDED_PRIVILEGES: HvPartitionPrivilege = HvPartitionPrivilege::new()
    .with_access_partition_reference_counter(true)
    .with_access_hypercall_msrs(true)
    .with_access_vp_index(true)
    .with_access_synic_msrs(true)
    .with_access_synthetic_timer_msrs(true)
    .with_access_apic_msrs(true);

/// Builds the 128-bit `PrivilegesAndFeaturesInfo` value using the **ARM64**
/// feature-dword packing from the private `_HV_ARM64_HYPERVISOR_FEATURES`
/// header struct.
///
/// This is the subtle part. `hvdef::HvFeatures` models the *x64* CPUID
/// 0x40000003 layout, where a 32-bit "power management" dword (`MaxSupportedC
/// State`, …) sits between the 64-bit privilege mask and the 32-bit
/// available-features dword. On ARM64 that power dword does **not exist** — the
/// features dword begins immediately at bit 64:
///
/// ```text
///   bit 64  GuestDebuggingAvailable
///   bit 65  PerformanceMonitorsAvailable
///   bit 66  CpuDynamicPartitioningAvailable
///   bit 67  GuestIdleAvailable
///   bit 68  HypervisorSleepStateSupportAvailable
///   bit 69  NumaDistanceQueryAvailable
///   bit 70  FrequencyRegsAvailable
///   bit 71  SyntheticMachineCheckAvailable
///   bit 72  GuestCrashRegsAvailable   <- the bit we need
/// ```
///
/// So `GuestCrashRegsAvailable` lives at absolute **bit 72** on ARM64, whereas
/// `HvFeatures::with_guest_crash_regs_available` (x64 layout) sets **bit 106**.
/// Emitting the x64 value leaves an ARM64 Windows guest reading bit 72 as 0,
/// which silently disables the guest-crash enlightenment: the kernel paints the
/// BSOD but never writes `GuestCrashP0..P4`/`GuestCrashCtl`, so the bugcheck
/// code and parameters never reach the host log. Building the ARM64 layout makes
/// the crash enlightenment actually fire.
///
/// We advertise `GuestCrashRegsAvailable` and nothing else in this dword — it is
/// the only feature in the band that `virt_hvf` truly backs (in
/// `set_vp_registers`).
fn arm64_privileges_and_features() -> u128 {
    /// `GuestCrashRegsAvailable` is bit 8 of the ARM64 feature dword, which
    /// itself starts at bit 64 of the 128-bit register.
    const ARM64_GUEST_CRASH_REGS_AVAILABLE_BIT: u32 = 64 + 8;
    (PROVIDED_PRIVILEGES.into_bits() as u128) | (1u128 << ARM64_GUEST_CRASH_REGS_AVAILABLE_BIT)
}

pub(crate) struct HvfHypercallHandler<'a, 'b> {
    vp: &'a mut HvfProcessor<'b>,
}

impl<'a, 'b> HvfHypercallHandler<'a, 'b> {
    pub const DISPATCHER: hv1_hypercall::Dispatcher<Self> = hv1_hypercall::dispatcher!(
        Self,
        [
            hv1_hypercall::HvGetVpRegisters,
            hv1_hypercall::HvSetVpRegisters,
            hv1_hypercall::HvPostMessage,
            hv1_hypercall::HvSignalEvent,
            hv1_hypercall::HvExtQueryCapabilities,
        ]
    );

    pub fn new(vp: &'a mut HvfProcessor<'b>) -> Self {
        Self { vp }
    }
}

impl Arm64RegisterState for HvfHypercallHandler<'_, '_> {
    fn pc(&mut self) -> u64 {
        self.vp.vcpu.pc()
    }

    fn set_pc(&mut self, pc: u64) {
        tracing::trace!(pc, "set pc");
        self.vp.vcpu.set_pc(pc)
    }

    fn x(&mut self, n: u8) -> u64 {
        self.vp.vcpu.gp(n)
    }

    fn set_x(&mut self, n: u8, v: u64) {
        tracing::trace!(n, v, "set x");
        self.vp.vcpu.set_gp(n, v)
    }
}

impl GetVpRegisters for HvfHypercallHandler<'_, '_> {
    fn get_vp_registers(
        &mut self,
        partition_id: u64,
        vp_index: u32,
        _vtl: Option<Vtl>,
        registers: &[hvdef::HvRegisterName],
        output: &mut [hvdef::HvRegisterValue],
    ) -> HvRepResult {
        if partition_id != hvdef::HV_PARTITION_ID_SELF || vp_index != hvdef::HV_VP_INDEX_SELF {
            return Err((HvError::InvalidParameter, 0));
        }

        for (&name, output) in registers.iter().zip(output) {
            *output = match name.into() {
                HvArm64RegisterName::TimeRefCount => {
                    self.vp.partition.vmtime.now().as_100ns().into()
                }
                HvArm64RegisterName::VpIndex => 0u32.into(),
                HvArm64RegisterName::GuestOsId => self
                    .vp
                    .partition
                    .hv1
                    .guest_os_id
                    .load(Ordering::Relaxed)
                    .into(),
                HvArm64RegisterName::Sipp => self.vp.hv1.simp().into(),
                HvArm64RegisterName::Sifp => self.vp.hv1.siefp().into(),
                HvArm64RegisterName::Scontrol => self.vp.hv1.scontrol().into(),
                // Synthetic-interrupt-controller *version* register. This MUST
                // be handled explicitly: `winhv.sys` gates its entire per-VP
                // synic bring-up (`WinHvpInitializeSynicSupport`) on reading
                // exactly `HV_SYNIC_VERSION_1` (== 1) here — any other value is
                // taken to mean "this isn't the hypervisor's SynIC" and it
                // silently skips SIMP/SIEFP/SCONTROL setup for every processor.
                // Falling through to the generic "unsupported register" arm
                // returns 0, which makes winhv leave `Siefp.EventFlagsPage` NULL;
                // `vmbus.sys` then dereferences the NULL from
                // `WinHvGetSintEventFlags(VMBUS_MESSAGE_SINT)` during its root
                // PrepareHardware and bugchecks 0x7E. The emulator reports the
                // correct version (1); surface it. (WHP passes this through to
                // the real hypervisor, which likewise returns 1.)
                HvArm64RegisterName::Sversion => self.vp.hv1.sversion().into(),
                r if (HvArm64RegisterName::Sint0..=HvArm64RegisterName::Sint15).contains(&r) => {
                    self.vp
                        .hv1
                        .sint((r.0 - HvArm64RegisterName::Sint0.0) as u8)
                        .into()
                }

                HvArm64RegisterName::HypervisorVersion => 0u128.into(),
                // The partition privilege/feature self-description. Advertise the
                // exact subset we back so the guest's view of our enlightenments
                // matches what it actually observes. NOTE: this MUST use the
                // ARM64 feature-dword packing (see `arm64_privileges_and_features`)
                // — the x64 `HvFeatures` layout would place
                // `GuestCrashRegsAvailable` at the wrong bit and silently disable
                // the guest-crash enlightenment.
                HvArm64RegisterName::PrivilegesAndFeaturesInfo => {
                    arm64_privileges_and_features().into()
                }
                // Enlightenment *recommendations* (HvEnlightenmentInformation) and
                // hardware-assist features. We recommend no specific enlightenment
                // optimizations and expose no hardware virtualization assists, so
                // zero is the coherent, honest answer for both.
                HvArm64RegisterName::FeaturesInfo => 0u128.into(),
                HvArm64RegisterName::HardwareFeaturesInfo => 0u128.into(),

                // Isolation self-description (the AArch64 analogue of the x64
                // CPUID leaf 0x4000000B). HVF is a non-isolating development
                // hypervisor, so report `HvPartitionIsolationType::NONE` with no
                // paravisor and no shared-GPA boundary: every guest page is
                // plainly host-accessible. This is what keeps `vmbus.sys` on the
                // non-isolated channel-setup path. (Zero already decodes to
                // NONE; we spell it out so the intent is explicit and the
                // generic "unsupported register" warning never fires for it.)
                HvArm64RegisterName::IsolationConfiguration => {
                    hvdef::HvIsolationConfiguration::new()
                        .with_isolation_type(hvdef::HvPartitionIsolationType::NONE.0)
                        .into_bits()
                        .into()
                }

                // Implementation limits (the AArch64 analogue of the x64
                // HV_IMPLEMENTATION_LIMITS CPUID leaf 0x40000005). Mirror the x64
                // emulator: eax = max virtual processors, ebx = max logical
                // processors (both the partition VP count), ecx/edx = 0. The
                // little-endian register packing is eax | ebx<<32 | ecx<<64 |
                // edx<<96. Returning 0 here (max VP count = 0) is nonsensical and
                // can break the guest's early per-VP allocation sizing.
                HvArm64RegisterName::ImplementationLimitsInfo => {
                    let max_vps = self.vp.partition.vps.len() as u128;
                    (max_vps | (max_vps << 32)).into()
                }

                // Synthetic timers (STIMERn_CONFIG/COUNT). Config sits at the
                // even offset, Count at the odd offset, two registers per timer.
                r if (HvArm64RegisterName::Stimer0Config..=HvArm64RegisterName::Stimer3Count)
                    .contains(&r) =>
                {
                    let offset = (r.0 - HvArm64RegisterName::Stimer0Config.0) as usize;
                    let timer = offset / 2;
                    if offset.is_multiple_of(2) {
                        self.vp.hv1.stimer_config(timer).into()
                    } else {
                        self.vp.hv1.stimer_count(timer).into()
                    }
                }

                // Guest-crash enlightenment registers, read side. These are
                // sticky readbacks of what the guest last wrote (P0..P4 in
                // `crash_params`). Windows' crash path reads `GuestCrashCtl` at
                // the moment of a bugcheck; surface whatever bugcheck code +
                // parameters have been staged so an opaque guest crash becomes an
                // actionable stop code even if the guest never commits the
                // control write (CrashNotify). Returning a clean readback (rather
                // than the generic "unsupported register" 0) also keeps the
                // guest's crash handshake on the happy path.
                r if (HvArm64RegisterName::GuestCrashP0..=HvArm64RegisterName::GuestCrashP4)
                    .contains(&r) =>
                {
                    let idx = (r.0 - HvArm64RegisterName::GuestCrashP0.0) as usize;
                    self.vp.crash_params[idx].into()
                }
                HvArm64RegisterName::GuestCrashCtl => {
                    let [p0, p1, p2, p3, p4] = self.vp.crash_params;
                    if [p0, p1, p2, p3, p4].iter().any(|&p| p != 0) {
                        tracing::error!(
                            "guest read GuestCrashCtl at crash time with staged params: \
                             code={p0:#x} p1={p1:#x} p2={p2:#x} p3={p3:#x} p4={p4:#x}"
                        );
                    } else {
                        tracing::info!("guest read GuestCrashCtl (no crash parameters staged)");
                    }
                    // At crash time FAR_EL1/TTBR1_EL1 still hold the last EL1
                    // synchronous-exception VA and the live high-half page-table
                    // base (the bugcheck path and this HVC do not touch EL1's
                    // FAR/TTBR), so log the fault context and walk the guest's own
                    // stage-1 tables for that VA: a VALID leaf => the page is
                    // mapped and a HW fault on it is spurious (hypervisor-side
                    // walker-coherency bug); an INVALID leaf => genuinely unmapped
                    // (the guest faulted because of bad input or a nested
                    // page-table-builder fault it could not resolve).
                    let esr = self.vp.vcpu.sys_reg(crate::abi::HvSysReg::ESR_EL1);
                    let elr = self.vp.vcpu.sys_reg(crate::abi::HvSysReg::ELR_EL1);
                    let spsr = self.vp.vcpu.sys_reg(crate::abi::HvSysReg::SPSR_EL1);
                    let far = self.vp.vcpu.sys_reg(crate::abi::HvSysReg::FAR_EL1);
                    let ttbr1 = self.vp.vcpu.sys_reg(crate::abi::HvSysReg::TTBR1_EL1);
                    let tcr = self.vp.vcpu.sys_reg(crate::abi::HvSysReg::TCR_EL1);
                    if let (Ok(esr), Ok(elr), Ok(spsr), Ok(far)) = (esr, elr, spsr, far) {
                        let ec = (esr >> 26) & 0x3f;
                        let dfsc = esr & 0x3f;
                        let wnr = (esr >> 6) & 1;
                        tracing::error!(
                            esr = format!("{esr:#x}"),
                            ec = format!("{ec:#x}"),
                            dfsc = format!("{dfsc:#x}"),
                            wnr,
                            far = format!("{far:#x}"),
                            elr = format!("{elr:#x}"),
                            spsr = format!("{spsr:#x}"),
                            "EL1 fault context at GuestCrashCtl read"
                        );
                    }
                    if let (Ok(far), Ok(ttbr1), Ok(tcr)) = (far, ttbr1, tcr) {
                        // Walk the current (last) faulting VA, then dump the full
                        // recorded chain of recent in-guest EL1 faults so we can
                        // see the original trigger, not just the crash-time fault.
                        crate::diag_walk_ttbr1(
                            &self.vp.partition.guest_memory,
                            ttbr1,
                            tcr,
                            far,
                        );
                        crate::diag_dump_fault_ring(
                            &self.vp.partition.guest_memory,
                            ttbr1,
                            tcr,
                        );
                    }
                    // Reads of GuestCrashCtl must report our *supported
                    // capabilities*, NOT a cleared/zero value. Windows' NT
                    // bugcheck path reads this register to discover whether the
                    // host honors the crash enlightenment before it stages
                    // P0..P4 and commits the CrashNotify write. A zero readback
                    // makes it conclude the mechanism is unavailable and silently
                    // skip the parameter writes entirely — observed as "no crash
                    // parameters staged" -> BSOD painted -> reset, with P0..P4
                    // never written, so the stop code + faulting address are
                    // lost. Mirror the production mshv backend's `read_crash_msr`
                    // exactly (advertise every capability bit).
                    let caps = hvdef::GuestCrashCtl::new()
                        .with_crash_notify(true)
                        .with_crash_message(true)
                        .with_no_crash_dump(true)
                        .with_pre_os_id(0b111);
                    u64::from(caps).into()
                }

                register => {
                    tracelimit::warn_ratelimited!(
                        ?register,
                        "unsupported register get; returning 0 to avoid failing the batch"
                    );
                    0u128.into()
                }
            }
        }
        Ok(())
    }
}

impl hv1_hypercall::ExtendedQueryCapabilities for HvfHypercallHandler<'_, '_> {
    fn query_extended_capabilities(&mut self) -> hvdef::HvResult<u64> {
        // No extended hypercalls are supported; report an empty capability
        // bitmap so the guest cleanly skips the extended-hypercall path
        // instead of receiving HvInvalidHypercallCode.
        Ok(0)
    }
}

/// `HvArm64RegisterPartitionInfoPage` (0x00090015, marked "Legacy" in the
/// private hvgdk header). The guest writes `{ Enabled:1, _:11, GpaPage:52 }`
/// here to register the GPA of an `HV_PARTITION_INFO_PAGE`; the *hypervisor*
/// then publishes `TlbInUse` into that page.
const HV_ARM64_REGISTER_PARTITION_INFO_PAGE: u32 = 0x0009_0015;

/// `HvArm64RegisterTlbiControl` (0x00090016, "Legacy"): `{ TlbiEnlightened:1 }`.
const HV_ARM64_REGISTER_TLBI_CONTROL: u32 = 0x0009_0016;

impl SetVpRegisters for HvfHypercallHandler<'_, '_> {
    fn set_vp_registers(
        &mut self,
        partition_id: u64,
        vp_index: u32,
        _vtl: Option<Vtl>,
        registers: &[HvRegisterAssoc],
    ) -> HvRepResult {
        if partition_id != hvdef::HV_PARTITION_ID_SELF || vp_index != hvdef::HV_VP_INDEX_SELF {
            return Err((HvError::InvalidParameter, 0));
        }

        for &HvRegisterAssoc { name, value, .. } in registers.iter() {
            match name.into() {
                HvArm64RegisterName::GuestOsId => self
                    .vp
                    .partition
                    .hv1
                    .guest_os_id
                    .store(value.as_u64(), Ordering::Relaxed),
                HvArm64RegisterName::Sipp => self
                    .vp
                    .hv1
                    .set_simp(
                        value.as_u64(),
                        &mut HvfNoVtlProtections(&self.vp.partition.guest_memory),
                    )
                    .map_err(|_| (HvError::InvalidParameter, 1))?,
                HvArm64RegisterName::Sifp => self
                    .vp
                    .hv1
                    .set_siefp(
                        value.as_u64(),
                        &mut HvfNoVtlProtections(&self.vp.partition.guest_memory),
                    )
                    .map_err(|_| (HvError::InvalidParameter, 1))?,
                HvArm64RegisterName::Scontrol => self.vp.hv1.set_scontrol(value.as_u64()),
                HvArm64RegisterName::Eom => {}
                r if (HvArm64RegisterName::Sint0..=HvArm64RegisterName::Sint15).contains(&r) => {
                    let sint_index = (r.0 - HvArm64RegisterName::Sint0.0) as usize;
                    self.vp.hv1.set_sint(sint_index, value.as_u64())
                }
                // Synthetic timers (STIMERn_CONFIG/COUNT). The synic emulator
                // arms them; the run loop's `scan()` evaluates and delivers
                // expiries to the configured SINT.
                r if (HvArm64RegisterName::Stimer0Config..=HvArm64RegisterName::Stimer3Count)
                    .contains(&r) =>
                {
                    let offset = (r.0 - HvArm64RegisterName::Stimer0Config.0) as usize;
                    let timer = offset / 2;
                    if offset.is_multiple_of(2) {
                        self.vp.hv1.set_stimer_config(timer, value.as_u64());
                    } else {
                        self.vp.hv1.set_stimer_count(timer, value.as_u64());
                    }
                }
                // Hyper-V guest-crash enlightenment. Windows latches the
                // bugcheck code (`P0`) and its four parameters (`P1..P4`) into
                // these sticky registers, then writes `GuestCrashCtl` with
                // `crash_notify` set to signal the host. Surfacing them turns an
                // opaque guest BSOD into an actionable stop code + parameters.
                r if (HvArm64RegisterName::GuestCrashP0..=HvArm64RegisterName::GuestCrashP4)
                    .contains(&r) =>
                {
                    let idx = (r.0 - HvArm64RegisterName::GuestCrashP0.0) as usize;
                    self.vp.crash_params[idx] = value.as_u64();
                    // Surface each staged parameter. The guest may write P0..P4
                    // (P0 = bugcheck code) and reset WITHOUT ever committing the
                    // GuestCrashCtl write; logging here ensures we still capture
                    // the stop code in that case.
                    tracing::info!(
                        param = idx,
                        value = value.as_u64(),
                        "guest staged crash parameter (P{idx})"
                    );
                }
                HvArm64RegisterName::GuestCrashCtl => {
                    let ctl = hvdef::GuestCrashCtl::from(value.as_u64());
                    let [p0, p1, p2, p3, p4] = self.vp.crash_params;
                    tracing::error!(
                        vp_index,
                        crash_message = ctl.crash_message(),
                        no_crash_dump = ctl.no_crash_dump(),
                        "guest reported a bugcheck: \
                         code={p0:#x} p1={p1:#x} p2={p2:#x} p3={p3:#x} p4={p4:#x}"
                    );
                    // For an exception-class stop (P0=0x7E) P2/P3/P4 point at the
                    // faulting PC + on-stack EXCEPTION_RECORD/CONTEXT; decode them
                    // from guest memory to surface the faulting instruction, the
                    // access type + faulting VA, and the full register file (which
                    // names the register that held the bad pointer). The high-half
                    // kernel VAs translate through the live TTBR1.
                    if let (Ok(ttbr1), Ok(tcr)) = (
                        self.vp.vcpu.sys_reg(crate::abi::HvSysReg::TTBR1_EL1),
                        self.vp.vcpu.sys_reg(crate::abi::HvSysReg::TCR_EL1),
                    ) {
                        crate::diag_decode_bugcheck(
                            &self.vp.partition.guest_memory,
                            ttbr1,
                            tcr,
                            p0,
                            p2,
                            p3,
                            p4,
                        );
                        // For non-0x7E stops (e.g. 0x5C, where P3/P4 are not an
                        // EXCEPTION_RECORD/CONTEXT pair) the decoder returns early,
                        // so seed a live frame-pointer backtrace from the current
                        // guest registers to name the routine that called
                        // KeBugCheckEx, and resolve P3's module.
                        if p0 != 0x7e && p0 != 0x1000_007e {
                            if let (Ok(pc), Ok(fp), Ok(lr)) = (
                                self.vp.vcpu.reg(crate::abi::HvReg::PC),
                                self.vp.vcpu.reg(crate::abi::HvReg::FP),
                                self.vp.vcpu.reg(crate::abi::HvReg::LR),
                            ) {
                                crate::diag_backtrace_live(
                                    &self.vp.partition.guest_memory,
                                    ttbr1,
                                    tcr,
                                    pc,
                                    fp,
                                    lr,
                                    p3,
                                );
                            }
                        }
                    }
                    // When `crash_message` is set, P3 is the GPA of a textual
                    // crash message and P4 its length; surface it too.
                    if ctl.crash_message() && p4 > 0 && p4 <= 4096 {
                        let mut buf = vec![0u8; p4 as usize];
                        if self.vp.partition.guest_memory.read_at(p3, &mut buf).is_ok() {
                            let text = String::from_utf8_lossy(&buf);
                            tracing::error!(
                                text = text.trim_end_matches(['\0', '\n', '\r']),
                                "guest crash message"
                            );
                        }
                    }
                }
                // TLBI-enlightenment handshake (ARM64). The guest registers a
                // partition-info page and opts into the enlightenment; we keep it
                // effectively disabled by publishing `TlbInUse = 0`, so the guest
                // falls back on its own architectural `TLBI ..., IS` broadcast,
                // which HVF honors natively. (Apple's ARM64 hypervisor exposes no
                // guest-TLB-invalidation primitive, so we could not service a real
                // enlightened shootdown even if we wanted to — the architectural
                // path is the only correct one here.)
                r if r.0 == HV_ARM64_REGISTER_PARTITION_INFO_PAGE => {
                    // HV_REGISTER_PARTITION_INFO_PAGE { Enabled:1, _:11, GpaPage:52 }.
                    let reg = value.as_u64();
                    if reg & 1 != 0 {
                        let gpa = reg & 0xffff_ffff_ffff_f000;
                        // Publish HV_PARTITION_INFO_PAGE.TlbInUse = 0. A *non-zero*
                        // TlbInUse is precisely what tells the guest it must ALSO
                        // issue the supplemental HvCallFlushTlb hypercall to flush
                        // the hypervisor-saved TLB of *descheduled* VPs. Under HVF
                        // there is no such saved TLB, so 0 is the faithful value.
                        // Ignoring this write (the old behavior) left TlbInUse
                        // reading uninitialized guest memory, after which the guest
                        // storms FlushTlb against a backend that can only no-op it.
                        match self
                            .vp
                            .partition
                            .guest_memory
                            .write_at(gpa, &0u32.to_le_bytes())
                        {
                            Ok(()) => tracing::info!(
                                gpa = format!("{gpa:#x}"),
                                "published HV_PARTITION_INFO_PAGE (TlbInUse=0)"
                            ),
                            Err(err) => tracing::warn!(
                                gpa = format!("{gpa:#x}"),
                                error = format!("{err:?}"),
                                "failed to publish HV_PARTITION_INFO_PAGE"
                            ),
                        }
                    }
                }
                r if r.0 == HV_ARM64_REGISTER_TLBI_CONTROL => {
                    // Accept the opt-in as a no-op; with TlbInUse=0 published above
                    // (and a GET returning 0 => TlbiEnlightened=0) the guest relies
                    // on its native architectural TLBI regardless.
                    tracelimit::info_ratelimited!(
                        value = value.as_u64(),
                        "TlbiControl set; relying on native architectural TLBI"
                    );
                }
                register => {
                    tracelimit::warn_ratelimited!(
                        ?register,
                        "unsupported register set; ignoring to avoid failing the batch"
                    );
                }
            }
        }
        Ok(())
    }
}

struct HvfNoVtlProtections<'a>(&'a guestmem::GuestMemory);
impl<'a> hv1_emulator::VtlProtectAccess for HvfNoVtlProtections<'a> {
    fn check_modify_and_lock_overlay_page(
        &mut self,
        gpn: u64,
        _check_perms: hvdef::HvMapGpaFlags,
        _new_perms: Option<hvdef::HvMapGpaFlags>,
    ) -> Result<guestmem::LockedPages, HvError> {
        Ok(self.0.lock_gpns(false, &[gpn]).unwrap())
    }

    fn unlock_overlay_page(&mut self, _gpn: u64) -> Result<(), HvError> {
        Ok(())
    }
}

impl PostMessage for HvfHypercallHandler<'_, '_> {
    fn post_message(&mut self, connection_id: u32, message: &[u8]) -> hvdef::HvResult<()> {
        self.vp
            .partition
            .synic_ports
            .handle_post_message(Vtl::Vtl0, connection_id, false, message)
    }
}

impl SignalEvent for HvfHypercallHandler<'_, '_> {
    fn signal_event(&mut self, connection_id: u32, flag: u16) -> hvdef::HvResult<()> {
        self.vp
            .partition
            .synic_ports
            .handle_signal_event(Vtl::Vtl0, connection_id, flag)
    }
}
