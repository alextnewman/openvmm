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
use hvdef::HvFeatures;
use hvdef::HvPartitionPrivilege;
use hvdef::Vtl;
use hvdef::hypercall::HvRegisterAssoc;
use std::sync::atomic::Ordering;

/// The partition privileges this backend actually provides, advertised through
/// `PrivilegesAndFeaturesInfo` (the AArch64 analogue of the x64 `HV_FEATURES`
/// CPUID leaf).
///
/// This is deliberately a strict *subset* of `hv1_emulator`'s
/// `SUPPORTED_PRIVILEGES`: we advertise only what `virt_hvf` genuinely backs, so
/// the self-description stays coherent with observable behavior. In particular
/// `access_partition_reference_tsc` is **false** — we return 0 for the
/// `ReferenceTsc` register and do not implement the reference TSC page. We
/// present the Hyper-V guest ABI (synic, hypercalls, synthetic timers, reference
/// counter, vp index); we are not the Hyper-V hypervisor, so VSM, debugging,
/// partition management, and hardware-assist privileges all remain false.
///
/// `guest_crash_regs_available` is **true**: we back the guest-crash
/// enlightenment (`GuestCrashP0..P4`/`GuestCrashCtl`) in `set_vp_registers`, so
/// the guest may report its bugcheck code + parameters through those registers.
const PROVIDED_FEATURES: HvFeatures = HvFeatures::new()
    .with_privileges(
        HvPartitionPrivilege::new()
            .with_access_partition_reference_counter(true)
            .with_access_hypercall_msrs(true)
            .with_access_vp_index(true)
            .with_access_synic_msrs(true)
            .with_access_synthetic_timer_msrs(true),
    )
    .with_guest_crash_regs_available(true);

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
                r if (HvArm64RegisterName::Sint0..=HvArm64RegisterName::Sint15).contains(&r) => {
                    self.vp
                        .hv1
                        .sint((r.0 - HvArm64RegisterName::Sint0.0) as u8)
                        .into()
                }

                HvArm64RegisterName::HypervisorVersion => 0u128.into(),
                // The partition privilege/feature self-description. Advertise the
                // exact subset we back (see PROVIDED_FEATURES) so the guest's view
                // of our enlightenments matches what it actually observes.
                HvArm64RegisterName::PrivilegesAndFeaturesInfo => {
                    PROVIDED_FEATURES.into_bits().into()
                }
                // Enlightenment *recommendations* (HvEnlightenmentInformation) and
                // hardware-assist features. We recommend no specific enlightenment
                // optimizations and expose no hardware virtualization assists, so
                // zero is the coherent, honest answer for both.
                HvArm64RegisterName::FeaturesInfo => 0u128.into(),
                HvArm64RegisterName::HardwareFeaturesInfo => 0u128.into(),

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
                    self.vp.hv1.set_sint(
                        (r.0 - HvArm64RegisterName::Sint0.0) as usize,
                        value.as_u64(),
                    )
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
                    // When `crash_message` is set, P3 is the GPA of a textual
                    // crash message and P4 its length; surface it too.
                    if ctl.crash_message() && p4 > 0 && p4 <= 4096 {
                        let mut buf = vec![0u8; p4 as usize];
                        if self
                            .vp
                            .partition
                            .guest_memory
                            .read_at(p3, &mut buf)
                            .is_ok()
                        {
                            let text = String::from_utf8_lossy(&buf);
                            tracing::error!(
                                text = text.trim_end_matches(['\0', '\n', '\r']),
                                "guest crash message"
                            );
                        }
                    }
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
