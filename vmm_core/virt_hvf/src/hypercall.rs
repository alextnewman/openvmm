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

/// Partition privileges implemented by this backend.
const PROVIDED_PRIVILEGES: HvPartitionPrivilege = HvPartitionPrivilege::new()
    .with_access_partition_reference_counter(true)
    .with_access_hypercall_msrs(true)
    .with_access_vp_index(true)
    .with_access_synic_msrs(true)
    .with_access_synthetic_timer_msrs(true);

/// ARM64 packs its feature dword directly above the 64-bit privilege mask.
const ARM64_GUEST_CRASH_REGS_AVAILABLE: u128 = 1 << 72;

fn arm64_privileges_and_features() -> u128 {
    (PROVIDED_PRIVILEGES.into_bits() as u128) | ARM64_GUEST_CRASH_REGS_AVAILABLE
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

    fn report_guest_crash(&self, control: hvdef::GuestCrashCtl) {
        let [code, p1, p2, p3, p4] = self.vp.crash_params;
        tracing::error!(
            vp_index = self.vp.inner.vp_info.base.vp_index.index(),
            no_crash_dump = control.no_crash_dump(),
            "guest reported a crash: code={code:#x} p1={p1:#x} p2={p2:#x} \
             p3={p3:#x} p4={p4:#x}"
        );

        if control.crash_message() && p4 != 0 {
            let message_size = p4.min(hvdef::HV_PAGE_SIZE) as usize;
            let mut message = vec![0; message_size];
            match self.vp.partition.guest_memory.read_at(p3, &mut message) {
                Ok(()) => {
                    let message = String::from_utf8_lossy(&message);
                    tracing::error!(
                        message = %message.trim_end_matches(['\0', '\n', '\r']),
                        "guest crash message"
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        ?err,
                        gpa = p3,
                        size = message_size,
                        "failed to read guest crash message"
                    );
                }
            }
        }
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
                HvArm64RegisterName::PrivilegesAndFeaturesInfo => {
                    arm64_privileges_and_features().into()
                }
                HvArm64RegisterName::FeaturesInfo => 0u128.into(),
                HvArm64RegisterName::HardwareFeaturesInfo => 0u128.into(),

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

                r if (HvArm64RegisterName::GuestCrashP0..=HvArm64RegisterName::GuestCrashP4)
                    .contains(&r) =>
                {
                    let idx = (r.0 - HvArm64RegisterName::GuestCrashP0.0) as usize;
                    self.vp.crash_params[idx].into()
                }
                HvArm64RegisterName::GuestCrashCtl => 0u128.into(),

                r if r.0 == HV_ARM64_REGISTER_TSC_FREQUENCY => crate::read_cntfrq().into(),
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

/// `HvRegisterTscFrequency` (0x00090006): the frequency, in Hz, of the counter
/// the guest reads for high-resolution timing. On ARM64 that counter is
/// `CNTVCT_EL0`, whose rate is `CNTFRQ_EL0`, so we answer with the live
/// `CNTFRQ`. Not present in `HvArm64RegisterName`, so it is matched by value.
const HV_ARM64_REGISTER_TSC_FREQUENCY: u32 = 0x0009_0006;

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
                r if (HvArm64RegisterName::GuestCrashP0..=HvArm64RegisterName::GuestCrashP4)
                    .contains(&r) =>
                {
                    let idx = (r.0 - HvArm64RegisterName::GuestCrashP0.0) as usize;
                    self.vp.crash_params[idx] = value.as_u64();
                }
                HvArm64RegisterName::GuestCrashCtl => {
                    let control = hvdef::GuestCrashCtl::from(value.as_u64());
                    if control.crash_notify() {
                        self.report_guest_crash(control);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm64_guest_crash_feature_is_bit_72() {
        let value = arm64_privileges_and_features();

        assert_eq!(value as u64, PROVIDED_PRIVILEGES.into_bits());
        assert_eq!(
            value & !(u64::MAX as u128),
            ARM64_GUEST_CRASH_REGS_AVAILABLE
        );
    }
}
