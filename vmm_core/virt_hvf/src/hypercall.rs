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

/// Partition privileges implemented by this backend. On ARM64, the APIC-named
/// bit represents access to synthetic interrupt-controller registers.
const PROVIDED_PRIVILEGES: HvPartitionPrivilege = HvPartitionPrivilege::new()
    .with_access_partition_reference_counter(true)
    .with_access_hypercall_msrs(true)
    .with_access_vp_index(true)
    .with_access_synic_msrs(true)
    .with_access_synthetic_timer_msrs(true)
    .with_access_apic_msrs(true);

/// ARM64 packs its feature dword directly above the 64-bit privilege mask.
const ARM64_GUEST_CRASH_REGS_AVAILABLE: u128 = 1 << 72;

fn arm64_privileges_and_features() -> u128 {
    (PROVIDED_PRIVILEGES.into_bits() as u128) | ARM64_GUEST_CRASH_REGS_AVAILABLE
}

fn guest_crash_capabilities() -> u64 {
    hvdef::GuestCrashCtl::new()
        .with_crash_notify(true)
        .with_crash_message(true)
        .with_no_crash_dump(true)
        .with_pre_os_id(0b111)
        .into()
}

fn crash_parameter_index(register: HvArm64RegisterName) -> Option<usize> {
    (HvArm64RegisterName::GuestCrashP0..=HvArm64RegisterName::GuestCrashP4)
        .contains(&register)
        .then(|| (register.0 - HvArm64RegisterName::GuestCrashP0.0) as usize)
}

#[derive(Debug, Default)]
pub(crate) struct GuestCrashRegisters {
    parameters: [u64; 5],
}

impl GuestCrashRegisters {
    fn write(&mut self, register: HvArm64RegisterName, value: u64) {
        if let Some(index) = crash_parameter_index(register) {
            self.parameters[index] = value;
        }
    }

    fn parameters(&self) -> [u64; 5] {
        self.parameters
    }

    pub(crate) fn clear(&mut self) {
        self.parameters = [0; 5];
    }
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
        let [code, p1, p2, p3, p4] = self.vp.crash_regs.parameters();
        let message = if control.crash_message() && p4 != 0 {
            let message_size = p4.min(hvdef::HV_PAGE_SIZE) as usize;
            let mut message = vec![0; message_size];
            match self.vp.partition.guest_memory.read_at(p3, &mut message) {
                Ok(()) => Some(
                    String::from_utf8_lossy(&message)
                        .trim_end_matches(['\0', '\n', '\r'])
                        .to_owned(),
                ),
                Err(err) => {
                    tracing::warn!(
                        ?err,
                        gpa = p3,
                        size = message_size,
                        "failed to read guest crash message"
                    );
                    None
                }
            }
        } else {
            None
        };

        tracing::error!(
            vp_index = self.vp.inner.vp_info.base.vp_index.index(),
            no_crash_dump = control.no_crash_dump(),
            ?message,
            "guest reported a crash: code={code:#x} p1={p1:#x} p2={p2:#x} \
             p3={p3:#x} p4={p4:#x}"
        );
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

        for (index, (&name, output)) in registers.iter().zip(output).enumerate() {
            *output = match name.into() {
                HvArm64RegisterName::TimeRefCount => {
                    self.vp.partition.vmtime.now().as_100ns().into()
                }
                HvArm64RegisterName::VpIndex => self.vp.inner.vp_info.base.vp_index.index().into(),
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
                HvArm64RegisterName::Sversion => self.vp.hv1.sversion().into(),
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
                HvArm64RegisterName::CpuManagementFeaturesInfo
                | HvArm64RegisterName::PasidFeaturesInfo
                | HvArm64RegisterName::SkipLevelFeaturesInfo
                | HvArm64RegisterName::NestedVirtFeaturesInfo
                | HvArm64RegisterName::IptFeaturesInfo => 0u128.into(),

                HvArm64RegisterName::IsolationConfiguration => {
                    hvdef::HvIsolationConfiguration::new()
                        .with_isolation_type(hvdef::HvPartitionIsolationType::NONE.0)
                        .into_bits()
                        .into()
                }

                HvArm64RegisterName::ImplementationLimitsInfo => {
                    let max_vps = self.vp.partition.vps.len() as u128;
                    (max_vps | (max_vps << 32)).into()
                }

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

                HvArm64RegisterName::GuestCrashCtl => guest_crash_capabilities().into(),
                r if (HvArm64RegisterName::GuestCrashP0..=HvArm64RegisterName::GuestCrashP4)
                    .contains(&r) =>
                {
                    return Err((HvError::AccessDenied, index));
                }
                register => match register.0 {
                    HV_ARM64_REGISTER_SYNTHETIC_VBAR_EL1 => self.vp.synthetic_vbar_el1.into(),
                    HV_ARM64_REGISTER_SYNTHETIC_ESR_EL1 => 0u64.into(),
                    HV_ARM64_REGISTER_INTERFACE_VERSION => u32::from_le_bytes(*b"Hv#1").into(),
                    HV_ARM64_REGISTER_PARTITION_INFO_PAGE => self
                        .vp
                        .partition
                        .partition_info_page
                        .load(Ordering::Acquire)
                        .into(),
                    HV_ARM64_REGISTER_TLBI_CONTROL => self.vp.tlbi_control.into(),
                    _ => return Err((HvError::UnknownRegisterName, index)),
                },
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

/// Private ARM64 register IDs not yet represented by `HvArm64RegisterName`.
const HV_ARM64_REGISTER_SYNTHETIC_VBAR_EL1: u32 = 0x0004_0400;
const HV_ARM64_REGISTER_SYNTHETIC_ESR_EL1: u32 = 0x0004_0401;
const HV_ARM64_REGISTER_INTERFACE_VERSION: u32 = 0x0009_0006;
const HV_ARM64_REGISTER_PARTITION_INFO_PAGE: u32 = 0x0009_0015;
const HV_ARM64_REGISTER_TLBI_CONTROL: u32 = 0x0009_0016;

fn partition_info_page_gpa(value: u64) -> Result<Option<u64>, HvError> {
    if value & 0xffe != 0 {
        return Err(HvError::InvalidRegisterValue);
    }

    Ok((value & 1 != 0).then_some(value & !0xfff))
}

fn validate_tlbi_control(value: u64) -> Result<(), HvError> {
    if value & !1 != 0 {
        return Err(HvError::InvalidRegisterValue);
    }

    Ok(())
}

fn set_synthetic_vbar(current: &mut u64, value: u64) -> Result<(), HvError> {
    if *current != 0 && *current != value {
        return Err(HvError::AccessDenied);
    }

    *current = value;
    Ok(())
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

        for (index, &HvRegisterAssoc { name, value, .. }) in registers.iter().enumerate() {
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
                    .map_err(|_| (HvError::InvalidParameter, index))?,
                HvArm64RegisterName::Sifp => self
                    .vp
                    .hv1
                    .set_siefp(
                        value.as_u64(),
                        &mut HvfNoVtlProtections(&self.vp.partition.guest_memory),
                    )
                    .map_err(|_| (HvError::InvalidParameter, index))?,
                HvArm64RegisterName::Scontrol => self.vp.hv1.set_scontrol(value.as_u64()),
                HvArm64RegisterName::Eom => {}
                r if (HvArm64RegisterName::Sint0..=HvArm64RegisterName::Sint15).contains(&r) => {
                    let sint_index = (r.0 - HvArm64RegisterName::Sint0.0) as usize;
                    self.vp.hv1.set_sint(sint_index, value.as_u64())
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
                    self.vp.crash_regs.write(r, value.as_u64());
                }
                HvArm64RegisterName::GuestCrashCtl => {
                    let control = hvdef::GuestCrashCtl::from(value.as_u64());
                    if control.crash_notify() {
                        self.report_guest_crash(control);
                    }
                }
                r if r.0 == HV_ARM64_REGISTER_SYNTHETIC_VBAR_EL1 => {
                    set_synthetic_vbar(&mut self.vp.synthetic_vbar_el1, value.as_u64())
                        .map_err(|err| (err, index))?;
                }
                r if r.0 == HV_ARM64_REGISTER_SYNTHETIC_ESR_EL1 => {
                    return Err((HvError::AccessDenied, index));
                }
                r if r.0 == HV_ARM64_REGISTER_PARTITION_INFO_PAGE => {
                    let reg = value.as_u64();
                    if let Some(gpa) = partition_info_page_gpa(reg).map_err(|err| (err, index))? {
                        self.vp
                            .partition
                            .guest_memory
                            .write_at(gpa, &0u32.to_le_bytes())
                            .map_err(|_| (HvError::InvalidParameter, index))?;
                    }
                    self.vp
                        .partition
                        .partition_info_page
                        .store(reg, Ordering::Release);
                }
                r if r.0 == HV_ARM64_REGISTER_TLBI_CONTROL => {
                    let control = value.as_u64();
                    validate_tlbi_control(control).map_err(|err| (err, index))?;
                    self.vp.tlbi_control = control;
                }
                _ => return Err((HvError::UnknownRegisterName, index)),
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
        self.0
            .lock_gpns(false, &[gpn])
            .map_err(|_| HvError::InvalidParameter)
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

    #[test]
    fn crash_control_reports_supported_capabilities() {
        let control = hvdef::GuestCrashCtl::from(guest_crash_capabilities());

        assert!(control.crash_notify());
        assert!(control.crash_message());
        assert!(control.no_crash_dump());
        assert_eq!(control.pre_os_id(), 0b111);
    }

    #[test]
    fn crash_parameters_are_sticky_until_reset() {
        let mut registers = GuestCrashRegisters::default();

        registers.write(HvArm64RegisterName::GuestCrashP0, 0x7e);
        registers.write(HvArm64RegisterName::GuestCrashP4, 0x1234);
        assert_eq!(registers.parameters(), [0x7e, 0, 0, 0, 0x1234]);

        registers.clear();
        assert_eq!(registers.parameters(), [0; 5]);
    }

    #[test]
    fn partition_info_page_register_validates_reserved_bits() {
        assert_eq!(partition_info_page_gpa(0), Ok(None));
        assert_eq!(partition_info_page_gpa(0x1234_5001), Ok(Some(0x1234_5000)));
        assert_eq!(
            partition_info_page_gpa(0x2),
            Err(HvError::InvalidRegisterValue)
        );
    }

    #[test]
    fn tlbi_control_only_accepts_the_enlightened_bit() {
        assert_eq!(validate_tlbi_control(0), Ok(()));
        assert_eq!(validate_tlbi_control(1), Ok(()));
        assert_eq!(validate_tlbi_control(2), Err(HvError::InvalidRegisterValue));
    }

    #[test]
    fn synthetic_vbar_is_write_once() {
        let mut vbar = 0;

        assert_eq!(set_synthetic_vbar(&mut vbar, 0x1000), Ok(()));
        assert_eq!(set_synthetic_vbar(&mut vbar, 0x1000), Ok(()));
        assert_eq!(
            set_synthetic_vbar(&mut vbar, 0x2000),
            Err(HvError::AccessDenied)
        );
        assert_eq!(vbar, 0x1000);
    }
}
