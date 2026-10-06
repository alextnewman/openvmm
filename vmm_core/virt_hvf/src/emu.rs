// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AArch64 instruction-emulation support for Hypervisor.framework exits.

use super::HvfPartitionInner;
use super::HvfVcpu;
use super::abi;
use aarch64defs::Cpsr64;
use aarch64defs::IssDataAbort;
use aarch64defs::SctlrEl1;
use aarch64defs::TranslationControlEl1;
use aarch64emu::AccessCpuState;
use aarch64emu::InterceptState;
use hvdef::HvAarch64PendingEvent;
use hvdef::HvAarch64PendingEventType;
use std::convert::Infallible;
use std::future::Future;
use virt::VpHaltReason;
use virt::VpIndex;
use virt::io::CpuIo;
use virt_support_aarch64emu::emulate;
use virt_support_aarch64emu::emulate::EmuCheckVtlAccessError;
use virt_support_aarch64emu::emulate::EmuTranslateError;
use virt_support_aarch64emu::emulate::EmuTranslateResult;
use virt_support_aarch64emu::emulate::EmulatorSupport;
use virt_support_aarch64emu::emulate::InitialTranslation;
use virt_support_aarch64emu::emulate::TranslateGvaSupport;
use virt_support_aarch64emu::emulate::TranslateMode;
use virt_support_aarch64emu::translate::EncryptionMode;
use virt_support_aarch64emu::translate::TranslationRegisters;

struct HvfEmulationState<'a> {
    vcpu: &'a mut HvfVcpu,
    partition: &'a HvfPartitionInner,
    vp_index: VpIndex,
    exception: abi::HvVcpuExitException,
    injection_error: Option<&'static str>,
}

fn exception_vector_offset(cpsr: Cpsr64) -> Option<u64> {
    match (cpsr.el(), cpsr.sp()) {
        (0, _) => Some(0x400),
        (1, false) => Some(0),
        (1, true) => Some(0x200),
        _ => None,
    }
}

impl AccessCpuState for HvfEmulationState<'_> {
    fn commit(&mut self) {}

    fn x(&mut self, index: u8) -> u64 {
        assert!(index < 31);
        self.vcpu.gp(index)
    }

    fn update_x(&mut self, index: u8, data: u64) {
        assert!(index < 31);
        self.vcpu.set_gp(index, data);
    }

    fn q(&self, index: u8) -> u128 {
        self.vcpu.q(index)
    }

    fn update_q(&mut self, index: u8, data: u128) {
        self.vcpu.set_q(index, data);
    }

    fn d(&self, index: u8) -> u64 {
        self.q(index) as u64
    }

    fn update_d(&mut self, index: u8, data: u64) {
        self.update_q(index, data.into());
    }

    fn h(&self, index: u8) -> u32 {
        self.d(index) as u32
    }

    fn update_h(&mut self, index: u8, data: u32) {
        self.update_q(index, data.into());
    }

    fn s(&self, index: u8) -> u16 {
        self.h(index) as u16
    }

    fn update_s(&mut self, index: u8, data: u16) {
        self.update_q(index, data.into());
    }

    fn b(&self, index: u8) -> u8 {
        self.s(index) as u8
    }

    fn update_b(&mut self, index: u8, data: u8) {
        self.update_q(index, data.into());
    }

    fn sp(&mut self) -> u64 {
        self.vcpu.gp(31)
    }

    fn update_sp(&mut self, data: u64) {
        self.vcpu.set_gp(31, data);
    }

    fn fp(&mut self) -> u64 {
        self.vcpu.gp(29)
    }

    fn update_fp(&mut self, data: u64) {
        self.vcpu.set_gp(29, data);
    }

    fn lr(&mut self) -> u64 {
        self.vcpu.gp(30)
    }

    fn update_lr(&mut self, data: u64) {
        self.vcpu.set_gp(30, data);
    }

    fn pc(&mut self) -> u64 {
        self.vcpu.pc()
    }

    fn update_pc(&mut self, data: u64) {
        self.vcpu.set_pc(data);
    }

    fn cpsr(&mut self) -> Cpsr64 {
        self.vcpu.cpsr()
    }
}

impl EmulatorSupport for HvfEmulationState<'_> {
    fn vp_index(&self) -> VpIndex {
        self.vp_index
    }

    fn physical_address(&self) -> Option<u64> {
        Some(self.exception.physical_address)
    }

    fn initial_gva_translation(&mut self) -> Option<InitialTranslation> {
        let iss = IssDataAbort::from(self.exception.syndrome.iss());
        if iss.fnv() {
            return None;
        }

        Some(InitialTranslation {
            gva: self.exception.virtual_address,
            gpa: self.exception.physical_address,
            translate_mode: if iss.wnr() {
                TranslateMode::Write
            } else {
                TranslateMode::Read
            },
        })
    }

    fn interruption_pending(&self) -> bool {
        false
    }

    fn check_vtl_access(
        &mut self,
        _gpa: u64,
        _mode: TranslateMode,
    ) -> Result<(), EmuCheckVtlAccessError> {
        Ok(())
    }

    fn translate_gva(
        &mut self,
        gva: u64,
        mode: TranslateMode,
    ) -> Result<EmuTranslateResult, EmuTranslateError> {
        match virt_support_aarch64emu::translate::emulate_translate_gva(self, gva, mode) {
            Ok(result) => result,
            Err(never) => match never {},
        }
    }

    fn inject_pending_event(&mut self, event: HvAarch64PendingEvent) {
        if !event.header.event_pending()
            || event.header.event_type() != HvAarch64PendingEventType::EXCEPTION
        {
            self.injection_error = Some("unsupported AArch64 pending event");
            return;
        }

        let mut syndrome_bytes = [0; 8];
        syndrome_bytes.copy_from_slice(&event.event_data[7..15]);
        let syndrome = u64::from_ne_bytes(syndrome_bytes);
        let fault_address = event._padding[0];
        let old_cpsr = self.vcpu.cpsr();
        let Some(vector_offset) = exception_vector_offset(old_cpsr) else {
            self.injection_error = Some("cannot inject an exception above EL1");
            return;
        };
        let vbar = self
            .vcpu
            .sys_reg(abi::HvSysReg::VBAR_EL1)
            .expect("unrecoverable error getting VBAR_EL1");
        let pc = self.vcpu.pc();

        self.vcpu
            .set_sys_reg(abi::HvSysReg::SPSR_EL1, old_cpsr.into())
            .expect("unrecoverable error setting SPSR_EL1");
        self.vcpu
            .set_sys_reg(abi::HvSysReg::ELR_EL1, pc)
            .expect("unrecoverable error setting ELR_EL1");
        self.vcpu
            .set_sys_reg(abi::HvSysReg::ESR_EL1, syndrome)
            .expect("unrecoverable error setting ESR_EL1");
        self.vcpu
            .set_sys_reg(abi::HvSysReg::FAR_EL1, fault_address)
            .expect("unrecoverable error setting FAR_EL1");
        self.vcpu
            .set_reg(
                abi::HvReg::CPSR,
                Cpsr64::new()
                    .with_sp(true)
                    .with_el(1)
                    .with_f(true)
                    .with_i(true)
                    .with_a(true)
                    .with_d(true)
                    .into(),
            )
            .expect("unrecoverable error setting CPSR");
        self.vcpu.set_pc(vbar + vector_offset);
    }

    fn is_gpa_mapped(&self, gpa: u64, _write: bool) -> bool {
        self.partition
            .mappings
            .lock()
            .iter()
            .any(|range| range.contains_addr(gpa))
    }
}

impl TranslateGvaSupport for HvfEmulationState<'_> {
    type Error = Infallible;

    fn guest_memory(&self) -> &guestmem::GuestMemory {
        &self.partition.guest_memory
    }

    fn acquire_tlb_lock(&mut self) {
        // HVF has no guest-TLB lock. The emulator uses the resulting translation
        // only until the current instruction completes.
    }

    fn registers(&mut self) -> Result<TranslationRegisters, Self::Error> {
        Ok(TranslationRegisters {
            cpsr: self.vcpu.cpsr(),
            sctlr: SctlrEl1::from(
                self.vcpu
                    .sys_reg(abi::HvSysReg::SCTLR_EL1)
                    .expect("unrecoverable error getting SCTLR_EL1"),
            ),
            tcr: TranslationControlEl1::from(
                self.vcpu
                    .sys_reg(abi::HvSysReg::TCR_EL1)
                    .expect("unrecoverable error getting TCR_EL1"),
            ),
            ttbr0: self
                .vcpu
                .sys_reg(abi::HvSysReg::TTBR0_EL1)
                .expect("unrecoverable error getting TTBR0_EL1"),
            ttbr1: self
                .vcpu
                .sys_reg(abi::HvSysReg::TTBR1_EL1)
                .expect("unrecoverable error getting TTBR1_EL1"),
            syndrome: self.exception.syndrome.into(),
            encryption_mode: EncryptionMode::None,
        })
    }
}

struct HvfEmulatorIo<'a, T> {
    partition: &'a HvfPartitionInner,
    inner: &'a T,
}

impl<T: CpuIo> CpuIo for HvfEmulatorIo<'_, T> {
    fn is_mmio(&self, address: u64) -> bool {
        self.inner.is_mmio(address)
    }

    fn acknowledge_pic_interrupt(&self) -> Option<u8> {
        self.inner.acknowledge_pic_interrupt()
    }

    fn handle_eoi(&self, irq: u32) {
        self.inner.handle_eoi(irq);
    }

    async fn read_mmio(&self, vp: VpIndex, address: u64, data: &mut [u8]) {
        if !self.partition.gicd.read(address, data) {
            self.inner.read_mmio(vp, address, data).await;
        }
    }

    async fn write_mmio(&self, vp: VpIndex, address: u64, data: &[u8]) {
        if self.partition.gicd.write(address, data) {
            for vp in &self.partition.vps {
                vp.wake();
            }
        } else {
            self.inner.write_mmio(vp, address, data).await;
        }
    }

    fn read_io(&self, vp: VpIndex, port: u16, data: &mut [u8]) -> impl Future<Output = ()> {
        self.inner.read_io(vp, port, data)
    }

    fn write_io(&self, vp: VpIndex, port: u16, data: &[u8]) -> impl Future<Output = ()> {
        self.inner.write_io(vp, port, data)
    }

    #[track_caller]
    fn fatal_error(&self, error: Box<dyn std::error::Error + Send + Sync>) -> VpHaltReason {
        self.inner.fatal_error(error)
    }
}

pub async fn emulate_data_abort(
    vcpu: &mut HvfVcpu,
    partition: &HvfPartitionInner,
    vp_index: VpIndex,
    exception: abi::HvVcpuExitException,
    dev: &impl CpuIo,
) -> Result<(), VpHaltReason> {
    let intercept_state = InterceptState {
        gpa: Some(exception.physical_address),
        syndrome: exception.syndrome,
        ..Default::default()
    };
    let io = HvfEmulatorIo {
        partition,
        inner: dev,
    };
    let mut state = HvfEmulationState {
        vcpu,
        partition,
        vp_index,
        exception,
        injection_error: None,
    };

    let result = emulate::emulate(&mut state, &intercept_state, &partition.guest_memory, &io).await;
    if let Some(error) = state.injection_error {
        return Err(dev.fatal_error(anyhow::anyhow!(error).into()));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exception_vector_offsets_follow_current_el() {
        assert_eq!(
            exception_vector_offset(Cpsr64::new().with_el(0)),
            Some(0x400)
        );
        assert_eq!(
            exception_vector_offset(Cpsr64::new().with_el(1).with_sp(false)),
            Some(0)
        );
        assert_eq!(
            exception_vector_offset(Cpsr64::new().with_el(1).with_sp(true)),
            Some(0x200)
        );
        assert_eq!(exception_vector_offset(Cpsr64::new().with_el(2)), None);
    }
}
