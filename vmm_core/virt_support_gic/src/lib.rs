// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A very incomplete implementation of ARM GICv3.

#![expect(missing_docs)]
#![forbid(unsafe_code)]

pub use gicd::Distributor;
pub use gicr::Redistributor;

mod gicd {
    use super::Redistributor;
    use super::gicr::SharedState;
    use aarch64defs::MpidrEl1;
    use aarch64defs::SystemReg;
    use aarch64defs::gic::GicdCtlr;
    use aarch64defs::gic::GicdRegister;
    use aarch64defs::gic::GicdTyper;
    use aarch64defs::gic::GicdTyper2;
    use aarch64defs::gic::GicrSgi;
    use inspect::Inspect;
    use memory_range::MemoryRange;
    use parking_lot::Mutex;
    use std::sync::Arc;
    use vm_topology::processor::VpIndex;

    #[derive(Debug, Inspect)]
    pub struct Distributor {
        state: Mutex<DistributorState>,
        max_spi_intid: u32,
        #[inspect(skip)]
        gicr: Vec<Arc<SharedState>>,
        gicd_range: MemoryRange,
        gicr_range: MemoryRange,
    }

    #[derive(Debug, Inspect)]
    struct DistributorState {
        #[inspect(iter_by_index)]
        pending: Vec<u32>,
        #[inspect(iter_by_index)]
        active: Vec<u32>,
        #[inspect(iter_by_index)]
        group: Vec<u32>,
        #[inspect(iter_by_index)]
        enable: Vec<u32>,
        #[inspect(iter_by_index)]
        cfg: Vec<u32>,
        #[inspect(iter_by_index)]
        priority: Vec<u32>,
        #[inspect(iter_by_index)]
        route: Vec<u64>,
        enable_grp0: bool,
        enable_grp1: bool,
    }

    impl Distributor {
        pub fn new(gicd_base: u64, gicr_range: MemoryRange, max_spis: u32) -> Self {
            let n = (max_spis as usize + 1) / 32;
            Self {
                state: Mutex::new(DistributorState {
                    pending: vec![0; n],
                    active: vec![0; n],
                    group: vec![0; n],
                    enable: vec![0; n],
                    cfg: vec![0; n * 2],
                    priority: vec![0; n * 8],
                    route: vec![0; n * 64],
                    enable_grp0: false,
                    enable_grp1: false,
                }),
                max_spi_intid: 32 + max_spis - 1,
                gicr: Default::default(),
                gicd_range: MemoryRange::new(
                    gicd_base..gicd_base + aarch64defs::GIC_DISTRIBUTOR_SIZE,
                ),
                gicr_range,
            }
        }

        /// Resets all distributor interrupt state to its initial
        /// (post-construction) values, preserving the configured geometry
        /// (intid count, MMIO ranges, and the set of attached redistributors).
        pub fn reset(&self) {
            let mut state = self.state.lock();
            let DistributorState {
                pending,
                active,
                group,
                enable,
                cfg,
                priority,
                route,
                enable_grp0,
                enable_grp1,
            } = &mut *state;
            pending.fill(0);
            active.fill(0);
            group.fill(0);
            enable.fill(0);
            cfg.fill(0);
            priority.fill(0);
            route.fill(0);
            *enable_grp0 = false;
            *enable_grp1 = false;
        }

        pub fn add_redistributor(&mut self, mpidr: u64, last: bool) -> Redistributor {
            let mpidr = mpidr & u64::from(MpidrEl1::AFFINITY_MASK);
            let (gicr, state) = Redistributor::new(self.gicr.len(), mpidr, last);
            self.gicr.push(state);
            assert!(
                (self.gicr.len() as u64)
                    <= self.gicr_range.len() / aarch64defs::GIC_REDISTRIBUTOR_SIZE
            );
            gicr
        }

        pub fn raise_ppi(&self, vp: VpIndex, intid: u32) -> bool {
            if let Some(gicr) = self.gicr.get(vp.index() as usize) {
                gicr.raise(intid)
            } else {
                false
            }
        }

        pub fn set_pending(&self, intid: u32, pending: bool) -> Option<u32> {
            let v = &mut self.state.lock().pending[intid as usize / 32];
            let mask = 1 << (intid & 31);
            if (*v & mask != 0) != pending {
                tracing::debug!(intid, pending, "set pending");
            }
            if pending {
                *v |= mask;
                Some(0)
            } else {
                *v &= !mask;
                None
            }
        }

        pub fn irq_pending(&self, gicr: &Redistributor) -> bool {
            if gicr.irq_pending() {
                return true;
            }
            if gicr.index != 0 {
                return false;
            }
            let state = self.state.lock();
            state
                .pending
                .iter()
                .zip(&state.active)
                .zip(&state.enable)
                .any(|((&p, &a), e)| p & !a & e != 0)
        }

        pub fn ack(&self, gicr: &mut Redistributor, group1: bool) -> u32 {
            if let Some(intid) = gicr.ack(group1) {
                return intid;
            }
            if gicr.index != 0 {
                return 1023;
            }
            let mut state = self.state.lock();
            let state = &mut *state;
            if let Some((i, (p, a))) = state
                .pending
                .iter_mut()
                .zip(&mut state.active)
                .enumerate()
                .find(|(_, (p, a))| **p & !**a != 0)
            {
                let v = 31 - (*p & !*a).leading_zeros();
                *p &= !(1 << v);
                *a |= 1 << v;
                let intid = i as u32 * 32 + v;
                tracing::debug!(intid, "gicd ack");
                intid
            } else {
                1023
            }
        }

        pub fn write_sysreg(
            &self,
            gicr: &mut Redistributor,
            reg: SystemReg,
            value: u64,
            wake: impl FnMut(usize),
        ) -> bool {
            match reg {
                SystemReg::ICC_EOIR0_EL1 => self.eoi(gicr, false, value as u32),
                SystemReg::ICC_EOIR1_EL1 => self.eoi(gicr, true, value as u32),
                SystemReg::ICC_SGI0R_EL1 => self.sgi(gicr, false, value, wake),
                SystemReg::ICC_SGI1R_EL1 => self.sgi(gicr, true, value, wake),
                _ => return gicr.write_cpuif(reg, value),
            }
            true
        }

        fn sgi(
            &self,
            this: &mut Redistributor,
            _group1: bool,
            value: u64,
            mut wake: impl FnMut(usize),
        ) {
            let value = GicrSgi::from(value);
            for (index, gicr) in self.gicr.iter().enumerate() {
                if (value.irm() && !Arc::ptr_eq(&this.shared, gicr))
                    || (!value.irm()
                        && gicr.mpidr.aff3() == value.aff3()
                        && gicr.mpidr.aff2() == value.aff2()
                        && gicr.mpidr.aff1() == value.aff1()
                        && (1 << gicr.mpidr.aff0()) & value.target_list() != 0)
                {
                    if gicr.raise(value.intid()) {
                        wake(index);
                    }
                }
            }
        }

        pub fn read_sysreg(&self, gicr: &mut Redistributor, reg: SystemReg) -> Option<u64> {
            let v = match reg {
                SystemReg::ICC_IAR0_EL1 => self.ack(gicr, false).into(),
                SystemReg::ICC_IAR1_EL1 => self.ack(gicr, true).into(),
                _ => return gicr.read_cpuif(reg),
            };
            Some(v)
        }

        fn eoi(&self, gicr: &mut Redistributor, group1: bool, intid: u32) {
            if intid < 32 {
                gicr.eoi(group1, intid);
                return;
            }
            if gicr.index != 0 {
                return;
            }
            tracing::debug!(intid, "gicd eoi");
            let v = &mut self.state.lock().active[intid as usize / 32];
            *v &= !(1 << (intid & 31));
        }

        fn write32(&self, address: GicdRegister, value: u32) -> bool {
            assert!(address.0 & 3 == 0);
            match address {
                GicdRegister::CTLR => {
                    let ctlr = GicdCtlr::from(value);
                    let mut state = self.state.lock();
                    let state = &mut *state;
                    state.enable_grp0 = ctlr.enable_grp0();
                    state.enable_grp1 = ctlr.enable_grp1();
                }
                r if GicdRegister::IGROUPR.contains(&r.0) => {
                    let n = (r.0 & 0x7f) / 4;
                    if n != 0 {
                        if let Some(group) = self.state.lock().group.get_mut(n as usize) {
                            *group = value;
                        }
                    }
                }
                r if GicdRegister::ISENABLER.contains(&r.0) => {
                    let n = (r.0 & 0x7f) / 4;
                    if n != 0 {
                        if let Some(enable) = self.state.lock().enable.get_mut(n as usize) {
                            *enable |= value;
                        }
                    }
                }
                r if GicdRegister::ICENABLER.contains(&r.0) => {
                    let n = (r.0 & 0x7f) / 4;
                    if n != 0 {
                        if let Some(enable) = self.state.lock().enable.get_mut(n as usize) {
                            *enable &= !value;
                        }
                    }
                }
                r if GicdRegister::ICFGR.contains(&r.0) => {
                    let n = (r.0 & 0xff) / 4;
                    if n >= 2 {
                        if let Some(cfg) = self.state.lock().cfg.get_mut(n as usize) {
                            // The low bit of each bit pair is res0.
                            *cfg = value & 0xaaaaaaaa;
                        }
                    }
                }
                r if GicdRegister::IPRIORITYR.contains(&r.0) => {
                    let n = (r.0 & 0x3ff) / 4;
                    if n >= 8 {
                        if let Some(cfg) = self.state.lock().cfg.get_mut(n as usize) {
                            *cfg = value;
                        }
                    }
                }
                r if GicdRegister::ISACTIVER.contains(&r.0) => {
                    let n = (r.0 & 0x7f) / 4;
                    if n != 0 {
                        if let Some(active) = self.state.lock().active.get_mut(n as usize) {
                            *active |= value;
                        }
                    }
                }
                r if GicdRegister::ICACTIVER.contains(&r.0) => {
                    let n = (r.0 & 0x7f) / 4;
                    if n != 0 {
                        if let Some(active) = self.state.lock().active.get_mut(n as usize) {
                            *active &= !value;
                        }
                    }
                }
                _ => return false,
            }
            true
        }

        fn read32(&self, address: GicdRegister) -> Option<u32> {
            assert!(address.0 & 3 == 0);
            let v = match address {
                GicdRegister::PIDR2 => {
                    // GICv3
                    3 << 4
                }
                GicdRegister::TYPER => GicdTyper::new()
                    .with_it_lines_number(31)
                    .with_id_bits(5)
                    .into(),
                GicdRegister::IIDR => 0,
                GicdRegister::TYPER2 => GicdTyper2::new().into(),
                GicdRegister::CTLR => {
                    let state = self.state.lock();
                    GicdCtlr::new()
                        .with_enable_grp0(state.enable_grp0)
                        .with_enable_grp1(state.enable_grp1)
                        .with_ds(true)
                        .with_are(true)
                        .into()
                }
                r if GicdRegister::IGROUPR.contains(&r.0) => {
                    let n = (r.0 & 0x7f) / 4;
                    self.state
                        .lock()
                        .group
                        .get(n as usize)
                        .copied()
                        .unwrap_or(0)
                }
                r if GicdRegister::ICENABLER.contains(&r.0)
                    || GicdRegister::ISENABLER.contains(&r.0) =>
                {
                    let n = (r.0 & 0x7f) / 4;
                    self.state
                        .lock()
                        .enable
                        .get(n as usize)
                        .copied()
                        .unwrap_or(0)
                }
                r if GicdRegister::ICFGR.contains(&r.0) => {
                    let n = (r.0 & 0xff) / 4;
                    self.state.lock().cfg.get(n as usize).copied().unwrap_or(0)
                }
                r if GicdRegister::IPRIORITYR.contains(&r.0) => {
                    let n = (r.0 & 0x3ff) / 4;
                    self.state
                        .lock()
                        .priority
                        .get(n as usize)
                        .copied()
                        .unwrap_or(0)
                }
                r if GicdRegister::ICACTIVER.contains(&r.0)
                    || GicdRegister::ISACTIVER.contains(&r.0) =>
                {
                    let n = (r.0 & 0x7f) / 4;
                    self.state
                        .lock()
                        .active
                        .get(n as usize)
                        .copied()
                        .unwrap_or(0)
                }
                r if GicdRegister::ICPENDR.contains(&r.0)
                    || GicdRegister::ISPENDR.contains(&r.0) =>
                {
                    let n = (r.0 & 0x7f) / 4;
                    self.state
                        .lock()
                        .pending
                        .get(n as usize)
                        .copied()
                        .unwrap_or(0)
                }
                _ => return None,
            };
            Some(v)
        }

        fn write64(&self, address: GicdRegister, value: u64) -> bool {
            assert!(address.0 & 7 == 0);
            match address {
                r if GicdRegister::IROUTER.contains(&r.0) => {
                    let n = (r.0 & 0x1fff) / 8;
                    if n >= 32 {
                        if let Some(route) = self.state.lock().route.get_mut(n as usize) {
                            *route = value;
                        }
                    }
                }
                _ => return false,
            }
            true
        }

        fn read64(&self, address: GicdRegister) -> Option<u64> {
            assert!(address.0 & 7 == 0);
            let v = match address {
                r if GicdRegister::IROUTER.contains(&r.0) => {
                    let n = (r.0 & 0x1fff) / 8;
                    self.state
                        .lock()
                        .route
                        .get(n as usize)
                        .copied()
                        .unwrap_or(0)
                }
                _ => return None,
            };
            Some(v)
        }

        pub fn read(&self, address: u64, data: &mut [u8]) -> bool {
            if self.gicd_range.contains_addr(address) {
                self.read_gicd(address - self.gicd_range.start(), data);
            } else if self.gicr_range.contains_addr(address) {
                let vp = (address - self.gicr_range.start()) / aarch64defs::GIC_REDISTRIBUTOR_SIZE;
                if let Some(gicr) = self.gicr.get(vp as usize) {
                    gicr.read(address - self.gicr_range.start(), data);
                } else {
                    tracelimit::warn_ratelimited!(
                        address,
                        ?data,
                        "gicr read unallocated redistributor"
                    );
                    data.fill(0);
                }
            } else {
                return false;
            }
            true
        }

        fn read_gicd(&self, address: u64, data: &mut [u8]) {
            if address & (data.len() as u64 - 1) != 0 {
                data.fill(!0);
                tracing::warn!(address, ?data, "gicd read unaligned access");
                return;
            }
            let address = GicdRegister(address as u16);
            let handled = match data.len() {
                4 => {
                    if let Some(v) = self.read32(address) {
                        data.copy_from_slice(&v.to_ne_bytes());
                        true
                    } else {
                        false
                    }
                }
                8 => {
                    if let Some(v) = self.read64(address) {
                        data.copy_from_slice(&v.to_ne_bytes());
                        true
                    } else {
                        false
                    }
                }
                _ => false,
            };
            if !handled {
                data.fill(0);
                tracelimit::warn_ratelimited!(?address, ?data, "unsupported gicd register read");
            }
        }

        pub fn write(&self, address: u64, data: &[u8]) -> bool {
            if self.gicd_range.contains_addr(address) {
                self.write_gicd(address - self.gicd_range.start(), data);
            } else if self.gicr_range.contains_addr(address) {
                let vp = (address - self.gicr_range.start()) / aarch64defs::GIC_REDISTRIBUTOR_SIZE;
                if let Some(gicr) = self.gicr.get(vp as usize) {
                    gicr.write(address - self.gicr_range.start(), data);
                } else {
                    tracelimit::warn_ratelimited!(
                        address,
                        ?data,
                        "gicr write unallocated redistributor"
                    );
                }
            } else {
                return false;
            }
            true
        }

        fn write_gicd(&self, address: u64, data: &[u8]) {
            if address & (data.len() as u64 - 1) != 0 {
                tracing::warn!(address, ?data, "gicd write unaligned access");
                return;
            }
            let address = GicdRegister(address as u16);
            let handled = match data.len() {
                4 => self.write32(address, u32::from_ne_bytes(data.try_into().unwrap())),
                8 => self.write64(address, u64::from_ne_bytes(data.try_into().unwrap())),
                _ => false,
            };
            if !handled {
                tracelimit::warn_ratelimited!(?address, ?data, "unsupported gicd register write");
            }
        }
    }
}

mod gicr {
    use aarch64defs::MpidrEl1;
    use aarch64defs::SystemReg;
    use aarch64defs::gic::GicrCtlr;
    use aarch64defs::gic::GicrRdRegister;
    use aarch64defs::gic::GicrSgiRegister;
    use aarch64defs::gic::GicrTyper;
    use aarch64defs::gic::GicrWaker;
    use aarch64defs::gic::IccCtlrEl1;
    use inspect::Inspect;
    use parking_lot::Mutex;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU32;
    use std::sync::atomic::Ordering;

    #[derive(Debug, Inspect)]
    pub struct Redistributor {
        #[inspect(flatten)]
        pub(super) shared: Arc<SharedState>,
        pub(super) index: usize,
    }

    #[derive(Debug, Inspect)]
    pub(crate) struct SharedState {
        pub(super) pending: AtomicU32,
        #[inspect(with = "|&x| u64::from(x)")]
        pub(super) mpidr: MpidrEl1,
        last: bool,
        mutable: Mutex<SharedMutState>,
    }

    #[derive(Debug, Inspect)]
    struct SharedMutState {
        #[inspect(hex)]
        active: u32,
        #[inspect(hex)]
        group: u32,
        #[inspect(hex)]
        enable: u32,
        #[inspect(hex)]
        ppi_cfg: u32,
        #[inspect(iter_by_index)]
        priority: [u32; 8],
        sleep: bool,
        // GICv3 CPU-interface registers. Banked per-PE, so they live on the
        // per-CPU redistributor state. Recorded for architectural read-back
        // only; delivery (`irq_pending`/`ack`) does NOT yet consult them.
        #[inspect(hex)]
        icc_pmr: u8,
        #[inspect(hex)]
        icc_bpr0: u8,
        #[inspect(hex)]
        icc_bpr1: u8,
        icc_grpen0: bool,
        icc_grpen1: bool,
        icc_cbpr: bool,
        icc_eoimode: bool,
    }

    impl SharedState {
        pub fn raise(&self, intid: u32) -> bool {
            let mask = 1 << intid;
            self.pending.fetch_or(mask, Ordering::Relaxed) & mask == 0
        }

        pub fn read(&self, address: u64, data: &mut [u8]) {
            if address & (data.len() as u64 - 1) != 0 {
                data.fill(!0);
                tracing::warn!(address, ?data, "gicr read unaligned access");
                return;
            }

            if address & 0x10000 == 0 {
                let address = GicrRdRegister(address as u16);
                let handled = match data.len() {
                    4 => {
                        if let Some(v) = self.rd_read32(address) {
                            data.copy_from_slice(&v.to_ne_bytes());
                            true
                        } else {
                            false
                        }
                    }
                    8 => {
                        if let Some(v) = self.rd_read64(address) {
                            data.copy_from_slice(&v.to_ne_bytes());
                            true
                        } else {
                            false
                        }
                    }
                    _ => false,
                };
                if !handled {
                    data.fill(0);
                    tracelimit::warn_ratelimited!(?address, "unsupported gicr rd register read");
                }
            } else {
                let address = GicrSgiRegister(address as u16);
                let handled = match data.len() {
                    4 => {
                        if let Some(v) = self.sgi_read32(address) {
                            data.copy_from_slice(&v.to_ne_bytes());
                            true
                        } else {
                            false
                        }
                    }
                    1 | 2 => self.sgi_read_subword(address, data),
                    _ => false,
                };
                if !handled {
                    data.fill(0);
                    tracelimit::warn_ratelimited!(
                        ?address,
                        ?data,
                        "unsupported gicr sgi register read"
                    );
                }
            }
        }

        pub fn write(&self, address: u64, data: &[u8]) {
            if address & (data.len() as u64 - 1) != 0 {
                tracing::warn!(address, ?data, "gicr write unaligned access");
                return;
            }

            if address & 0x10000 == 0 {
                let address = GicrRdRegister(address as u16);
                let handled = match data.len() {
                    4 => {
                        let data = u32::from_ne_bytes(data.try_into().unwrap());
                        self.rd_write32(address, data)
                    }
                    8 => {
                        let data = u64::from_ne_bytes(data.try_into().unwrap());
                        self.rd_write64(address, data)
                    }
                    _ => false,
                };
                if !handled {
                    tracelimit::warn_ratelimited!(
                        ?address,
                        ?data,
                        "unsupported gicr rd register write"
                    );
                }
            } else {
                let address = GicrSgiRegister(address as u16);
                let handled = match data.len() {
                    4 => {
                        let data = u32::from_ne_bytes(data.try_into().unwrap());
                        self.sgi_write32(address, data)
                    }
                    1 | 2 => self.sgi_write_subword(address, data),
                    _ => false,
                };
                if !handled {
                    tracelimit::warn_ratelimited!(
                        ?address,
                        ?data,
                        "unsupported gicr sgi register write"
                    );
                }
            }
        }

        fn rd_read32(&self, address: GicrRdRegister) -> Option<u32> {
            let v = match address {
                GicrRdRegister::PIDR2 => {
                    // GICv3
                    3 << 4
                }
                GicrRdRegister::CTLR => GicrCtlr::new().into(),
                GicrRdRegister::WAKER => {
                    let sleep = self.mutable.lock().sleep;
                    GicrWaker::new()
                        .with_processor_sleep(sleep)
                        .with_children_asleep(sleep)
                        .into()
                }
                _ => return None,
            };
            tracing::debug!(?address, v, "gicr rd read32");
            Some(v)
        }

        fn rd_write32(&self, address: GicrRdRegister, data: u32) -> bool {
            match address {
                GicrRdRegister::CTLR => {}
                GicrRdRegister::WAKER => {
                    let v = GicrWaker::from(data);
                    self.mutable.lock().sleep = v.processor_sleep();
                }
                _ => return false,
            }
            tracing::debug!(?address, data, "gicr rd write32");
            true
        }

        fn rd_read64(&self, address: GicrRdRegister) -> Option<u64> {
            let v = match address {
                GicrRdRegister::TYPER => GicrTyper::new()
                    .with_aff0(self.mpidr.aff0())
                    .with_aff1(self.mpidr.aff1())
                    .with_aff2(self.mpidr.aff2())
                    .with_aff3(self.mpidr.aff3())
                    .with_last(self.last)
                    .into(),
                _ => return None,
            };
            Some(v)
        }

        fn rd_write64(&self, _address: GicrRdRegister, _data: u64) -> bool {
            false
        }

        fn sgi_read32(&self, address: GicrSgiRegister) -> Option<u32> {
            let v = match address {
                GicrSgiRegister::IGROUPR0 => self.mutable.lock().group,
                GicrSgiRegister::ICACTIVER0 | GicrSgiRegister::ISACTIVER0 => {
                    self.mutable.lock().active
                }
                GicrSgiRegister::ICENABLER0 | GicrSgiRegister::ISENABLER0 => {
                    self.mutable.lock().enable
                }
                GicrSgiRegister::ICPENDR0 | GicrSgiRegister::ISPENDR0 => {
                    self.pending.load(Ordering::Relaxed)
                }
                GicrSgiRegister::ICFGR0 => {
                    // SGIs are always edge triggered.
                    0xaaaaaaaa
                }
                GicrSgiRegister::ICFGR1 => self.mutable.lock().ppi_cfg,
                r if GicrSgiRegister::IPRIORITYR.contains(&r.0) => {
                    let n = (r.0 & 0x1f) / 4;
                    self.mutable.lock().priority[n as usize]
                }
                _ => return None,
            };
            tracing::debug!(?address, v, "gicr sgi read32");
            Some(v)
        }

        fn sgi_write32(&self, address: GicrSgiRegister, data: u32) -> bool {
            match address {
                GicrSgiRegister::IGROUPR0 => self.mutable.lock().group = data,
                GicrSgiRegister::ISACTIVER0 => self.mutable.lock().active |= data,
                GicrSgiRegister::ICACTIVER0 => self.mutable.lock().active &= !data,
                GicrSgiRegister::ISENABLER0 => self.mutable.lock().enable |= data,
                GicrSgiRegister::ICENABLER0 => self.mutable.lock().enable &= !data,
                GicrSgiRegister::ICFGR0 => {
                    // Cannot change trigger mode for SGIs.
                }
                GicrSgiRegister::ICFGR1 => self.mutable.lock().ppi_cfg = data,
                r if GicrSgiRegister::IPRIORITYR.contains(&r.0) => {
                    let n = (r.0 & 0x1f) / 4;
                    self.mutable.lock().priority[n as usize] = data;
                }
                _ => return false,
            }
            tracing::debug!(?address, data, "gicr sgi write32");
            true
        }

        /// Handles byte/halfword writes to the SGI-frame `IPRIORITYR` registers.
        /// The architecture permits software to access priority registers at byte
        /// granularity, and the guest does. This is restricted to `IPRIORITYR`
        /// because the read-modify-write needed for sub-word access is only
        /// correct for plain storage registers; the set/clear registers
        /// (ISENABLER/ICENABLER/ISPENDR/...) must not be RMW'd this way.
        fn sgi_write_subword(&self, address: GicrSgiRegister, data: &[u8]) -> bool {
            if !GicrSgiRegister::IPRIORITYR.contains(&address.0) {
                return false;
            }
            let word = GicrSgiRegister(address.0 & !0x3);
            let mut bytes = self.sgi_read32(word).unwrap_or(0).to_ne_bytes();
            let offset = (address.0 & 0x3) as usize;
            bytes[offset..offset + data.len()].copy_from_slice(data);
            self.sgi_write32(word, u32::from_ne_bytes(bytes))
        }

        /// Handles byte/halfword reads of the SGI-frame `IPRIORITYR` registers.
        /// See [`Self::sgi_write_subword`] for why this is limited to `IPRIORITYR`.
        fn sgi_read_subword(&self, address: GicrSgiRegister, data: &mut [u8]) -> bool {
            if !GicrSgiRegister::IPRIORITYR.contains(&address.0) {
                return false;
            }
            let word = GicrSgiRegister(address.0 & !0x3);
            let Some(value) = self.sgi_read32(word) else {
                return false;
            };
            let bytes = value.to_ne_bytes();
            let offset = (address.0 & 0x3) as usize;
            data.copy_from_slice(&bytes[offset..offset + data.len()]);
            true
        }
    }

    impl Redistributor {
        pub(crate) fn new(index: usize, mpidr: u64, last: bool) -> (Self, Arc<SharedState>) {
            let shared = Arc::new(SharedState {
                pending: AtomicU32::new(0),
                mpidr: mpidr.into(),
                last,
                mutable: Mutex::new(SharedMutState {
                    active: 0,
                    group: 0,
                    enable: 0,
                    ppi_cfg: 0,
                    priority: [0; 8],
                    sleep: false,
                    icc_pmr: 0,
                    icc_bpr0: 0,
                    icc_bpr1: 0,
                    icc_grpen0: false,
                    icc_grpen1: false,
                    icc_cbpr: false,
                    icc_eoimode: false,
                }),
            });
            (
                Self {
                    index,
                    shared: shared.clone(),
                },
                shared,
            )
        }

        /// Resets this redistributor's interrupt state to its initial
        /// (post-construction) values, preserving its identity (mpidr, index,
        /// and last-in-region flag).
        pub fn reset(&mut self) {
            self.shared.pending.store(0, Ordering::Relaxed);
            let mut state = self.shared.mutable.lock();
            let SharedMutState {
                active,
                group,
                enable,
                ppi_cfg,
                priority,
                sleep,
                icc_pmr,
                icc_bpr0,
                icc_bpr1,
                icc_grpen0,
                icc_grpen1,
                icc_cbpr,
                icc_eoimode,
            } = &mut *state;
            *active = 0;
            *group = 0;
            *enable = 0;
            *ppi_cfg = 0;
            *priority = [0; 8];
            *sleep = false;
            *icc_pmr = 0;
            *icc_bpr0 = 0;
            *icc_bpr1 = 0;
            *icc_grpen0 = false;
            *icc_grpen1 = false;
            *icc_cbpr = false;
            *icc_eoimode = false;
        }

        /// Records a write to one of the GICv3 CPU-interface system registers
        /// (ICC_PMR/BPR/IGRPEN/CTLR). These are banked per-PE, so they live on
        /// the redistributor's per-CPU state. Returns `true` if `reg` is a
        /// CPU-interface register handled here.
        ///
        /// NOTE: this only records architectural state for honest read-back; it
        /// does NOT gate interrupt delivery on PMR/IGRPEN (see `irq_pending`).
        pub(crate) fn write_cpuif(&mut self, reg: SystemReg, value: u64) -> bool {
            let mut state = self.shared.mutable.lock();
            match reg {
                SystemReg::ICC_PMR_EL1 => state.icc_pmr = value as u8,
                SystemReg::ICC_BPR0_EL1 => state.icc_bpr0 = (value & 0x7) as u8,
                SystemReg::ICC_BPR1_EL1 => state.icc_bpr1 = (value & 0x7) as u8,
                SystemReg::ICC_IGRPEN0_EL1 => state.icc_grpen0 = value & 1 != 0,
                SystemReg::ICC_IGRPEN1_EL1 => state.icc_grpen1 = value & 1 != 0,
                SystemReg::ICC_CTLR_EL1 => {
                    let ctlr = IccCtlrEl1::from(value);
                    state.icc_cbpr = ctlr.cbpr();
                    state.icc_eoimode = ctlr.eoi_mode();
                }
                _ => return false,
            }
            true
        }

        /// Reads one of the GICv3 CPU-interface system registers. Returns `None`
        /// if `reg` is not a CPU-interface register handled here.
        ///
        /// The writable registers (PMR/BPR/IGRPEN) echo back what the guest
        /// wrote, exactly as real hardware does. This is Linux-validated
        /// (AZL-3 boots to login with these echoes live).
        ///
        /// ICC_CTLR_EL1 deliberately reads back 0. Its PRIbits/IDbits are
        /// read-only capability fields, and we have a *degenerate* priority
        /// model (delivery ignores priority entirely — see `irq_pending`).
        /// Reporting PRIbits=0 ("1 implemented priority bit") is the honest
        /// description of that. Bisection (2026-06-24) proved that fabricating a
        /// larger PRIbits (=7) regressed AZL-3 Linux into a tight UEFI reset
        /// loop, while CTLR=0 — the value the guest already saw historically —
        /// boots cleanly. Do not advertise priority bits we do not honor.
        pub(crate) fn read_cpuif(&self, reg: SystemReg) -> Option<u64> {
            let state = self.shared.mutable.lock();
            let value: u64 = match reg {
                SystemReg::ICC_PMR_EL1 => state.icc_pmr.into(),
                SystemReg::ICC_BPR0_EL1 => state.icc_bpr0.into(),
                SystemReg::ICC_BPR1_EL1 => state.icc_bpr1.into(),
                SystemReg::ICC_IGRPEN0_EL1 => state.icc_grpen0.into(),
                SystemReg::ICC_IGRPEN1_EL1 => state.icc_grpen1.into(),
                SystemReg::ICC_CTLR_EL1 => 0,
                _ => return None,
            };
            Some(value)
        }

        pub fn raise(&mut self, intid: u32) {
            self.shared.pending.fetch_or(1 << intid, Ordering::Relaxed);
        }

        pub(crate) fn irq_pending(&self) -> bool {
            let pending = self.shared.pending.load(Ordering::Relaxed);
            if pending == 0 {
                return false;
            }
            let state = self.shared.mutable.lock();
            (pending & !state.active & state.enable & state.group) != 0
        }

        pub fn is_pending_or_active(&self, intid: u32) -> bool {
            let state = self.shared.mutable.lock();
            (self.shared.pending.load(Ordering::Relaxed) | state.active) & (1 << intid) != 0
        }

        pub(crate) fn ack(&mut self, _group1: bool) -> Option<u32> {
            let pending = self.shared.pending.load(Ordering::Relaxed);
            if pending == 0 {
                None
            } else {
                let mut state = self.shared.mutable.lock();
                let intid = 31 - (pending & !state.active).leading_zeros();
                tracing::trace!(intid, "ack");
                self.shared
                    .pending
                    .fetch_and(!(1 << intid), Ordering::Relaxed);
                state.active |= 1 << intid;
                Some(intid)
            }
        }

        pub(crate) fn eoi(&mut self, _group1: bool, intid: u32) {
            assert!(intid < 32);
            tracing::trace!(intid, "eoi");
            self.shared.mutable.lock().active &= !(1 << intid);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::Redistributor;
        use aarch64defs::gic::GicrSgiRegister;

        // Offset from a redistributor base to its SGI frame.
        const SGI: u64 = 0x1_0000;
        const IPRIORITYR0: u64 = GicrSgiRegister::IPRIORITYR0.0 as u64;
        const ISENABLER0: u64 = GicrSgiRegister::ISENABLER0.0 as u64;
        const ICENABLER0: u64 = GicrSgiRegister::ICENABLER0.0 as u64;

        // Architecture permits byte access to IPRIORITYR; the guest uses it.
        #[test]
        fn ipriorityr_byte_write_read() {
            let (_redist, shared) = Redistributor::new(0, 0, true);

            // intid 20 (the vtimer PPI) sits at IPRIORITYR0 + 0x14.
            shared.write(SGI + IPRIORITYR0 + 0x14, &[0x20]);

            // Reads back at byte, halfword, and word granularity.
            let mut b = [0u8; 1];
            shared.read(SGI + IPRIORITYR0 + 0x14, &mut b);
            assert_eq!(b[0], 0x20);

            let mut w = [0u8; 4];
            shared.read(SGI + IPRIORITYR0 + 0x14, &mut w);
            assert_eq!(u32::from_ne_bytes(w) & 0xff, 0x20);
        }

        // Independent byte writes to one word must not clobber each other.
        #[test]
        fn ipriorityr_byte_writes_dont_clobber() {
            let (_redist, shared) = Redistributor::new(0, 0, true);

            shared.write(SGI + IPRIORITYR0, &[0x10]); // intid 0
            shared.write(SGI + IPRIORITYR0 + 1, &[0x20]); // intid 1
            shared.write(SGI + IPRIORITYR0 + 2, &[0x00]); // intid 2
            shared.write(SGI + IPRIORITYR0 + 3, &[0x40]); // intid 3

            let mut w = [0u8; 4];
            shared.read(SGI + IPRIORITYR0, &mut w);
            assert_eq!(w, [0x10, 0x20, 0x00, 0x40]);
        }

        // Sub-word access to set/clear registers must be rejected, not
        // read-modify-written (which would corrupt the enable mask).
        #[test]
        fn subword_does_not_corrupt_set_clear_registers() {
            let (_redist, shared) = Redistributor::new(0, 0, true);

            // Enable all 32 SGI/PPI interrupts via a word write to ISENABLER0.
            shared.write(SGI + ISENABLER0, &0xffff_ffffu32.to_ne_bytes());

            // A stray byte write to ICENABLER0 must be ignored, not RMW'd
            // (an RMW through ICENABLER would clear the whole enable mask).
            shared.write(SGI + ICENABLER0, &[0xff]);

            let mut w = [0u8; 4];
            shared.read(SGI + ISENABLER0, &mut w);
            assert_eq!(u32::from_ne_bytes(w), 0xffff_ffff);
        }

        // The GICv3 CPU-interface registers round-trip. ICC_CTLR_EL1 read-back
        // is currently pinned to 0 (BISECTION 2026-06-24): fabricating PRIbits=7
        // regressed Linux boot, so we are confirming CTLR is the sole culprit.
        #[test]
        fn icc_cpu_interface_round_trips() {
            use aarch64defs::SystemReg;

            let (mut redist, _shared) = Redistributor::new(0, 0, true);

            // Writable registers read back what was written.
            assert!(redist.write_cpuif(SystemReg::ICC_PMR_EL1, 0xf0));
            assert_eq!(redist.read_cpuif(SystemReg::ICC_PMR_EL1), Some(0xf0));
            assert!(redist.write_cpuif(SystemReg::ICC_BPR1_EL1, 0x3));
            assert_eq!(redist.read_cpuif(SystemReg::ICC_BPR1_EL1), Some(0x3));
            assert!(redist.write_cpuif(SystemReg::ICC_IGRPEN1_EL1, 0x1));
            assert_eq!(redist.read_cpuif(SystemReg::ICC_IGRPEN1_EL1), Some(0x1));

            // ICC_CTLR_EL1 is claimed by the CPU interface but currently reads
            // back as 0 while we bisect the Linux regression.
            assert_eq!(redist.read_cpuif(SystemReg::ICC_CTLR_EL1), Some(0));

            // A non-CPU-interface register is not claimed here.
            assert!(!redist.write_cpuif(SystemReg::ICC_IAR1_EL1, 0));
            assert_eq!(redist.read_cpuif(SystemReg::ICC_IAR1_EL1), None);
        }

        // reset() returns the CPU-interface registers to their defaults.
        #[test]
        fn reset_clears_cpu_interface() {
            use aarch64defs::SystemReg;

            let (mut redist, _shared) = Redistributor::new(0, 0, true);
            redist.write_cpuif(SystemReg::ICC_PMR_EL1, 0xff);
            redist.write_cpuif(SystemReg::ICC_IGRPEN1_EL1, 0x1);
            redist.reset();
            assert_eq!(redist.read_cpuif(SystemReg::ICC_PMR_EL1), Some(0));
            assert_eq!(redist.read_cpuif(SystemReg::ICC_IGRPEN1_EL1), Some(0));
        }
    }
}
