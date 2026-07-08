// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! System-level, multi-CPU concurrency test harness for the software GIC.
//!
//! The pre-existing unit tests (in each of `mod gicd` / `mod gicr`) all drive a
//! *single* redistributor in isolation. None exercise the GIC as an integrated
//! `Distributor` + N-redistributor *system*, and none exercise it under
//! concurrency. Yet every SMP interrupt bug we have hit (the `GICR_IGROUPR0`
//! group-default hang, the nondeterministic `-p 4` livelock) lives precisely in
//! that surface: SGI routing across redistributors, the pending -> ack ->
//! active -> EOI lifecycle under multiple CPUs, and the discipline of the two
//! locks (the distributor mutex and each redistributor's mutex + atomic pending
//! word).
//!
//! This harness pursues *correctness*, not reaction to a single observed hang.
//! It has three complementary layers:
//!
//! 1. An **independent reference model** ([`refmodel`]) — a small, obviously
//!    correct, single-threaded implementation of the delivery semantics for the
//!    `GICD_CTLR.DS = 1`, Group-1-via-IRQ configuration OpenVMM-on-HVF actually
//!    uses (grounded in ARM IHI 0069 §4.8 and the Hyper-V synthetic-vGIC
//!    contract), against which the real model is differentially fuzzed.
//!
//! 2. **Seeded differential fuzzing** — arbitrary, deliberately-out-of-order
//!    operation streams (including nonsensical ones: EOI without ack, ack with
//!    nothing pending, redundant / reordered config writes) applied identically
//!    to the real GIC and the reference, asserting observable equivalence after
//!    every step. A failing seed replays deterministically.
//!
//! 3. **Real-thread concurrency stress** — genuine OS threads, one per CPU,
//!    storming SGIs at each other while servicing their own, under a wall-clock
//!    watchdog that turns any deadlock or livelock into a test failure, with the
//!    per-CPU architectural invariants asserted throughout.

use crate::Distributor;
use crate::Redistributor;
use aarch64defs::MpidrEl1;
use aarch64defs::SystemReg;
use aarch64defs::gic::GicrSgi;
use memory_range::MemoryRange;

// ---- GICR SGI-frame register offsets (relative to a redistributor base) ------
// The redistributor MMIO window is two 64 KiB frames; the SGI/PPI configuration
// registers live in the second (SGI) frame at `+0x1_0000`.
const SGI_FRAME: u64 = 0x1_0000;
const IGROUPR0: u64 = 0x0080;
const ISENABLER0: u64 = 0x0100;
const IPRIORITYR0: u64 = 0x0400;

// ---- GICD register offsets (relative to the distributor base, here 0) --------
const GICD_IGROUPR0: u64 = 0x0080;
const GICD_ISENABLER0: u64 = 0x0100;
const GICD_ISPENDR0: u64 = 0x0200;
const GICD_ISACTIVER0: u64 = 0x0300;
const GICD_IPRIORITYR0: u64 = 0x0400;

/// A no-op `wake` sink for the (single-threaded) paths that do not care whether
/// a target CPU would have been kicked.
fn no_wake(_: usize) {}

// -----------------------------------------------------------------------------
// Deterministic PRNG (SplitMix64). Every fuzz body is a pure function of its
// seed, so a failure prints one number that reproduces it exactly. No external
// `rand` dependency (and thus no Cargo.toml churn on the keeper crate).
// -----------------------------------------------------------------------------
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..n` (`n > 0`).
    fn below(&mut self, n: u32) -> u32 {
        (self.next_u64() % u64::from(n)) as u32
    }

    fn boolean(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
}

// -----------------------------------------------------------------------------
// ICC_SGI1R_EL1 raw-value builders.
// -----------------------------------------------------------------------------

/// A targeted SGI: `intid` to the single CPU whose affinity-0 == `cpu`
/// (affinity 1/2/3 == 0 in this harness's flat topology).
fn sgi1r_targeted(intid: u32, cpu: usize) -> u64 {
    GicrSgi::new()
        .with_intid(intid)
        .with_irm(false)
        .with_target_list(1u16 << cpu)
        .into()
}

/// A broadcast SGI (IRM = 1): `intid` to every CPU *except* the sender.
fn sgi1r_broadcast(intid: u32) -> u64 {
    GicrSgi::new().with_intid(intid).with_irm(true).into()
}

// -----------------------------------------------------------------------------
// A multi-CPU GIC system under test: one shared `Distributor` and one
// `Redistributor` handle per CPU (each handle wraps that CPU's `Arc<SharedState>`
// which the distributor also holds, so SGI routing reaches real shared state).
// -----------------------------------------------------------------------------
struct Sys {
    dist: Distributor,
    redists: Vec<Redistributor>,
    n: usize,
}

impl Sys {
    fn new(n: usize, max_spis: u32) -> Self {
        let gicd_base = 0u64;
        let gicr_base = aarch64defs::GIC_DISTRIBUTOR_SIZE;
        let gicr_len = n as u64 * aarch64defs::GIC_REDISTRIBUTOR_SIZE;
        let gicr_range = MemoryRange::new(gicr_base..gicr_base + gicr_len);
        let mut dist = Distributor::new(gicd_base, gicr_range, max_spis);
        let redists = (0..n)
            .map(|i| {
                let mpidr: u64 = MpidrEl1::new().with_aff0(i as u8).into();
                dist.add_redistributor(mpidr, i == n - 1)
            })
            .collect();
        Sys { dist, redists, n }
    }

    /// Bring every CPU interface "online" the way a guest does before it expects
    /// delivery: unmask all priorities (PMR = 0xff) and enable Group 1. Also
    /// enable both groups at the distributor (for SPI forwarding).
    fn online_all(&mut self) {
        use aarch64defs::gic::GicdCtlr;
        let ctlr: u32 = GicdCtlr::new()
            .with_enable_grp0(true)
            .with_enable_grp1(true)
            .into();
        self.dist.write(0 /* GICD_CTLR */, &ctlr.to_ne_bytes());
        let Sys { dist, redists, .. } = self;
        for r in redists.iter_mut() {
            dist.write_sysreg(r, SystemReg::ICC_PMR_EL1, 0xff, no_wake);
            dist.write_sysreg(r, SystemReg::ICC_IGRPEN1_EL1, 1, no_wake);
            dist.write_sysreg(r, SystemReg::ICC_IGRPEN0_EL1, 1, no_wake);
        }
    }

    fn send_sgi1r(&mut self, from: usize, raw: u64) {
        let Sys { dist, redists, .. } = self;
        dist.write_sysreg(&mut redists[from], SystemReg::ICC_SGI1R_EL1, raw, no_wake);
    }

    /// Acknowledge the highest-priority pending Group-1 interrupt on `cpu`
    /// (ICC_IAR1_EL1 read). Returns the acknowledged INTID (1023 == spurious).
    fn ack1(&mut self, cpu: usize) -> u32 {
        let Sys { dist, redists, .. } = self;
        dist.read_sysreg(&mut redists[cpu], SystemReg::ICC_IAR1_EL1)
            .unwrap() as u32
    }

    /// End-of-interrupt for `intid` on `cpu` (ICC_EOIR1_EL1 write).
    fn eoi1(&mut self, cpu: usize, intid: u32) {
        let Sys { dist, redists, .. } = self;
        dist.write_sysreg(
            &mut redists[cpu],
            SystemReg::ICC_EOIR1_EL1,
            u64::from(intid),
            no_wake,
        );
    }

    fn pending(&self, cpu: usize) -> bool {
        self.dist.irq_pending(&self.redists[cpu])
    }

    /// Write this CPU's `GICR_IGROUPR0` (SGI/PPI group config) via MMIO.
    fn write_igroupr0(&self, cpu: usize, value: u32) {
        self.redists[cpu]
            .shared
            .write(SGI_FRAME + IGROUPR0, &value.to_ne_bytes());
    }

    /// Enable a set of PPIs (word mask, intids 16..31) via `GICR_ISENABLER0`.
    fn enable_ppis(&self, cpu: usize, mask: u32) {
        self.redists[cpu]
            .shared
            .write(SGI_FRAME + ISENABLER0, &mask.to_ne_bytes());
    }

    /// Set the 8-bit priority of an SGI/PPI `intid` on `cpu` (byte write to
    /// `GICR_IPRIORITYR`).
    fn set_sgi_ppi_priority(&self, cpu: usize, intid: u32, priority: u8) {
        self.redists[cpu]
            .shared
            .write(SGI_FRAME + IPRIORITYR0 + u64::from(intid), &[priority]);
    }

    /// Write a CPU-interface system register on `cpu` (PMR / BPR1 / CBPR /
    /// IGRPEN), the way a guest programs its CPU interface.
    fn write_cpuif(&mut self, cpu: usize, reg: SystemReg, value: u64) {
        let Sys { dist, redists, .. } = self;
        dist.write_sysreg(&mut redists[cpu], reg, value, no_wake);
    }

    /// Read a distributor SPI pending word (`w` >= 1) via `GICD_ISPENDR` MMIO.
    fn spi_pending_word(&self, w: usize) -> u32 {
        let mut b = [0u8; 4];
        self.dist.read(GICD_ISPENDR0 + (w as u64) * 4, &mut b);
        u32::from_ne_bytes(b)
    }

    /// Read a distributor SPI active word (`w` >= 1) via `GICD_ISACTIVER` MMIO.
    fn spi_active_word(&self, w: usize) -> u32 {
        let mut b = [0u8; 4];
        self.dist.read(GICD_ISACTIVER0 + (w as u64) * 4, &mut b);
        u32::from_ne_bytes(b)
    }

    /// Provision an SPI `intid` the way a guest does: enable it, place it in
    /// Group 1, and set its priority — via GICD MMIO with the exact
    /// read/modify/write the model expects (ISENABLER is set-only; IGROUPR and
    /// IPRIORITYR are overwrite, so both are RMW'd to avoid clobbering
    /// neighbours).
    fn provision_spi(&self, intid: u32, priority: u8) {
        let w = u64::from(intid / 32);
        self.dist.write(
            GICD_ISENABLER0 + w * 4,
            &(1u32 << (intid % 32)).to_ne_bytes(),
        );
        let goff = GICD_IGROUPR0 + w * 4;
        let mut gb = [0u8; 4];
        self.dist.read(goff, &mut gb);
        let g = u32::from_ne_bytes(gb) | (1u32 << (intid % 32));
        self.dist.write(goff, &g.to_ne_bytes());
        let poff = GICD_IPRIORITYR0 + u64::from(intid / 4) * 4;
        let mut pb = [0u8; 4];
        self.dist.read(poff, &mut pb);
        pb[(intid % 4) as usize] = priority;
        self.dist.write(poff, &pb);
    }
}

#[cfg(test)]
mod smoke {
    use super::*;

    /// The most basic cross-CPU path: CPU 0 targets an SGI at CPU 1; CPU 1 (and
    /// only CPU 1) sees it, acknowledges the right INTID, and drains it on EOI.
    #[test]
    fn targeted_sgi_lifecycle() {
        let mut sys = Sys::new(4, 32);
        sys.online_all();

        sys.send_sgi1r(0, sgi1r_targeted(3, 1));

        // Exactly CPU 1 sees it.
        assert!(sys.pending(1), "target CPU 1 should see the SGI");
        for cpu in [0, 2, 3] {
            assert!(!sys.pending(cpu), "non-target CPU {cpu} must not see it");
        }

        assert_eq!(sys.ack1(1), 3, "CPU 1 should ack INTID 3");
        assert!(sys.redists[1].is_pending_or_active(3), "3 is now active");
        assert!(!sys.pending(1), "nothing else pending after ack");

        sys.eoi1(1, 3);
        assert!(!sys.redists[1].is_pending_or_active(3), "EOI drains 3");
        assert!(!sys.pending(1));
    }

    /// A broadcast SGI (IRM = 1) reaches every CPU except the sender.
    #[test]
    fn broadcast_sgi_reaches_all_but_sender() {
        let mut sys = Sys::new(4, 32);
        sys.online_all();

        sys.send_sgi1r(2, sgi1r_broadcast(0));

        assert!(!sys.pending(2), "sender must not receive its own broadcast");
        for cpu in [0, 1, 3] {
            assert!(sys.pending(cpu), "CPU {cpu} should receive the broadcast");
            assert_eq!(sys.ack1(cpu), 0);
            sys.eoi1(cpu, 0);
            assert!(!sys.pending(cpu));
        }
    }
}

// =============================================================================
// Independent reference model.
//
// A small, deliberately-simple, single-threaded implementation of the GICv3
// delivery semantics for the configuration OpenVMM-on-HVF uses:
// `GICD_CTLR.DS = 1` (single security state, all interrupts Non-secure), no
// EL3, Group-1 delivered via IRQ. It is grounded in ARM IHI 0069H.b §4.8
// (priority grouping, active priorities, preemption, masking, deactivation) and
// the Hyper-V synthetic-vGIC contract, and is written *independently* of the
// implementation under test so that agreement between the two is meaningful.
//
// The constants and small arithmetic helpers are re-declared locally (rather
// than imported from the crate) precisely so the reference does not inherit a
// bug from the code it is meant to check.
// =============================================================================
mod refmodel {
    use aarch64defs::gic::GicrSgi;

    const PREEMPT_SHIFT: u8 = 3; // 8 - PRIBITS, PRIBITS = 5
    const SGI_ENABLE_MASK: u32 = 0x0000_ffff;
    const IGROUPR0_RESET: u32 = 0xffff_ffff;

    fn group_mask(bpr: u8) -> u8 {
        (0xffu16 << (bpr + 1)) as u8
    }
    fn group_priority(priority: u8, bpr: u8) -> u8 {
        priority & group_mask(bpr)
    }
    fn effective_bpr(group1: bool, cbpr: bool, bpr0: u8, bpr1: u8) -> u8 {
        if group1 && !cbpr {
            bpr1.saturating_sub(1)
        } else {
            bpr0
        }
    }
    fn running_priority(apr: u32) -> u8 {
        if apr == 0 {
            0xff
        } else {
            (apr.trailing_zeros() as u8) << PREEMPT_SHIFT
        }
    }

    #[derive(Clone)]
    pub struct RefCpu {
        pub pending: u32,
        pub active: u32,
        pub enable: u32,
        pub group: u32,
        pub priority: [u8; 32],
        pub pmr: u8,
        pub bpr0: u8,
        pub bpr1: u8,
        pub grpen0: bool,
        pub grpen1: bool,
        pub cbpr: bool,
        pub apr0: u32,
        pub apr1: u32,
    }

    impl RefCpu {
        fn new() -> Self {
            RefCpu {
                pending: 0,
                active: 0,
                enable: SGI_ENABLE_MASK,
                group: IGROUPR0_RESET,
                priority: [0; 32],
                pmr: 0,
                bpr0: 2,
                bpr1: 3,
                grpen0: false,
                grpen1: false,
                cbpr: false,
                apr0: 0,
                apr1: 0,
            }
        }
    }

    pub struct RefGic {
        pub cpus: Vec<RefCpu>,
        pub max_spi_intid: u32,
        pub spi_pending: Vec<u32>,
        pub spi_active: Vec<u32>,
        pub spi_enable: Vec<u32>,
        pub spi_group: Vec<u32>,
        pub spi_priority: Vec<u8>,
        pub gicd_grp0: bool,
        pub gicd_grp1: bool,
    }

    impl RefGic {
        pub fn new(n: usize, max_spis: u32) -> Self {
            let words = (max_spis as usize + 1) / 32;
            RefGic {
                cpus: vec![RefCpu::new(); n],
                max_spi_intid: 32 + max_spis - 1,
                spi_pending: vec![0; words],
                spi_active: vec![0; words],
                spi_enable: vec![0; words],
                spi_group: vec![0; words],
                spi_priority: vec![0; words * 32],
                gicd_grp0: false,
                gicd_grp1: false,
            }
        }

        // ---- configuration (mirrors the real MMIO / sysreg write semantics) --

        pub fn online_all(&mut self) {
            self.gicd_grp0 = true;
            self.gicd_grp1 = true;
            for c in &mut self.cpus {
                c.pmr = 0xff;
                c.grpen1 = true;
                c.grpen0 = true;
            }
        }

        pub fn set_pmr(&mut self, cpu: usize, v: u8) {
            self.cpus[cpu].pmr = v;
        }
        pub fn set_bpr1(&mut self, cpu: usize, v: u8) {
            self.cpus[cpu].bpr1 = (v & 0x7).max(3);
        }
        pub fn set_cbpr(&mut self, cpu: usize, v: bool) {
            self.cpus[cpu].cbpr = v;
        }
        pub fn set_grpen1(&mut self, cpu: usize, v: bool) {
            self.cpus[cpu].grpen1 = v;
        }
        pub fn set_igroupr0(&mut self, cpu: usize, v: u32) {
            self.cpus[cpu].group = v;
        }
        pub fn enable_ppis(&mut self, cpu: usize, mask: u32) {
            // Only PPI bits are writable; SGIs are permanently enabled.
            self.cpus[cpu].enable |= mask & !SGI_ENABLE_MASK;
        }
        pub fn set_sgi_ppi_priority(&mut self, cpu: usize, intid: u32, priority: u8) {
            self.cpus[cpu].priority[intid as usize] = priority;
        }

        // ---- raising ---------------------------------------------------------

        /// Decode an `ICC_SGI1R_EL1` value and set the target(s) pending, exactly
        /// as the real distributor's `sgi` routing does (IRM = broadcast to all
        /// except the sender; otherwise affinity + target-list match). This
        /// harness uses a flat topology: CPU `i` has affinity `aff0 = i`, all
        /// higher affinities zero.
        pub fn send_sgi(&mut self, from: usize, raw: u64) {
            let v = GicrSgi::from(raw);
            let intid = v.intid();
            for i in 0..self.cpus.len() {
                let hit = if v.irm() {
                    i != from
                } else {
                    v.aff1() == 0
                        && v.aff2() == 0
                        && v.aff3() == 0
                        && (1u16 << i) & v.target_list() != 0
                };
                if hit {
                    self.cpus[i].pending |= 1 << intid;
                }
            }
        }

        pub fn raise_ppi(&mut self, cpu: usize, intid: u32) {
            self.cpus[cpu].pending |= 1 << intid;
        }

        pub fn raise_spi(&mut self, intid: u32) {
            self.spi_pending[intid as usize / 32] |= 1 << (intid % 32);
        }

        pub fn enable_spi(&mut self, intid: u32) {
            self.spi_enable[intid as usize / 32] |= 1 << (intid % 32);
        }

        pub fn set_spi_group1(&mut self, intid: u32) {
            self.spi_group[intid as usize / 32] |= 1 << (intid % 32);
        }

        pub fn set_spi_priority(&mut self, intid: u32, priority: u8) {
            self.spi_priority[intid as usize] = priority;
        }

        /// Provision an SPI (enable + Group 1 + priority), mirroring
        /// `Sys::provision_spi`.
        pub fn provision_spi(&mut self, intid: u32, priority: u8) {
            self.enable_spi(intid);
            self.set_spi_group1(intid);
            self.set_spi_priority(intid, priority);
        }

        // ---- delivery --------------------------------------------------------

        fn best_sgi_ppi(&self, cpu: usize, group1: bool) -> Option<(u32, u8)> {
            let c = &self.cpus[cpu];
            let group = if group1 { c.group } else { !c.group };
            let mut deliverable = c.pending & !c.active & c.enable & group;
            let mut best: Option<(u32, u8)> = None;
            while deliverable != 0 {
                let intid = deliverable.trailing_zeros();
                deliverable &= deliverable - 1;
                let pri = c.priority[intid as usize];
                best = Some(match best {
                    Some((bi, bp)) if bp <= pri => (bi, bp),
                    _ => (intid, pri),
                });
            }
            best
        }

        fn best_spi(&self, group1: bool) -> Option<(u32, u8)> {
            // Spec: SPIs are only forwarded when the corresponding group is
            // enabled at the distributor (GICD_CTLR.EnableGrpX).
            let gicd_en = if group1 {
                self.gicd_grp1
            } else {
                self.gicd_grp0
            };
            if !gicd_en {
                return None;
            }
            let mut best: Option<(u32, u8)> = None;
            for w in 1..self.spi_pending.len() {
                let group = if group1 {
                    self.spi_group[w]
                } else {
                    !self.spi_group[w]
                };
                let mut deliverable =
                    self.spi_pending[w] & !self.spi_active[w] & self.spi_enable[w] & group;
                while deliverable != 0 {
                    let bit = deliverable.trailing_zeros();
                    deliverable &= deliverable - 1;
                    let intid = w as u32 * 32 + bit;
                    if intid > self.max_spi_intid {
                        continue;
                    }
                    let pri = self.spi_priority[intid as usize];
                    best = Some(match best {
                        Some((bi, bp)) if bp <= pri => (bi, bp),
                        _ => (intid, pri),
                    });
                }
            }
            best
        }

        fn admit(&self, cpu: usize, group1: bool, priority: u8) -> Option<u8> {
            let c = &self.cpus[cpu];
            // Spec: the CPU interface only signals a group's interrupts when that
            // group is enabled (ICC_IGRPEN{0,1}_EL1.Enable).
            let grpen = if group1 { c.grpen1 } else { c.grpen0 };
            if !grpen {
                return None;
            }
            // Priority masking: an interrupt is masked when priority >= PMR.
            if priority >= c.pmr {
                return None;
            }
            let bpr = effective_bpr(group1, c.cbpr, c.bpr0, c.bpr1);
            let gp = group_priority(priority, bpr);
            let apr = if group1 { c.apr1 } else { c.apr0 };
            (gp < running_priority(apr)).then_some(gp)
        }

        fn select(&self, cpu: usize, group1: bool) -> Option<(u32, u8)> {
            let mut cand = self.best_sgi_ppi(cpu, group1);
            if cpu == 0 {
                if let Some(spi) = self.best_spi(group1) {
                    cand = Some(match cand {
                        Some((i, p)) if p <= spi.1 => (i, p),
                        _ => spi,
                    });
                }
            }
            let (intid, pri) = cand?;
            let gp = self.admit(cpu, group1, pri)?;
            Some((intid, gp))
        }

        /// The Group-1/IRQ delivery predicate the HVF poll loop consults. Only
        /// PE 0 sees SPIs (matching the real model's PE-0-only SPI delivery).
        pub fn irq_pending(&self, cpu: usize) -> bool {
            self.select(cpu, true).is_some()
        }

        fn push_priority(&mut self, cpu: usize, group1: bool, gp: u8) {
            let bit = 1u32 << (gp >> PREEMPT_SHIFT);
            if group1 {
                self.cpus[cpu].apr1 |= bit;
            } else {
                self.cpus[cpu].apr0 |= bit;
            }
        }

        fn pop_priority(&mut self, cpu: usize, group1: bool) {
            let apr = if group1 {
                &mut self.cpus[cpu].apr1
            } else {
                &mut self.cpus[cpu].apr0
            };
            if *apr != 0 {
                *apr &= *apr - 1;
            }
        }

        pub fn ack(&mut self, cpu: usize, group1: bool) -> u32 {
            if cpu != 0 {
                // Non-zero PE: only its own SGI/PPIs.
                let Some((intid, pri)) = self.best_sgi_ppi(cpu, group1) else {
                    return 1023;
                };
                let Some(gp) = self.admit(cpu, group1, pri) else {
                    return 1023;
                };
                self.cpus[cpu].pending &= !(1 << intid);
                self.cpus[cpu].active |= 1 << intid;
                self.push_priority(cpu, group1, gp);
                return intid;
            }
            let Some((intid, gp)) = self.select(0, group1) else {
                return 1023;
            };
            if intid < 32 {
                self.cpus[0].pending &= !(1 << intid);
                self.cpus[0].active |= 1 << intid;
            } else {
                let w = intid as usize / 32;
                self.spi_pending[w] &= !(1 << (intid % 32));
                self.spi_active[w] |= 1 << (intid % 32);
            }
            self.push_priority(0, group1, gp);
            intid
        }

        pub fn eoi(&mut self, cpu: usize, group1: bool, intid: u32) {
            if intid >= 1020 {
                return;
            }
            if intid < 32 {
                self.pop_priority(cpu, group1);
                self.cpus[cpu].active &= !(1 << intid);
                return;
            }
            if cpu != 0 {
                return;
            }
            self.pop_priority(0, group1);
            let w = intid as usize / 32;
            self.spi_active[w] &= !(1 << (intid % 32));
        }
    }
}

// -----------------------------------------------------------------------------
// Layer 2: seeded differential fuzzing.
//
// Drive the *real* GIC and the independent [`refmodel::RefGic`] with the SAME
// deliberately-out-of-order operation stream, and assert full observable
// equivalence after EVERY operation. The op mix is intentionally adversarial —
// it makes no assumption of guest sanity or ordering: EOI without a matching
// ack, ack with nothing pending, EOI of a random (not-active) intid, redundant
// and reordered config writes, SGIs to arbitrary targets. Any divergence prints
// the seed + step + last op + both states, replaying deterministically.
//
// Group enables (ICC_IGRPEN0/1) and the distributor group enables stay ON for
// the whole stream (both models are brought online and never toggle them), so
// this layer isolates *delivery-lifecycle* equivalence. Group-gating and PMR /
// preemption spec properties are asserted separately in [`properties`].
// -----------------------------------------------------------------------------
#[cfg(test)]
mod differential {
    use super::refmodel::RefGic;
    use super::*;
    use vm_topology::processor::VpIndex;

    /// Assert the real GIC and the reference are observably identical: for every
    /// CPU, its SGI/PPI pending/active/APR/enable/group and `irq_pending`; and
    /// the distributor's SPI pending/active words.
    fn check_equiv(sys: &Sys, refm: &RefGic, seed: u64, step: usize, last: &str) {
        for cpu in 0..sys.n {
            let d = sys.redists[cpu].ppi_diag();
            let rc = &refm.cpus[cpu];
            let ctx = || format!("seed={seed:#x} step={step} last_op=[{last}] cpu={cpu}");
            assert_eq!(
                d.pending,
                rc.pending,
                "{}: sgi/ppi pending\n real={d:?}",
                ctx()
            );
            assert_eq!(
                d.active,
                rc.active,
                "{}: sgi/ppi active\n real={d:?}",
                ctx()
            );
            assert_eq!(d.icc_ap1r0, rc.apr1, "{}: apr1\n real={d:?}", ctx());
            assert_eq!(d.icc_ap0r0, rc.apr0, "{}: apr0\n real={d:?}", ctx());
            assert_eq!(d.enable, rc.enable, "{}: enable\n real={d:?}", ctx());
            assert_eq!(d.group, rc.group, "{}: group\n real={d:?}", ctx());
            let ip_real = sys.dist.irq_pending(&sys.redists[cpu]);
            let ip_ref = refm.irq_pending(cpu);
            assert_eq!(ip_real, ip_ref, "{}: irq_pending", ctx());
        }
        for w in 1..refm.spi_pending.len() {
            assert_eq!(
                sys.spi_pending_word(w),
                refm.spi_pending[w],
                "seed={seed:#x} step={step} last_op=[{last}] spi_pending[{w}]"
            );
            assert_eq!(
                sys.spi_active_word(w),
                refm.spi_active[w],
                "seed={seed:#x} step={step} last_op=[{last}] spi_active[{w}]"
            );
        }
    }

    #[test]
    fn differential_random_ops() {
        const N: usize = 4;
        // 96 SPIs => 3 pending/active words (0..=2); SPI intids 32..=95 are all
        // in range of the model's Vecs.
        const MAX_SPIS: u32 = 96;
        const SEEDS: u64 = 400;
        const OPS: usize = 600;

        for s in 0..SEEDS {
            let seed = 0x0C0FFEE_u64.wrapping_mul(s.wrapping_add(1)) ^ (s << 32);
            let mut rng = Rng::new(seed);
            let mut sys = Sys::new(N, MAX_SPIS);
            let mut refm = RefGic::new(N, MAX_SPIS);
            sys.online_all();
            refm.online_all();

            // Per-CPU in-service stack (acked, not yet EOI'd) so most EOIs are
            // realistic LIFO — but a fraction are deliberately nonsensical.
            let mut inflight: Vec<Vec<u32>> = vec![Vec::new(); N];

            check_equiv(&sys, &refm, seed, 0, "init");

            for step in 1..=OPS {
                let last: String;
                match rng.below(100) {
                    // ---- send SGI (targeted or broadcast) --------------------
                    0..=26 => {
                        let from = rng.below(N as u32) as usize;
                        let intid = rng.below(16);
                        if rng.boolean() {
                            let raw = sgi1r_broadcast(intid);
                            sys.send_sgi1r(from, raw);
                            refm.send_sgi(from, raw);
                            last = format!("sgi_bcast from={from} id={intid}");
                        } else {
                            let target = rng.below(N as u32) as usize;
                            let raw = sgi1r_targeted(intid, target);
                            sys.send_sgi1r(from, raw);
                            refm.send_sgi(from, raw);
                            last = format!("sgi_tgt from={from} to={target} id={intid}");
                        }
                    }
                    // ---- acknowledge (ICC_IAR1) ------------------------------
                    27..=50 => {
                        let cpu = rng.below(N as u32) as usize;
                        let got = sys.ack1(cpu);
                        let exp = refm.ack(cpu, true);
                        assert_eq!(
                            got, exp,
                            "seed={seed:#x} step={step} ack cpu={cpu}: real={got} ref={exp}"
                        );
                        if got != 1023 {
                            inflight[cpu].push(got);
                        }
                        last = format!("ack cpu={cpu} -> {got}");
                    }
                    // ---- EOI (mostly LIFO; sometimes nonsensical) ------------
                    51..=73 => {
                        let cpu = rng.below(N as u32) as usize;
                        let intid = if !inflight[cpu].is_empty() && rng.below(100) < 80 {
                            inflight[cpu].pop().unwrap()
                        } else {
                            // Nonsensical: EOI a random intid that may not be
                            // active (and may not even have been acked).
                            rng.below(MAX_SPIS)
                        };
                        sys.eoi1(cpu, intid);
                        refm.eoi(cpu, true, intid);
                        last = format!("eoi cpu={cpu} id={intid}");
                    }
                    // ---- raise a PPI (+ enable it) ---------------------------
                    74..=81 => {
                        let cpu = rng.below(N as u32) as usize;
                        let intid = 16 + rng.below(16);
                        sys.enable_ppis(cpu, 1 << intid);
                        refm.enable_ppis(cpu, 1 << intid);
                        sys.dist.raise_ppi(VpIndex::new(cpu as u32), intid);
                        refm.raise_ppi(cpu, intid);
                        last = format!("ppi cpu={cpu} id={intid}");
                    }
                    // ---- provision + raise an SPI (PE0-delivered) ------------
                    82..=88 => {
                        let intid = 32 + rng.below(MAX_SPIS - 32);
                        let pri = (rng.below(32) as u8) << 3;
                        sys.provision_spi(intid, pri);
                        sys.dist.set_pending(intid, true);
                        refm.provision_spi(intid, pri);
                        refm.raise_spi(intid);
                        last = format!("spi id={intid} p={pri:#x}");
                    }
                    // ---- set an SGI/PPI priority -----------------------------
                    89..=92 => {
                        let cpu = rng.below(N as u32) as usize;
                        let intid = rng.below(32);
                        let pri = (rng.below(32) as u8) << 3;
                        sys.set_sgi_ppi_priority(cpu, intid, pri);
                        refm.set_sgi_ppi_priority(cpu, intid, pri);
                        last = format!("prio cpu={cpu} id={intid} p={pri:#x}");
                    }
                    // ---- rewrite GICR_IGROUPR0 (arbitrary) -------------------
                    93..=95 => {
                        let cpu = rng.below(N as u32) as usize;
                        let v = rng.next_u64() as u32;
                        sys.write_igroupr0(cpu, v);
                        refm.set_igroupr0(cpu, v);
                        last = format!("igroupr0 cpu={cpu} v={v:#x}");
                    }
                    // ---- reprogram PMR / BPR1 / CBPR -------------------------
                    _ => {
                        let cpu = rng.below(N as u32) as usize;
                        match rng.below(3) {
                            0 => {
                                let pmr = if rng.boolean() {
                                    0xff
                                } else {
                                    (rng.below(32) as u8) << 3
                                };
                                sys.write_cpuif(cpu, SystemReg::ICC_PMR_EL1, pmr as u64);
                                refm.set_pmr(cpu, pmr);
                                last = format!("pmr cpu={cpu} v={pmr:#x}");
                            }
                            1 => {
                                let bpr1 = rng.below(8);
                                sys.write_cpuif(cpu, SystemReg::ICC_BPR1_EL1, bpr1 as u64);
                                // Real clamps BPR1 to >= MIN_BPR1 (3); mirror it.
                                refm.set_bpr1(cpu, (bpr1 as u8).max(3));
                                last = format!("bpr1 cpu={cpu} v={bpr1}");
                            }
                            _ => {
                                let cbpr = rng.boolean();
                                // ICC_CTLR_EL1: bit0 = CBPR, bit1 = EOImode(=0).
                                sys.write_cpuif(
                                    cpu,
                                    SystemReg::ICC_CTLR_EL1,
                                    if cbpr { 1 } else { 0 },
                                );
                                refm.set_cbpr(cpu, cbpr);
                                last = format!("cbpr cpu={cpu} v={cbpr}");
                            }
                        }
                    }
                }
                check_equiv(&sys, &refm, seed, step, &last);
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Layer 3: real-thread concurrency stress.
//
// One `Arc<Distributor>` shared across N genuine OS threads, one thread per CPU
// owning that CPU's `Redistributor`. Threads storm SGIs (targeted + broadcast)
// at each other and raise their own PPIs while continuously servicing their own
// interrupts, exercising the real lock discipline: the lockless atomic `pending`
// word (cross-thread `raise`) against each redistributor's mutex (ack/eoi/config)
// and the distributor mutex (SPI/state).
//
// Two independent hang detectors turn a livelock or deadlock into a test
// FAILURE rather than an actual hang:
//   * per-thread bounded drain loops assert the core livelock invariant
//     directly — "if `irq_pending()` is true, `ICC_IAR1` must NOT ack 1023
//     (spurious)" — and cap their iteration count; and
//   * the main thread joins the workers through an `mpsc` channel with a
//     wall-clock `recv_timeout`, so a mutex deadlock (no worker ever completes)
//     fails loudly instead of wedging the test binary.
//
// This is the direct, generalized analogue of the nondeterministic `-p 4`
// Windows-boot livelock (`pending` floods, guest never drains): here we flood
// `pending` from every direction and prove the model always drains to
// quiescence.
//
// Discipline that keeps the livelock invariant airtight under concurrency: a
// thread only ever mutates its OWN redistributor (config + ack + eoi), and keeps
// its own PMR/grpen/group stable during a service pass; other threads only
// atomically *raise* (add pending), which can never make an observed-pending
// interrupt undeliverable. So `irq_pending(i)` true genuinely implies `ack(i)`
// must succeed.
// -----------------------------------------------------------------------------
#[cfg(test)]
mod threaded {
    use super::*;

    fn build_online(n: usize, max_spis: u32) -> (Distributor, Vec<Redistributor>) {
        let mut sys = Sys::new(n, max_spis);
        sys.online_all();
        let Sys { dist, redists, .. } = sys;
        (dist, redists)
    }

    #[test]
    fn smp_sgi_storm_drains() {
        use std::sync::Arc;
        use std::sync::Barrier;
        use std::sync::mpsc;
        use std::time::Duration;

        const N: usize = 4;
        const ROUNDS: usize = 60_000;

        let (dist, mut redists) = build_online(N, 96);
        let dist = Arc::new(dist);
        let barrier = Arc::new(Barrier::new(N));
        let (tx, rx) = mpsc::channel();

        // Hand thread i its own redistributor (index i).
        redists.reverse();
        let mut handles = Vec::new();
        for i in 0..N {
            let dist = dist.clone();
            let barrier = barrier.clone();
            let tx = tx.clone();
            let mut r = redists.pop().unwrap();
            handles.push(std::thread::spawn(move || {
                let mut rng =
                    Rng::new(0xA11CE ^ (i as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15));
                let mut inflight: Vec<u32> = Vec::new();

                for _ in 0..ROUNDS {
                    // Vary our own SGI/PPI priorities (affects ordering, not
                    // deliverability — keeps the livelock invariant valid).
                    if rng.below(8) == 0 {
                        let intid = rng.below(32);
                        let pri = (rng.below(32) as u8) << 3;
                        r.shared
                            .write(SGI_FRAME + IPRIORITYR0 + u64::from(intid), &[pri]);
                    }
                    // Enable + raise a PPI on ourselves.
                    if rng.below(3) == 0 {
                        let ppi = 16 + rng.below(16);
                        r.shared
                            .write(SGI_FRAME + ISENABLER0, &(1u32 << ppi).to_ne_bytes());
                        r.raise(ppi);
                    }
                    // Storm SGIs at random targets (and sometimes broadcast).
                    // Always send at least one so the threads stay contended.
                    for _ in 0..1 + rng.below(4) {
                        let intid = rng.below(16);
                        let raw = if rng.below(4) == 0 {
                            sgi1r_broadcast(intid)
                        } else {
                            sgi1r_targeted(intid, rng.below(N as u32) as usize)
                        };
                        dist.write_sysreg(&mut r, SystemReg::ICC_SGI1R_EL1, raw, no_wake);
                    }
                    // Service everything currently deliverable, then EOI (LIFO).
                    let mut guard = 0;
                    while dist.irq_pending(&r) {
                        let intid =
                            dist.read_sysreg(&mut r, SystemReg::ICC_IAR1_EL1).unwrap() as u32;
                        assert_ne!(
                            intid,
                            1023,
                            "LIVELOCK cpu={i}: irq_pending()=true but ICC_IAR1 acked 1023 \
                             (spurious); pending={:#x} active={:#x}",
                            r.ppi_diag().pending,
                            r.ppi_diag().active
                        );
                        inflight.push(intid);
                        guard += 1;
                        assert!(guard < 4096, "cpu={i}: service loop failed to converge");
                    }
                    while let Some(intid) = inflight.pop() {
                        dist.write_sysreg(
                            &mut r,
                            SystemReg::ICC_EOIR1_EL1,
                            u64::from(intid),
                            no_wake,
                        );
                    }
                }

                // No more sends after everyone crosses the barrier; drain to
                // quiescence under a bounded spin (a real livelock would spin
                // forever -> the cap fires).
                barrier.wait();
                let mut spins = 0;
                while dist.irq_pending(&r) {
                    let intid = dist.read_sysreg(&mut r, SystemReg::ICC_IAR1_EL1).unwrap() as u32;
                    assert_ne!(
                        intid, 1023,
                        "LIVELOCK(drain) cpu={i}: irq_pending()=true but ack spurious (1023)"
                    );
                    dist.write_sysreg(&mut r, SystemReg::ICC_EOIR1_EL1, u64::from(intid), no_wake);
                    spins += 1;
                    assert!(
                        spins < 100_000,
                        "cpu={i}: drain did not converge (livelock)"
                    );
                }

                let d = r.ppi_diag();
                assert_eq!(d.pending, 0, "cpu={i}: residual pending {:#x}", d.pending);
                assert_eq!(d.active, 0, "cpu={i}: residual active {:#x}", d.active);
                assert_eq!(d.icc_ap1r0, 0, "cpu={i}: residual apr1 {:#x}", d.icc_ap1r0);
                assert_eq!(d.icc_ap0r0, 0, "cpu={i}: residual apr0 {:#x}", d.icc_ap0r0);

                tx.send(i).unwrap();
            }));
        }
        drop(tx);

        for _ in 0..N {
            rx.recv_timeout(Duration::from_secs(30))
                .expect("DEADLOCK/LIVELOCK: a CPU thread failed to reach quiescence within 30s");
        }
        for h in handles {
            h.join()
                .expect("a CPU thread panicked (invariant violated)");
        }
    }
}

// -----------------------------------------------------------------------------
// Layer 4: spec property tests.
//
// Targeted assertions of individual GICv3 CPU-interface properties (ARM IHI
// 0069 §4.8) for the `GICD_CTLR.DS = 1` / all-Non-secure-Group-1 configuration
// OpenVMM-on-HVF uses. These lock in the semantics the differential fuzzer keeps
// the two models agreeing on, and — crucially — PIN and DOCUMENT the two places
// where the current model deliberately deviates from the letter of the spec, so
// the deviations are visible, deliberate, and regression-guarded rather than
// latent. Both deviations are benign for the guests we run (see each test), and
// are tracked for the with-user triage before any delivery-semantics change.
// -----------------------------------------------------------------------------
#[cfg(test)]
mod properties {
    use super::refmodel::RefGic;
    use super::*;
    use aarch64defs::gic::GicdCtlr;

    const ICENABLER0_OFF: u64 = 0x0180;

    /// Raise SGI `intid` on `cpu` by targeting an ICC_SGI1R at that CPU itself.
    fn self_sgi(sys: &mut Sys, cpu: usize, intid: u32) {
        sys.send_sgi1r(cpu, sgi1r_targeted(intid, cpu));
    }

    // §4.8.6 Priority masking: an interrupt is signalled only when its priority
    // is strictly higher (numerically lower) than ICC_PMR_EL1.
    #[test]
    fn pmr_masks_by_priority() {
        let mut sys = Sys::new(1, 96);
        sys.online_all();
        sys.write_cpuif(0, SystemReg::ICC_PMR_EL1, 0x40);
        sys.set_sgi_ppi_priority(0, 5, 0x80); // >= PMR -> masked
        sys.set_sgi_ppi_priority(0, 3, 0x20); // <  PMR -> deliverable
        self_sgi(&mut sys, 0, 5);
        self_sgi(&mut sys, 0, 3);
        assert!(sys.pending(0), "the priority-0x20 SGI must pass PMR=0x40");
        assert_eq!(sys.ack1(0), 3, "the deliverable SGI is acknowledged");
        sys.eoi1(0, 3);
        assert!(
            !sys.pending(0),
            "the priority-0x80 SGI stays masked at PMR=0x40"
        );
        sys.write_cpuif(0, SystemReg::ICC_PMR_EL1, 0xff);
        assert!(sys.pending(0), "raising PMR unmasks it");
        assert_eq!(sys.ack1(0), 5);
    }

    // §4.8 acknowledge selects the highest-priority pending interrupt; ties are
    // broken by the lowest INTID.
    #[test]
    fn ack_selects_highest_priority_then_lowest_intid() {
        let mut sys = Sys::new(1, 96);
        sys.online_all();
        sys.set_sgi_ppi_priority(0, 7, 0x80);
        sys.set_sgi_ppi_priority(0, 9, 0x40);
        self_sgi(&mut sys, 0, 7);
        self_sgi(&mut sys, 0, 9);
        assert_eq!(sys.ack1(0), 9, "0x40 outranks 0x80");
        sys.eoi1(0, 9);
        assert_eq!(sys.ack1(0), 7);
        sys.eoi1(0, 7);

        // Equal priority -> lowest INTID wins.
        sys.set_sgi_ppi_priority(0, 6, 0x40);
        sys.set_sgi_ppi_priority(0, 4, 0x40);
        self_sgi(&mut sys, 0, 6);
        self_sgi(&mut sys, 0, 4);
        assert_eq!(sys.ack1(0), 4, "ties break to the lower INTID");
    }

    // §4.8.5 Preemption: once an interrupt is active, only a strictly
    // higher-group-priority interrupt is signalled; an equal-group-priority one
    // is not (no self-preemption).
    #[test]
    fn preemption_respects_running_priority() {
        let mut sys = Sys::new(1, 96);
        sys.online_all();
        sys.set_sgi_ppi_priority(0, 8, 0x80);
        self_sgi(&mut sys, 0, 8);
        assert_eq!(sys.ack1(0), 8, "running priority is now 0x80");

        // Same group-priority bucket -> must NOT preempt.
        sys.set_sgi_ppi_priority(0, 10, 0x84); // &0xF8 == 0x80
        self_sgi(&mut sys, 0, 10);
        assert!(!sys.pending(0), "equal group priority does not preempt");

        // Strictly higher priority -> preempts.
        sys.set_sgi_ppi_priority(0, 4, 0x40);
        self_sgi(&mut sys, 0, 4);
        assert!(sys.pending(0), "a higher-priority interrupt preempts");
        assert_eq!(sys.ack1(0), 4);
    }

    // A targeted ICC_SGI1R (IRM = 0) reaches only the addressed affinity, and a
    // broadcast (IRM = 1) reaches every PE except the sender.
    #[test]
    fn sgi_routing_targeted_and_broadcast() {
        let mut sys = Sys::new(4, 96);
        sys.online_all();
        sys.send_sgi1r(0, sgi1r_targeted(6, 2));
        assert!(sys.pending(2), "targeted SGI reaches the addressed PE");
        for cpu in [0, 1, 3] {
            assert!(!sys.pending(cpu), "targeted SGI must not reach PE {cpu}");
        }
        sys.ack1(2);
        sys.eoi1(2, 6);

        sys.send_sgi1r(1, sgi1r_broadcast(7));
        assert!(!sys.pending(1), "broadcast excludes the sender");
        for cpu in [0, 2, 3] {
            assert!(sys.pending(cpu), "broadcast reaches PE {cpu}");
        }
    }

    // Hyper-V's vGIC (and thus our model, matching it) treats SGIs 0..15 as
    // permanently enabled: ICENABLER0 cannot disable them.
    #[test]
    fn sgis_are_permanently_enabled() {
        let mut sys = Sys::new(1, 96);
        sys.online_all();
        // Attempt to disable SGI 4 via GICR_ICENABLER0.
        sys.redists[0]
            .shared
            .write(SGI_FRAME + ICENABLER0_OFF, &(1u32 << 4).to_ne_bytes());
        self_sgi(&mut sys, 0, 4);
        assert!(sys.pending(0), "SGI 4 stays enabled despite ICENABLER0");
        assert_eq!(sys.ack1(0), 4);
    }

    // -------------------------------------------------------------------------
    // FINDINGS — deliberate, pinned deviations from ARM IHI 0069 §4.8.
    // -------------------------------------------------------------------------

    /// FINDING #1: `Redistributor::admit` does not consult `ICC_IGRPEN1_EL1`,
    /// so a pending Group-1 interrupt is still reported deliverable while the
    /// guest has Group 1 *disabled* at the CPU interface. Per §4.8.5 the CPU
    /// interface must not signal a group's interrupts when that group is
    /// disabled. This is BENIGN for our guests because Hyper-V's synthetic vGIC
    /// keeps Group 1 enabled and Windows/Linux enable it early and leave it on;
    /// the reference model gates on grpen (spec-correct), and the differential
    /// fuzzer keeps IGRPEN1 = 1 throughout so the gap never causes a divergence
    /// there. Fixing it changes delivery semantics and so is gated on re-running
    /// the AZL-3 + Windows boot suites (with-user triage), not autopilot.
    ///
    /// This test pins the CURRENT behavior so the deviation is explicit and any
    /// future change is caught.
    #[test]
    fn finding_group1_disable_not_gated_in_delivery() {
        let mut sys = Sys::new(1, 96);
        sys.online_all();
        sys.write_cpuif(0, SystemReg::ICC_IGRPEN1_EL1, 0); // disable Group 1
        self_sgi(&mut sys, 0, 5);
        assert!(
            sys.pending(0),
            "DEVIATION pinned: model still delivers Group 1 with IGRPEN1=0 \
             (spec: should be gated). If this now fails, the grpen gate was \
             added — update the reference/differential and re-run boot gates."
        );
    }

    /// FINDING #2: `Distributor::best_spi` does not consult
    /// `GICD_CTLR.EnableGrp1`, so a Group-1 SPI is forwarded to a PE even while
    /// the distributor has Group 1 forwarding *disabled*. Per §4.8 a disabled
    /// distributor group must not forward. Same benign rationale (guests enable
    /// the distributor groups before expecting delivery); the reference gates on
    /// it and the differential keeps both distributor groups enabled. Pinned
    /// here as a deliberate deviation.
    #[test]
    fn finding_gicd_ctlr_disable_not_gated_for_spi() {
        let mut sys = Sys::new(1, 96);
        sys.online_all();
        // Provision + raise a Group-1 SPI, then disable GICD Group 1 forwarding.
        sys.provision_spi(40, 0x40);
        sys.dist.set_pending(40, true);
        let ctlr: u32 = GicdCtlr::new()
            .with_enable_grp0(true)
            .with_enable_grp1(false)
            .into();
        sys.dist.write(0 /* GICD_CTLR */, &ctlr.to_ne_bytes());
        assert!(
            sys.pending(0),
            "DEVIATION pinned: model still forwards a Group-1 SPI with \
             GICD_CTLR.EnableGrp1=0 (spec: should be gated). If this now fails, \
             the distributor-enable gate was added — update the model peers."
        );
    }

    /// The independent reference model DOES gate Group 1 on `ICC_IGRPEN1_EL1`
    /// (spec-correct) — it is the complement of
    /// [`finding_group1_disable_not_gated_in_delivery`] and is what makes the
    /// reference a valid oracle for a future gating fix: a corrected real model
    /// would match the reference here.
    #[test]
    fn reference_model_gates_group1_enable() {
        let mut refm = RefGic::new(1, 96);
        refm.online_all();
        refm.send_sgi(0, sgi1r_targeted(5, 0));
        assert!(refm.irq_pending(0), "enabled Group 1: reference delivers");
        refm.set_grpen1(0, false);
        assert!(
            !refm.irq_pending(0),
            "reference gates Group 1 at the CPU interface (spec-correct)"
        );
    }
}
