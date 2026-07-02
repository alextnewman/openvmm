// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! # Each vCPU as an independent asynchronous actor: the HVF wake protocol.
//!
//! This is the whole per-vCPU wake/park state machine for the Hypervisor.framework
//! backend, isolated behind a small, race-free interface. It exists to make one
//! property true *by construction*: a vCPU never blocks while it has undelivered
//! work, no matter how producers (other vCPUs, device threads, the synic) race
//! against its decision to idle.
//!
//! ## Grounded in Apple HVF's actual primitives
//!
//! Apple's in-kernel GIC cannot inject a live per-vCPU PPI/SGI, so all interrupt
//! delivery is the VMM's job. Apple's own GIC architect described the required
//! model verbatim: *"the source exits to the VMM, which requests the target vCPU
//! to exit, records the pending interrupt to its virtual GIC state, and returns."*
//! That is exactly [`VpActor::notify`]: the caller records work into the virtual
//! GIC / synic state, then calls `notify`, which requests the target to observe
//! it. Two HVF facts make this lossless when modeled honestly:
//!
//! * `hv_vcpus_exit` is a **sticky, kernel-mediated latch**: if the target is not
//!   currently in `hv_vcpu_run`, its next entry returns immediately without
//!   entering the guest. A wake aimed at a *running* vCPU therefore cannot be
//!   lost — [`VpActor::cancel_run`] is the RUNNING-state wake.
//! * `hv_vcpu_set_pending_interrupt` is **per-run level input**, re-supplied on
//!   every entry, so the consumer recomputes deliverability from virtual GIC
//!   state on every pass ([`VpActor::begin_pass`] + the caller's re-scan).
//!
//! ## Two real states, and the fused word that keeps them exclusive
//!
//! A vCPU is only ever RUNNING (executing the guest or the decision loop — woken
//! lock-free by the latch) or PARKED (blocked as a pending async task — woken by
//! its stored [`Waker`]). There is no third "imagined" state: the earlier design
//! parked in an async executor reachable by neither mechanism, which forced a
//! `kick = wake + cancel_run` shotgun and a 2 ms polling backstop. Both are gone.
//!
//! The crux — proven exhaustively with `loom` in the companion proof crate — is
//! that the phase (RUNNING / PARKING / PARKED) and the "must re-check" latch live
//! in **one atomic `ctl` word**. Every cross-CPU transition is a single-location
//! RMW, which is totally ordered and reads the immediately-preceding value, so
//! "a producer latches MUST_EXIT" and "the consumer commits to PARKED" are
//! **mutually exclusive**: whichever RMW lands first in the modification order
//! wins, with no fence and no fragile `SeqCst`. The per-vCPU lock is taken only
//! to hand off the waker to a genuinely-parked vCPU; the running path is
//! lock-free. Crucially, this same-location edge also supplies the happens-before
//! that the software GIC's `pending` word (published `Relaxed`) otherwise lacks:
//! a consumer that observes MUST_EXIT is guaranteed to observe the work the
//! producer published before setting it.

use crate::abi;
use parking_lot::Mutex;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::task::Waker;

/// vCPU phase, held in the low bits of the fused [`VpActor::ctl`] word.
const RUNNING: u32 = 0;
const PARKING: u32 = 1;
const PARKED: u32 = 2;
const PHASE_MASK: u32 = 0b11;

/// The sticky "must re-check" latch bit, layered above the phase. Set by any
/// producer in [`VpActor::notify`]; consumed by the consumer's next
/// [`VpActor::begin_pass`] (or it fails the consumer's park commit).
const MUST_EXIT: u32 = 0b100;

/// Sentinel `ctl`-carried vcpu id meaning "no live HVF vcpu yet" — matches the
/// historical `!0` guard so [`VpActor::cancel_run`] is a no-op before the vCPU
/// thread has created its `hv_vcpu`.
const NO_VCPU: u64 = !0;

/// The outcome of a consumer's attempt to idle-park.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ParkDecision {
    /// Committed to the async block: the caller must return `Poll::Pending`. The
    /// vCPU will be re-polled when a producer wakes the stored waker (or when an
    /// independently-registered timer deadline fires).
    Parked,
    /// Work raced in (or the latch fired) during the parking window: the caller
    /// must re-scan its work sources and keep running. Never parks with work
    /// pending.
    Rescan,
}

/// The per-vCPU wake actor: a fused phase+latch `ctl` word, the live HVF vcpu id
/// for the running-state wake, and the one lock used solely to hand a waker to a
/// parked vCPU.
#[derive(Debug)]
pub(crate) struct VpActor {
    /// Fused phase (`RUNNING`/`PARKING`/`PARKED`) + [`MUST_EXIT`] latch. Every
    /// cross-thread transition is a single RMW on this location.
    ctl: AtomicU32,
    /// The HVF `hv_vcpu` id, or [`NO_VCPU`]. Set once when the vCPU thread starts.
    vcpu: AtomicU64,
    /// The parked task's waker. Written by the consumer as it commits to PARKED
    /// and taken by exactly one producer as it wakes — the lock provides the
    /// happens-before for that handoff. `None` whenever the vCPU is not parked.
    park: Mutex<Option<Waker>>,
}

impl VpActor {
    pub(crate) fn new() -> Self {
        Self {
            ctl: AtomicU32::new(RUNNING),
            vcpu: AtomicU64::new(NO_VCPU),
            park: Mutex::new(None),
        }
    }

    /// Records the live HVF vcpu id, enabling the running-state (`cancel_run`)
    /// wake. Called once from the vCPU thread after `hv_vcpu_create`.
    pub(crate) fn set_vcpu(&self, vcpu: u64) {
        self.vcpu.store(vcpu, Ordering::Relaxed);
    }

    /// Forces the target out of `hv_vcpu_run` via the sticky `hv_vcpus_exit`
    /// latch. If the target is not currently running the guest, the latch simply
    /// makes its next entry return immediately — it cannot be lost. Also used by
    /// the generic `Partition::request_yield` path to make the vCPU yield.
    pub(crate) fn cancel_run(&self) {
        let vcpu = self.vcpu.load(Ordering::Relaxed);
        if vcpu != NO_VCPU {
            // SAFETY: `&vcpu` points to a list of vcpu ids of length 1.
            unsafe { abi::hv_vcpus_exit(&vcpu, 1) }.chk().unwrap();
        }
    }

    /// Producer path: work (an interrupt in virtual GIC state, a synic message, a
    /// pending `CPU_ON`) has just been published for this vCPU; request it to
    /// observe it. The publish MUST be sequenced before this call.
    ///
    /// * target RUNNING → latch `MUST_EXIT` and `cancel_run` so its in-guest run
    ///   (or its next entry) returns and re-scans. Lock-free.
    /// * target PARKING → latch `MUST_EXIT`; the consumer's commit CAS will now
    ///   fail and it will self-rescue. Lock-free.
    /// * target PARKED → hand off and fire the stored waker to re-poll the task.
    pub(crate) fn notify(&self) {
        let prev = self.ctl.fetch_or(MUST_EXIT, Ordering::AcqRel);
        match prev & PHASE_MASK {
            RUNNING => self.cancel_run(),
            PARKING => {}
            PARKED => self.wake_parked(),
            _ => unreachable!("invalid vcpu phase"),
        }
    }

    /// Wakes a parked vCPU: return it to RUNNING and fire its waker under the
    /// lock, so exactly one racing producer performs the wake and later
    /// producers take the lock-free running path.
    fn wake_parked(&self) {
        let waker = {
            let mut park = self.park.lock();
            self.ctl.store(RUNNING, Ordering::Release);
            park.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Consumer path: begin a fresh decision/scan pass. Resets the phase to
    /// RUNNING and consumes the `MUST_EXIT` latch in one RMW, establishing the
    /// happens-before under which the subsequent work re-scan observes every
    /// producer's published work. Returns whether the latch had fired (for
    /// diagnostics only — the caller re-scans unconditionally regardless).
    pub(crate) fn begin_pass(&self) -> bool {
        self.ctl.swap(RUNNING, Ordering::AcqRel) & MUST_EXIT != 0
    }

    /// Consumer path: the guest is idle and the caller wants to block. Attempts
    /// to commit to the async park; `still_idle` re-checks *all* work sources
    /// inside the parking window (its result may be racy — the fused `ctl` edge
    /// is the actual safety backstop, so a stale "idle" can never lose a wake).
    ///
    /// On [`ParkDecision::Parked`] the caller must return `Poll::Pending`; the
    /// stored `waker` will be fired by the next producer. On
    /// [`ParkDecision::Rescan`] the caller must loop and re-scan.
    pub(crate) fn try_park(
        &self,
        waker: &Waker,
        still_idle: impl FnOnce() -> bool,
    ) -> ParkDecision {
        // Announce PARKING. Fails iff a producer already latched MUST_EXIT (ctl
        // is no longer exactly RUNNING) — in which case re-scan.
        if self
            .ctl
            .compare_exchange(RUNNING, PARKING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.ctl.store(RUNNING, Ordering::Release);
            return ParkDecision::Rescan;
        }

        // Cheap pre-commit re-check of all work sources.
        if !still_idle() {
            self.ctl.store(RUNNING, Ordering::Release);
            return ParkDecision::Rescan;
        }

        // Commit under the lock. Store the waker before flipping to PARKED so a
        // producer that later observes PARKED (under the same lock) always sees
        // it. The CAS PARKING->PARKED succeeds only if MUST_EXIT is still clear;
        // if a producer latched it in the meantime the CAS fails and we rescue.
        let mut park = self.park.lock();
        match self
            .ctl
            .compare_exchange(PARKING, PARKED, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {
                *park = Some(waker.clone());
                ParkDecision::Parked
            }
            Err(_) => {
                drop(park);
                self.ctl.store(RUNNING, Ordering::Release);
                ParkDecision::Rescan
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::task::Wake;

    /// A test waker that records how many times it was fired.
    struct CountingWaker(AtomicU32);

    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn counting() -> (Waker, Arc<CountingWaker>) {
        let inner = Arc::new(CountingWaker(AtomicU32::new(0)));
        (Waker::from(inner.clone()), inner)
    }

    fn fired(w: &Arc<CountingWaker>) -> u32 {
        w.0.load(Ordering::Relaxed)
    }

    #[test]
    fn parks_cleanly_when_idle() {
        let a = VpActor::new();
        let (waker, count) = counting();
        assert_eq!(a.try_park(&waker, || true), ParkDecision::Parked);
        // Parked, not yet woken.
        assert_eq!(fired(&count), 0);
        assert_eq!(a.ctl.load(Ordering::Relaxed) & PHASE_MASK, PARKED);
    }

    #[test]
    fn rescans_when_work_present() {
        let a = VpActor::new();
        let (waker, _count) = counting();
        // still_idle=false models work racing in during the window.
        assert_eq!(a.try_park(&waker, || false), ParkDecision::Rescan);
        assert_eq!(a.ctl.load(Ordering::Relaxed) & PHASE_MASK, RUNNING);
    }

    #[test]
    fn notify_wakes_a_parked_vcpu() {
        let a = VpActor::new();
        let (waker, count) = counting();
        assert_eq!(a.try_park(&waker, || true), ParkDecision::Parked);
        a.notify();
        // The parked waker fired exactly once, and the vCPU is RUNNING again.
        assert_eq!(fired(&count), 1);
        assert_eq!(a.ctl.load(Ordering::Relaxed) & PHASE_MASK, RUNNING);
    }

    #[test]
    fn notify_while_running_does_not_touch_the_waker() {
        let a = VpActor::new();
        // No park: notify must take the (lock-free) running path. vcpu==NO_VCPU
        // so cancel_run is a no-op, but MUST_EXIT is latched for the next pass.
        a.notify();
        assert!(
            a.begin_pass(),
            "begin_pass must observe the latched MUST_EXIT"
        );
        // Latch consumed; a second pass sees nothing.
        assert!(!a.begin_pass());
    }

    #[test]
    fn latch_set_before_park_forces_rescan() {
        let a = VpActor::new();
        let (waker, count) = counting();
        // Producer latches while the consumer is RUNNING...
        a.notify();
        // ...so the consumer's park attempt must rescue rather than block.
        assert_eq!(a.try_park(&waker, || true), ParkDecision::Rescan);
        assert_eq!(fired(&count), 0);
    }

    #[test]
    fn double_notify_on_parked_wakes_once() {
        let a = VpActor::new();
        let (waker, count) = counting();
        assert_eq!(a.try_park(&waker, || true), ParkDecision::Parked);
        a.notify();
        a.notify();
        // Only the first producer takes the waker; the second sees RUNNING.
        assert_eq!(fired(&count), 1);
    }

    #[test]
    fn re_park_after_wake_uses_the_fresh_waker() {
        let a = VpActor::new();
        let (w1, c1) = counting();
        assert_eq!(a.try_park(&w1, || true), ParkDecision::Parked);
        a.notify();
        assert_eq!(fired(&c1), 1);

        // Re-park with a different waker; the next notify must fire the new one.
        let (w2, c2) = counting();
        assert_eq!(a.try_park(&w2, || true), ParkDecision::Parked);
        a.notify();
        assert_eq!(fired(&c2), 1);
        assert_eq!(fired(&c1), 1, "the stale waker must not fire again");
    }
}
