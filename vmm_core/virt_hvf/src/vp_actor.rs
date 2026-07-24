// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Race-free wake and park coordination for one HVF vCPU.
//!
//! Producers publish work before calling [`VpActor::notify`]. Every notification
//! advances a sequence, forces the vCPU out of `hv_vcpu_run`, and wakes a parked
//! task. The consumer may park only if the sequence did not change during its
//! work scan.

use crate::abi;
use parking_lot::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::task::Waker;

/// The outcome of a consumer's attempt to idle-park.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ParkDecision {
    /// The caller must return `Poll::Pending`.
    Parked,
    /// Work raced with the park transition; the caller must rescan.
    Rescan,
}

#[derive(Copy, Clone, Debug)]
pub(crate) struct ScanToken(u64);

#[derive(Debug)]
pub(crate) struct VpActor {
    sequence: AtomicU64,
    vcpu: Mutex<Option<u64>>,
    park: Mutex<Option<Waker>>,
}

impl VpActor {
    pub(crate) fn new() -> Self {
        Self {
            sequence: AtomicU64::new(0),
            vcpu: Mutex::new(None),
            park: Mutex::new(None),
        }
    }

    pub(crate) fn set_vcpu(&self, vcpu: u64) {
        *self.vcpu.lock() = Some(vcpu);
    }

    /// Serializes vCPU destruction and replacement against concurrent exits.
    pub(crate) fn replace_vcpu<T, E>(
        &self,
        replace: impl FnOnce() -> Result<(u64, T), E>,
    ) -> Result<T, E> {
        let mut published = self.vcpu.lock();
        *published = None;
        let (vcpu, value) = replace()?;
        *published = Some(vcpu);
        Ok(value)
    }

    /// Unpublishes and destroys the vCPU while excluding concurrent exits.
    pub(crate) fn remove_vcpu<E>(&self, remove: impl FnOnce() -> Result<(), E>) -> Result<(), E> {
        let mut published = self.vcpu.lock();
        *published = None;
        self.park.lock().take();
        remove()
    }

    pub(crate) fn try_cancel_run(&self) -> Result<(), abi::HvfError> {
        let vcpu = self.vcpu.lock();
        if let Some(vcpu) = *vcpu {
            // SAFETY: `&vcpu` points to a list of vcpu ids of length 1.
            unsafe { abi::hv_vcpus_exit(&vcpu, 1) }.chk()?;
        }
        Ok(())
    }

    pub(crate) fn cancel_run(&self) {
        if let Err(err) = self.try_cancel_run() {
            tracing::error!(?err, "failed to force vcpu exit");
        }
    }

    /// Notifies the vCPU after work has been published.
    pub(crate) fn notify(&self) {
        self.sequence.fetch_add(1, Ordering::Release);
        self.cancel_run();

        let waker = self.park.lock().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Captures the notification sequence before scanning persistent work.
    pub(crate) fn begin_scan(&self) -> ScanToken {
        ScanToken(self.sequence.load(Ordering::Acquire))
    }

    fn clear_park(&self, waker: &Waker) {
        let mut park = self.park.lock();
        if park
            .as_ref()
            .is_some_and(|registered| registered.will_wake(waker))
        {
            *park = None;
        }
    }

    /// Attempts to park after scanning and rechecking all work sources.
    pub(crate) fn try_park(
        &self,
        scan: ScanToken,
        waker: &Waker,
        still_idle: impl FnOnce() -> bool,
    ) -> ParkDecision {
        *self.park.lock() = Some(waker.clone());

        let idle = still_idle();
        let unchanged = self.sequence.load(Ordering::Acquire) == scan.0;
        if idle && unchanged {
            ParkDecision::Parked
        } else {
            self.clear_park(waker);
            ParkDecision::Rescan
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU32;
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
        let scan = a.begin_scan();

        assert_eq!(a.try_park(scan, &waker, || true), ParkDecision::Parked);
        assert_eq!(fired(&count), 0);
    }

    #[test]
    fn rescans_when_work_present() {
        let a = VpActor::new();
        let (waker, count) = counting();
        let scan = a.begin_scan();

        assert_eq!(a.try_park(scan, &waker, || false), ParkDecision::Rescan);
        a.notify();
        assert_eq!(fired(&count), 0);
    }

    #[test]
    fn notify_wakes_a_parked_vcpu() {
        let a = VpActor::new();
        let (waker, count) = counting();
        let scan = a.begin_scan();

        assert_eq!(a.try_park(scan, &waker, || true), ParkDecision::Parked);
        a.notify();
        assert_eq!(fired(&count), 1);
    }

    #[test]
    fn notification_before_park_forces_rescan() {
        let a = VpActor::new();
        let (waker, count) = counting();
        let scan = a.begin_scan();

        a.notify();
        assert_eq!(a.try_park(scan, &waker, || true), ParkDecision::Rescan);
        assert_eq!(fired(&count), 0);
    }

    #[test]
    fn notify_during_idle_recheck_forces_rescan() {
        let a = VpActor::new();
        let (waker, count) = counting();
        let scan = a.begin_scan();

        assert_eq!(
            a.try_park(scan, &waker, || {
                a.notify();
                true
            }),
            ParkDecision::Rescan
        );
        assert_eq!(fired(&count), 1);
    }

    #[test]
    fn double_notify_on_parked_wakes_once() {
        let a = VpActor::new();
        let (waker, count) = counting();
        let scan = a.begin_scan();

        assert_eq!(a.try_park(scan, &waker, || true), ParkDecision::Parked);
        a.notify();
        a.notify();
        assert_eq!(fired(&count), 1);
    }

    #[test]
    fn re_park_after_external_wake_uses_the_fresh_waker() {
        let a = VpActor::new();
        let (w1, c1) = counting();
        let scan = a.begin_scan();

        assert_eq!(a.try_park(scan, &w1, || true), ParkDecision::Parked);
        w1.wake_by_ref();
        assert_eq!(fired(&c1), 1);

        let (w2, c2) = counting();
        let scan = a.begin_scan();
        assert_eq!(a.try_park(scan, &w2, || true), ParkDecision::Parked);
        a.notify();

        assert_eq!(fired(&c2), 1);
        assert_eq!(fired(&c1), 1);
    }

    #[test]
    fn remove_vcpu_clears_parked_waker() {
        let actor = VpActor::new();
        let (waker, _) = counting();
        let scan = actor.begin_scan();

        assert_eq!(actor.try_park(scan, &waker, || true), ParkDecision::Parked);
        actor.remove_vcpu(|| Ok::<_, ()>(())).unwrap();

        assert!(actor.park.lock().is_none());
    }
}
