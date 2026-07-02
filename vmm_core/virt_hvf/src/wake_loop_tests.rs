// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! # Synthetic integration test of the vCPU wake/park *loop* (not just the actor).
//!
//! [`crate::vp_actor::VpActor`] is proven lossless in isolation (its own unit
//! tests + the `loom_parker_proof` model). But the actor is only half the
//! contract: the `run_vp` poll loop wraps it in a *multi-source* decision pass —
//!
//! ```text
//! loop {
//!     actor.begin_pass();                 // clears the MUST_EXIT latch
//!     if cpu_on  { deliver; continue }    // PSCI CPU_ON        (latch-only)
//!     if synic   { deliver; continue }    // SynIC message      (latch-only)
//!     if gic_irq { inject;  ...      }     // virtual GIC IRQ    (latch + still_idle)
//!     if idle {
//!         if timer_due { deliver; continue }          // vmtime deadline (direct waker)
//!         match actor.try_park(waker, || !gic_irq) {  // still_idle rechecks ONLY the GIC
//!             Rescan => continue,
//!             Parked => return Pending,               // block on the waker
//!         }
//!     }
//!     run_guest();
//! }
//! ```
//!
//! The subtle, *non-obvious* property this exercises: the WFI park's `still_idle`
//! closure rechecks **only** the GIC pending state (`!gicd.irq_pending`). Every
//! other work source that can race the parking window — a SynIC message, a PSCI
//! `CPU_ON`, a re-armed timer — is covered **solely** by the fused `MUST_EXIT`
//! latch (each producer publishes its work and then calls [`VpActor::notify`]).
//! If that reliance were wrong for even one source, an idle vCPU would park on
//! undelivered work and sleep forever — precisely the class of hang the idle
//! hot-spin used to mask (the spin re-scanned every ~2 µs, papering over any lost
//! wake; a truly-parked vCPU does not).
//!
//! This harness models that loop against the **real** `VpActor` with **real OS
//! threads** and a real [`Waker`] (thread park/unpark, whose token is sticky —
//! faithfully modeling an async executor's edge-triggered-but-coalescing
//! readiness). It hammers all four sources concurrently and asserts the
//! **no-lost-wakeup** invariant: after every producer has published, the consumer
//! always drains all work (it is never left parked with work pending).
//!
//! A deliberately-broken control ([`harness_detects_lost_wakeup`]) proves the
//! detector has teeth: a classic publish-after-park-with-no-wake deterministically
//! trips the timeout.

use crate::vp_actor::ParkDecision;
use crate::vp_actor::VpActor;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::AcqRel;
use std::sync::atomic::Ordering::Acquire;
use std::sync::atomic::Ordering::Release;
use std::task::Wake;
use std::task::Waker;
use std::thread;
use std::time::Duration;
use std::time::Instant;

/// A [`Waker`] that unparks a specific OS thread — the test-harness stand-in for
/// the async runtime re-polling the vCPU task. `unpark`'s token is sticky, which
/// is exactly the coalescing "became ready" semantics a real `Waker` has.
struct ThreadWaker(thread::Thread);

impl Wake for ThreadWaker {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

/// Abstract per-vCPU work sources, mirroring the `run_vp` loop's inputs. Each is
/// a count of undelivered items; producers increment, the consumer drains.
#[derive(Default)]
struct Sources {
    /// Virtual GIC interrupts pending. The **only** source the WFI park's
    /// `still_idle` closure rechecks (`!gicd.irq_pending`).
    gic: AtomicU64,
    /// SynIC messages queued (`post_message`). Latch-only: not rechecked by
    /// `still_idle`, so its safety rests entirely on `notify`'s MUST_EXIT.
    synic: AtomicU64,
    /// PSCI `CPU_ON` requests. Latch-only, handled at the top of the pass.
    cpu_on: AtomicU64,
    /// A re-armed vmtime/vtimer deadline that has come due. Woken by the timer
    /// keeper firing the task waker *directly* (bypassing `notify`, exactly as
    /// core `vmtime` does), and consumed by the pre-park `poll_timeout` check.
    timer_due: AtomicBool,
    /// Total items the consumer has delivered (for the invariant check).
    delivered: AtomicU64,
}

/// Take one unit from `src` if available, counting it as delivered. Returns
/// whether an item was drained (the loop's "handled work, re-scan" signal).
fn drain(src: &AtomicU64, delivered: &AtomicU64) -> bool {
    let mut cur = src.load(Acquire);
    loop {
        if cur == 0 {
            return false;
        }
        match src.compare_exchange_weak(cur, cur - 1, AcqRel, Acquire) {
            Ok(_) => {
                delivered.fetch_add(1, AcqRel);
                return true;
            }
            Err(actual) => cur = actual,
        }
    }
}

/// One producer's publish of a single item into `src`, followed by the mandated
/// [`VpActor::notify`] (the "publish-then-request-exit" contract). Used for the
/// GIC / SynIC / CPU_ON sources.
fn produce_notify(src: &AtomicU64, actor: &VpActor) {
    src.fetch_add(1, Release);
    actor.notify();
}

/// The consumer: runs the multi-source decision loop against the real `VpActor`,
/// parking on the real waker when idle. Returns when `stop` is observed.
fn consumer_loop(actor: &VpActor, s: &Sources, stop: &AtomicBool, shared: &Mutex<Option<Waker>>) {
    let waker = Waker::from(Arc::new(ThreadWaker(thread::current())));
    // Publish a clone for the timer keeper (models vmtime holding the task waker).
    *shared.lock().unwrap() = Some(waker.clone());

    'outer: loop {
        // Poll phase: keep running passes until we commit to a park.
        loop {
            if stop.load(Acquire) {
                break 'outer;
            }
            actor.begin_pass();

            // Loop-top: PSCI CPU_ON (latch-only source).
            if drain(&s.cpu_on, &s.delivered) {
                continue;
            }
            // SynIC scan (latch-only source): deliver + re-scan.
            if drain(&s.synic, &s.delivered) {
                continue;
            }
            // Virtual GIC inject (latch + still_idle source).
            if drain(&s.gic, &s.delivered) {
                continue;
            }
            // Idle. Mirror the loop: check the armed timer deadline *before*
            // committing to the actor park.
            if s.timer_due.swap(false, AcqRel) {
                s.delivered.fetch_add(1, AcqRel);
                continue;
            }
            // still_idle rechecks ONLY the GIC — every other source relies on the
            // MUST_EXIT latch that `notify` set.
            match actor.try_park(&waker, || s.gic.load(Acquire) == 0) {
                ParkDecision::Rescan => continue,
                ParkDecision::Parked => break,
            }
        }

        if stop.load(Acquire) {
            break 'outer;
        }
        // Committed to the async park: block until a producer's `notify` wakes the
        // actor's stored waker, or the timer keeper fires the shared waker.
        thread::park();
    }
}

/// Wake and join the consumer once all work is accounted for (or on failure).
fn stop_consumer(actor: &VpActor, stop: &AtomicBool, consumer: thread::JoinHandle<()>) {
    stop.store(true, Release);
    // If the consumer is parked (actor PARKED) this wakes it; if it is RUNNING the
    // latch is harmless and the stop flag is observed on the next pass. Also
    // unpark its thread directly to cover a park that raced the stop store.
    let t = consumer.thread().clone();
    actor.notify();
    t.unpark();
    consumer.join().expect("consumer thread panicked");
}

/// The core property: across heavy concurrent production on all four sources, the
/// consumer never parks on undelivered work. Run many fresh-actor iterations so
/// the OS scheduler explores a wide range of publish/notify/park interleavings.
#[test]
fn wake_loop_never_strands_work() {
    // Tunable via env so we can crank it in a soak run without editing code.
    let iters: u64 = std::env::var("WAKE_LOOP_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3000);
    let producers_per_source: u64 = 3;
    let items_per_producer: u64 = 4;

    for iter in 0..iters {
        let actor = Arc::new(VpActor::new());
        let sources = Arc::new(Sources::default());
        let stop = Arc::new(AtomicBool::new(false));
        let shared_waker: Arc<Mutex<Option<Waker>>> = Arc::new(Mutex::new(None));

        let consumer = {
            let actor = actor.clone();
            let sources = sources.clone();
            let stop = stop.clone();
            let shared = shared_waker.clone();
            thread::spawn(move || consumer_loop(&actor, &sources, &stop, &shared))
        };

        // GIC / SynIC / CPU_ON producers all publish + notify.
        let mut producers = Vec::new();
        for _ in 0..producers_per_source {
            for pick in 0..3u8 {
                let actor = actor.clone();
                let sources = sources.clone();
                producers.push(thread::spawn(move || {
                    for _ in 0..items_per_producer {
                        let src = match pick {
                            0 => &sources.gic,
                            1 => &sources.synic,
                            _ => &sources.cpu_on,
                        };
                        produce_notify(src, &actor);
                        // Occasionally widen the race window against the park.
                        if fastrand_bit() {
                            thread::yield_now();
                        }
                    }
                }));
            }
        }

        // Timer keeper: arms the deadline and fires the task waker DIRECTLY, the
        // way core vmtime does (no `notify`, no MUST_EXIT).
        let timer_items = items_per_producer;
        {
            let sources = sources.clone();
            let shared = shared_waker.clone();
            producers.push(thread::spawn(move || {
                for _ in 0..timer_items {
                    sources.timer_due.store(true, Release);
                    if let Some(w) = shared.lock().unwrap().clone() {
                        w.wake_by_ref();
                    }
                    if fastrand_bit() {
                        thread::yield_now();
                    }
                }
            }));
        }

        for p in producers {
            p.join().expect("producer thread panicked");
        }

        // Every source has now published in full. The gic/synic/cpu_on totals are
        // fixed; the timer collapses repeated arms into at most `timer_items`
        // deliveries but at least one (the final arm cannot be lost).
        let fixed = producers_per_source * items_per_producer * 3;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let d = sources.delivered.load(Acquire);
            let gic = sources.gic.load(Acquire);
            let synic = sources.synic.load(Acquire);
            let cpu_on = sources.cpu_on.load(Acquire);
            let timer = sources.timer_due.load(Acquire);
            // All notify-backed work drained AND no timer arm left outstanding.
            if d >= fixed && gic == 0 && synic == 0 && cpu_on == 0 && !timer {
                break;
            }
            if Instant::now() > deadline {
                stop.store(true, Release);
                consumer.thread().unpark();
                let _ = consumer.join();
                panic!(
                    "LOST WAKEUP (iter {iter}): consumer parked on undelivered work — \
                     delivered={d} fixed_expected={fixed} leftover gic={gic} synic={synic} \
                     cpu_on={cpu_on} timer_due={timer}"
                );
            }
            thread::yield_now();
        }

        stop_consumer(&actor, &stop, consumer);
    }
}

/// Positive control: a deterministically-lost wakeup (publish after the consumer
/// has parked, with no wake at all) MUST be caught by the harness's timeout. This
/// proves the `wake_loop_never_strands_work` detector is not vacuous.
#[test]
#[should_panic(expected = "control lost wakeup")]
fn harness_detects_lost_wakeup() {
    let src = Arc::new(AtomicU64::new(0));
    let delivered = Arc::new(AtomicU64::new(0));
    let parked = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));

    let consumer = {
        let src = src.clone();
        let delivered = delivered.clone();
        let parked = parked.clone();
        let stop = stop.clone();
        thread::spawn(move || {
            loop {
                if stop.load(Acquire) {
                    return;
                }
                if drain(&src, &delivered) {
                    continue;
                }
                // BROKEN: announce idle and block with NO wake wired to `src`.
                parked.store(true, Release);
                thread::park();
            }
        })
    };

    // Ensure the consumer is genuinely parked, then publish with no wake at all.
    while !parked.load(Acquire) {
        thread::yield_now();
    }
    // Small settle so the consumer is inside thread::park(), not just past the flag.
    thread::sleep(Duration::from_millis(20));
    src.fetch_add(1, Release);

    let deadline = Instant::now() + Duration::from_secs(2);
    while delivered.load(Acquire) < 1 {
        if Instant::now() > deadline {
            stop.store(true, Release);
            consumer.thread().unpark();
            let _ = consumer.join();
            panic!("control lost wakeup: item never delivered");
        }
        thread::yield_now();
    }
    stop.store(true, Release);
    consumer.thread().unpark();
    consumer.join().unwrap();
}

/// A tiny, dependency-free coin flip to jitter producer timing. Uses a
/// per-thread xorshift so different threads diverge without a PRNG crate.
fn fastrand_bit() -> bool {
    use std::cell::Cell;
    thread_local! {
        static STATE: Cell<u64> = const { Cell::new(0) };
    }
    STATE.with(|s| {
        // xorshift64*
        let mut x = s.get().wrapping_add(0x9E37_79B9_7F4A_7C15);
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        s.set(x);
        (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 33) & 1 == 1
    })
}
