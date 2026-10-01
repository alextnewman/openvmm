// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use std::collections::BTreeSet;
use test_with_tracing::test;

#[path = "../examples/contract_probe.rs"]
mod probe;

#[test]
fn independent_wire_corpus() {
    for case in probe::CASES {
        probe::run_case(case).unwrap();
    }
}

#[test]
fn full_width_work_cursor_rollover() {
    let mut monitor = Monitor::new(64, ObservationScope::CompleteConsumerTrace);
    let key = QueueKey {
        kind: QueueKind::Sq,
        id: 24,
    };
    assert!(
        monitor
            .observe(Event::QueueBound(QueueDescriptor {
                key,
                bytes: 64,
                parent_eq: None,
                msix: None,
            }))
            .is_none()
    );
    // A reachable aligned cursor just before natural 32-bit rollover.
    let queue = monitor.queues.get_mut(&key).unwrap();
    queue.producer = u32::MAX - 31;
    queue.consumer = u32::MAX - 31;
    let value = 24u64;
    assert!(
        monitor
            .observe(Event::MmioWrite {
                space: MmioSpace::Doorbell,
                offset: 0,
                data: &value.to_le_bytes(),
            })
            .is_none()
    );
    let header = [0, 0, 0, 0, 1, 2, 0, 0];
    assert!(
        monitor
            .observe(Event::WorkHeader {
                queue: key,
                position: u32::MAX - 31,
                header: &header,
            })
            .is_none()
    );
    assert!(
        monitor
            .observe(Event::WorkConsumed {
                queue: key,
                position: u32::MAX - 31,
                bytes: 32,
            })
            .is_none()
    );
    assert_eq!(monitor.queues[&key].consumer, 0);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ReferenceRing {
    live: bool,
    producer: u8,
    consumer: u8,
}

impl ReferenceRing {
    fn fresh() -> Self {
        Self {
            live: true,
            producer: 2,
            consumer: 2,
        }
    }

    fn used(self) -> u8 {
        (self.producer + 16 - self.consumer) % 16
    }
}

fn event_queue(id: u32) -> QueueDescriptor {
    QueueDescriptor {
        key: QueueKey {
            kind: QueueKind::Eq,
            id,
        },
        bytes: 32,
        parent_eq: None,
        msix: Some(0),
    }
}

#[test]
fn exhaustive_two_ring_interleavings() {
    let mut initial = Monitor::new(64, ObservationScope::CompleteConsumerTrace);
    for id in [24, 25] {
        assert!(
            initial
                .observe(Event::QueueBound(event_queue(id)))
                .is_none()
        );
    }
    let start = [ReferenceRing::fresh(); 2];
    let mut seen = BTreeSet::from([start]);
    let mut pending = VecDeque::from([(start, initial)]);
    let mut transitions = 0usize;
    while let Some((state, monitor)) = pending.pop_front() {
        for index in 0..2 {
            let ring = state[index];
            let descriptor = event_queue(24 + index as u32);
            let key = descriptor.key;
            if !ring.live {
                let mut next = state;
                next[index] = ReferenceRing::fresh();
                let mut observer = monitor.clone();
                assert!(
                    observer.observe(Event::QueueBound(descriptor)).is_none(),
                    "{state:?}"
                );
                transitions += 1;
                if seen.insert(next) {
                    pending.push_back((next, observer));
                }
                continue;
            }
            if ring.used() < 2 {
                let mut next = state;
                next[index].producer = (ring.producer + 1) % 16;
                let mut observer = monitor.clone();
                let mut entry = [0; 16];
                entry[12..].copy_from_slice(&(u32::from(ring.producer / 2) << 29).to_le_bytes());
                let value = observer.observe(Event::Completion {
                    queue: key,
                    entry: &entry,
                    body_written: true,
                    owner_written: true,
                });
                assert!(value.is_none(), "{state:?}: {value:?}");
                transitions += 1;
                if seen.insert(next) {
                    pending.push_back((next, observer));
                }
            } else {
                let mut observer = monitor.clone();
                let mut entry = [0; 16];
                entry[12..].copy_from_slice(&(u32::from(ring.producer / 2) << 29).to_le_bytes());
                let value = observer.observe(Event::Completion {
                    queue: key,
                    entry: &entry,
                    body_written: true,
                    owner_written: true,
                });
                assert!(
                    value.is_some_and(
                        |f| f.actor == Actor::Device && f.rule == Rule::CompletionWindow
                    ),
                    "{state:?}: {value:?}"
                );
            }
            for distance in 0..=2u8 {
                let tail = (ring.producer + 16 - distance) % 16;
                let mut next = state;
                if distance <= ring.used() {
                    next[index].consumer = tail;
                }
                let mut observer = monitor.clone();
                let doorbell = u64::from(key.id) | (u64::from(tail) << 32) | (1 << 63);
                let value = observer.observe(Event::MmioWrite {
                    space: MmioSpace::Doorbell,
                    offset: 0xff8,
                    data: &doorbell.to_le_bytes(),
                });
                assert!(value.is_none(), "{state:?}, distance {distance}: {value:?}");
                transitions += 1;
                if seen.insert(next) {
                    pending.push_back((next, observer));
                }
            }
            let mut next = state;
            next[index] = ReferenceRing {
                live: false,
                producer: 0,
                consumer: 0,
            };
            let mut observer = monitor.clone();
            observer.observe(Event::QueueReleased(key));
            transitions += 1;
            if seen.insert(next) {
                pending.push_back((next, observer));
            }
            let invalid_tail = (ring.producer + 1) % 16;
            let doorbell = u64::from(key.id) | (u64::from(invalid_tail) << 32) | (1 << 63);
            let mut observer = monitor.clone();
            let value = observer.observe(Event::MmioWrite {
                space: MmioSpace::Doorbell,
                offset: 0xff8,
                data: &doorbell.to_le_bytes(),
            });
            assert!(
                value.is_some_and(|f| f.actor == Actor::Guest && f.rule == Rule::ConsumerWindow),
                "{state:?}: {value:?}"
            );
        }
    }
    // 16 owner positions * 3 bounded occupancies, plus one retired state,
    // independently composed for each of the two queues.
    assert_eq!(seen.len(), 49 * 49);
    assert_eq!(transitions, 2 * 49 * (16 * (2 * 5 + 4) + 1));
}

#[test]
fn unavailable_observation_is_not_compliance() {
    let mut monitor = Monitor::new(64, ObservationScope::ConsumerPublicationsOnly);
    assert!(
        monitor
            .observe(Event::ObservationUnavailable(Rule::ResponseEnvelope))
            .is_none()
    );
    let report = monitor.report();
    assert!(!report.resource_tracking_complete);
    assert_eq!(
        report.statistics[Rule::ResponseEnvelope as usize].inconclusive,
        1
    );
    assert_eq!(
        report.statistics[Rule::ResponseEnvelope as usize].satisfied,
        0
    );
    assert!(report.findings.is_empty());
}
