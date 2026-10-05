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

fn exchange_request(code: u32, request_version: u16, response_version: u16) -> [u8; 40] {
    let mut request = [0; 40];
    request[4..8].copy_from_slice(&code.to_le_bytes());
    request[8..10].copy_from_slice(&request_version.to_le_bytes());
    request[12..16].copy_from_slice(&40u32.to_le_bytes());
    request[20..24].copy_from_slice(&code.to_le_bytes());
    request[24..26].copy_from_slice(&response_version.to_le_bytes());
    request[26..28].copy_from_slice(&17u16.to_le_bytes());
    request[28..32].copy_from_slice(&128u32.to_le_bytes());
    request[36..40].copy_from_slice(&93u32.to_le_bytes());
    request
}

fn exchange_reply(code: u32, version: u16, status: u32) -> [u8; 32] {
    let mut response = [0; 32];
    response[4..8].copy_from_slice(&code.to_le_bytes());
    response[8..10].copy_from_slice(&version.to_le_bytes());
    response[10..12].copy_from_slice(&17u16.to_le_bytes());
    response[12..16].copy_from_slice(&128u32.to_le_bytes());
    response[20..24].copy_from_slice(&93u32.to_le_bytes());
    response[24..28].copy_from_slice(&status.to_le_bytes());
    response
}

fn driver_declaration_request() -> [u8; 640] {
    let mut request = [0; 640];
    request[..40].copy_from_slice(&exchange_request(1, 1, 1));
    request[12..16].copy_from_slice(&640u32.to_le_bytes());
    for (offset, value) in [
        (40, 1u64),
        (48, 3),
        (56, 0x27eca6f),
        (64, 0x1122334455667788),
        (72, 0x8877665544332211),
        (80, u64::MAX),
        (88, 0x300050000001f),
    ] {
        request[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [(96, 16u32), (104, 6), (108, 6), (112, 144), (116, 7)] {
        request[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [
        (128, "Linux"),
        (256, "6.6.144.1-1.azl3"),
        (384, "kernel identity"),
        (512, "advisory"),
    ] {
        request[offset..offset + value.len()].copy_from_slice(value.as_bytes());
    }
    request
}

#[test]
fn driver_declaration_is_an_independent_current_epoch_request_observation() {
    let mut monitor = Monitor::new(64, ObservationScope::ConsumerPublicationsOnly);
    let request = driver_declaration_request();
    assert!(
        monitor
            .observe(Event::HwcRequest {
                bytes: &request,
                wire_len: 640,
                receive_capacity: 128,
            })
            .is_none()
    );
    let declaration = monitor.report().driver_declaration.unwrap();
    assert_eq!((declaration.epoch, declaration.sequence), (0, 1));
    assert_eq!((declaration.protocol_min, declaration.protocol_max), (1, 3));
    assert_eq!(
        declaration.capabilities,
        [0x27eca6f, 0x1122334455667788, 0x8877665544332211, u64::MAX]
    );
    assert_eq!(declaration.driver_version, 0x300050000001f);
    assert_eq!(declaration.os_type, 16);
    assert_eq!(declaration.os_version, [6, 6, 144, 7]);
    assert_eq!(
        declaration.os_version_strings,
        ["Linux", "6.6.144.1-1.azl3", "kernel identity", "advisory"]
    );
    assert!(monitor.report().exchanges.is_empty());
    monitor.observe(Event::Reset);
    assert!(monitor.report().driver_declaration.is_none());
    monitor.observe(Event::HwcRequest {
        bytes: &request,
        wire_len: 640,
        receive_capacity: 128,
    });
    assert_eq!(monitor.report().driver_declaration.unwrap().epoch, 1);
}

#[test]
fn incomplete_or_unknown_declarations_cannot_retain_an_earlier_identity() {
    for mutation in 0..6 {
        let mut monitor = Monitor::new(64, ObservationScope::ConsumerPublicationsOnly);
        let original = driver_declaration_request();
        monitor.observe(Event::HwcRequest {
            bytes: &original,
            wire_len: 640,
            receive_capacity: 128,
        });
        let mut request = original;
        let mut captured = 640;
        let mut wire_len = 640;
        match mutation {
            0 => captured = 639,
            1 => {
                captured = 639;
                wire_len = 639;
                request[12..16].copy_from_slice(&639u32.to_le_bytes());
            }
            2 => request[256..384].fill(b'x'),
            3 => request[384] = 0xff,
            4 => request[8..10].copy_from_slice(&2u16.to_le_bytes()),
            5 => request[12..16].copy_from_slice(&40u32.to_le_bytes()),
            _ => unreachable!(),
        }
        monitor.observe(Event::HwcRequest {
            bytes: &request[..captured],
            wire_len,
            receive_capacity: 128,
        });
        assert!(monitor.report().driver_declaration.is_none(), "{mutation}");
    }
}

#[test]
fn live_namespace_has_positive_bind_release_and_reuse_witnesses() {
    let mut monitor = Monitor::new(64, ObservationScope::ConsumerPublicationsOnly);
    for kind in [QueueKind::Sq, QueueKind::Rq] {
        assert!(
            monitor
                .observe(Event::QueueBound(QueueDescriptor {
                    key: QueueKey { kind, id: 0 },
                    bytes: 64,
                    parent_eq: None,
                    msix: None,
                }))
                .is_none()
        );
    }
    let sq = QueueKey {
        kind: QueueKind::Sq,
        id: 0,
    };
    assert!(monitor.observe(Event::QueueReleased(sq)).is_none());
    assert!(
        monitor
            .observe(Event::QueueBound(QueueDescriptor {
                key: sq,
                bytes: 64,
                parent_eq: None,
                msix: None,
            }))
            .is_none()
    );
    assert_eq!(
        monitor.report().statistics[Rule::QueueLifetime as usize].satisfied,
        4
    );
    assert_eq!(monitor.report().ownership.live_queues, [1, 1, 0, 0]);
    let finding = monitor
        .observe(Event::QueueBound(QueueDescriptor {
            key: sq,
            bytes: 64,
            parent_eq: None,
            msix: None,
        }))
        .unwrap();
    assert_eq!(
        (finding.actor, finding.rule),
        (Actor::Device, Rule::QueueLifetime)
    );
}

#[test]
fn exchange_evidence_preserves_independent_versions_and_short_rejection() {
    let mut monitor = Monitor::new(64, ObservationScope::ConsumerPublicationsOnly);
    for _ in 0..2 {
        let request = exchange_request(0x20002, 2, 4);
        assert!(
            monitor
                .observe(Event::HwcRequest {
                    bytes: &request,
                    wire_len: 40,
                    receive_capacity: 128,
                })
                .is_none()
        );
        let response = exchange_reply(0x20002, 3, 31);
        assert!(
            monitor
                .observe(Event::HwcResponse {
                    bytes: &response,
                    wire_len: 32,
                })
                .is_none()
        );
    }
    let report = monitor.report();
    assert_eq!(report.exchanges.len(), 1);
    let exchange = report.exchanges[0];
    assert_eq!(exchange.count, 2);
    assert_eq!(exchange.key.request_version, 2);
    assert_eq!(exchange.key.requested_response_version, 4);
    assert_eq!(exchange.key.response_version, 3);
    assert_eq!(exchange.key.status, 31);
    assert!(exchange.key.correlated);
    assert_eq!(
        (exchange.min_response_bytes, exchange.max_response_bytes),
        (32, 32)
    );
    assert_eq!((exchange.first_sequence, exchange.last_sequence), (2, 4));
    assert!(report.findings.is_empty());
}

#[test]
fn observed_limits_are_raw_reply_counts_not_opaque_queue_ids() {
    let mut monitor = Monitor::new(64, ObservationScope::ConsumerPublicationsOnly);
    let request = exchange_request(2, 1, 1);
    monitor.observe(Event::HwcRequest {
        bytes: &request,
        wire_len: 40,
        receive_capacity: 128,
    });
    let mut response = [0; 72];
    response[..32].copy_from_slice(&exchange_reply(2, 1, 0));
    for (offset, value) in [(36, 64u32), (40, 64), (44, 128), (48, 4), (68, 64)] {
        response[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    assert!(
        monitor
            .observe(Event::HwcResponse {
                bytes: &response,
                wire_len: 72,
            })
            .is_none()
    );
    assert_eq!(monitor.report().advertised_limits.unwrap().eq, 4);
    monitor.observe(Event::Reset);
    assert!(monitor.report().advertised_limits.is_none());
    assert_eq!(monitor.report().exchanges[0].count, 1);
}

#[test]
fn exchange_budget_omission_is_explicit() {
    let mut monitor = Monitor::new(64, ObservationScope::ConsumerPublicationsOnly);
    for code in 0x30000..0x30000 + MAX_EXCHANGES as u32 + 1 {
        let request = exchange_request(code, 1, 1);
        monitor.observe(Event::HwcRequest {
            bytes: &request,
            wire_len: 40,
            receive_capacity: 128,
        });
        let response = exchange_reply(code, 1, 0);
        assert!(
            monitor
                .observe(Event::HwcResponse {
                    bytes: &response,
                    wire_len: 32,
                })
                .is_none()
        );
    }
    assert_eq!(monitor.report().exchanges.len(), MAX_EXCHANGES);
    assert_eq!(monitor.report().omitted_exchanges, 1);
}

#[test]
fn vport_limits_come_from_a_correlated_known_wire_prefix() {
    let mut monitor = Monitor::new(64, ObservationScope::ConsumerPublicationsOnly);
    let request = exchange_request(0x20008, 1, 1);
    monitor.observe(Event::HwcRequest {
        bytes: &request,
        wire_len: 40,
        receive_capacity: 128,
    });
    let mut response = [0; 64];
    response[..32].copy_from_slice(&exchange_reply(0x20008, 1, 0));
    response[32..36].copy_from_slice(&1u32.to_le_bytes());
    response[36..40].copy_from_slice(&2u32.to_le_bytes());
    response[40..44].copy_from_slice(&64u32.to_le_bytes());
    assert!(
        monitor
            .observe(Event::HwcResponse {
                bytes: &response,
                wire_len: 64,
            })
            .is_none()
    );
    let limits = monitor.report().vport_limits.unwrap();
    assert_eq!(
        (
            limits.handle,
            limits.sq,
            limits.rq,
            limits.indirection_entries
        ),
        (0, 1, 2, 64)
    );
    monitor.observe(Event::Reset);
    assert!(monitor.report().vport_limits.is_none());
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
