// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Boundary capture and operator-visible reporting for the independent contract.

use gdma_contract::Event;
use gdma_contract::Monitor;
use gdma_contract::ObservationScope;
use gdma_contract::QueueKey;
use gdma_contract::QueueKind;
use gdma_contract::RULES;
use gdma_contract::Report;
use gdma_contract::Rule;
use gdma_contract::UNOBSERVABLE;
use guestmem::GuestMemory;
use guestmem::MemoryRead;
use inspect::Inspect;
use parking_lot::Mutex;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;

const CAPTURE_LIMIT: usize = 4096;

#[derive(Clone, Default)]
pub(crate) struct ProtocolObserver(Option<Arc<Mutex<ObserverState>>>);

struct ObserverState {
    monitor: Monitor,
    descriptors: BTreeMap<QueueKey, Vec<u8>>,
}

impl ProtocolObserver {
    pub fn new(enabled: bool, msix_vectors: u32) -> Self {
        Self(enabled.then(|| {
            Arc::new(Mutex::new(ObserverState {
                monitor: Monitor::new(msix_vectors, ObservationScope::ConsumerPublicationsOnly),
                descriptors: BTreeMap::new(),
            }))
        }))
    }

    pub fn observe(&self, event: Event<'_>) {
        let Some(monitor) = &self.0 else {
            return;
        };
        let finding = {
            let mut state = monitor.lock();
            match event {
                Event::QueueReleased(key) => {
                    state.descriptors.remove(&key);
                }
                Event::Reset => state.descriptors.clear(),
                _ => {}
            }
            state.monitor.observe(event)
        };
        if let Some(finding) = finding {
            tracelimit::warn_ratelimited!(
                rule = finding.rule.id(),
                actor = finding.actor.as_str(),
                sequence = finding.sequence,
                epoch = finding.epoch,
                queue = ?finding.queue,
                evidence = ?finding.evidence,
                "GDMA protocol contract violation",
            );
        }
    }

    pub fn report(&self) -> Option<Report> {
        self.0.as_ref().map(|state| state.lock().monitor.report())
    }

    pub fn report_json(&self) -> Option<String> {
        self.report().map(|report| Self::encode_report(&report))
    }

    pub fn descriptor(
        &self,
        queue: QueueKey,
        header: &[u8],
        mut read: impl MemoryRead,
        published: u32,
    ) {
        let Some(state) = &self.0 else {
            return;
        };
        let count = (published.saturating_sub(8) as usize)
            .min(504)
            .min(read.len());
        let mut bytes = vec![0; 8 + count];
        if header.len() != 8 {
            self.observe(Event::ObservationUnavailable(Rule::WorkDescriptor));
            return;
        }
        bytes[..8].copy_from_slice(header);
        if let Err(error) = read.read(&mut bytes[8..]) {
            state.lock().descriptors.remove(&queue);
            self.observe(Event::ObservationUnavailable(Rule::WorkDescriptor));
            tracelimit::warn_ratelimited!(
                error = &error as &dyn std::error::Error,
                "GDMA descriptor observation unavailable",
            );
            return;
        }
        let mut state = state.lock();
        if state.descriptors.len() < 512 || state.descriptors.contains_key(&queue) {
            state.descriptors.insert(queue, bytes);
        } else {
            state
                .monitor
                .observe(Event::ObservationUnavailable(Rule::WorkDescriptor));
        }
    }

    fn encode_report(report: &Report) -> String {
        let rules: serde_json::Map<String, serde_json::Value> = RULES
            .into_iter()
            .map(|rule| {
                let statistics = report.statistics[rule as usize];
                (
                    rule.id().to_owned(),
                    json!({
                        "satisfied": statistics.satisfied,
                        "guest_violations": statistics.guest_violations,
                        "device_violations": statistics.device_violations,
                        "inconclusive": statistics.inconclusive,
                    }),
                )
            })
            .collect();
        let findings: Vec<_> = report
            .findings
            .iter()
            .map(|finding| {
                json!({
                    "rule": finding.rule.id(),
                    "actor": finding.actor.as_str(),
                    "sequence": finding.sequence,
                    "epoch": finding.epoch,
                    "queue": finding.queue.map(|queue| json!({
                        "kind": queue.kind.as_str(),
                        "id": queue.id,
                    })),
                    "evidence": finding.evidence,
                })
            })
            .collect();
        let exchanges: Vec<_> = report
            .exchanges
            .iter()
            .map(|exchange| {
                json!({
                    "request_type": exchange.key.request_type,
                    "request_version": exchange.key.request_version,
                    "requested_response_version": exchange.key.requested_response_version,
                    "response_type": exchange.key.response_type,
                    "response_version": exchange.key.response_version,
                    "status": exchange.key.status,
                    "correlated": exchange.key.correlated,
                    "count": exchange.count,
                    "first_sequence": exchange.first_sequence,
                    "last_sequence": exchange.last_sequence,
                    "min_request_bytes": exchange.min_request_bytes,
                    "max_request_bytes": exchange.max_request_bytes,
                    "min_response_bytes": exchange.min_response_bytes,
                    "max_response_bytes": exchange.max_response_bytes,
                })
            })
            .collect();
        let limits = report.advertised_limits.map(|limits| {
            json!({
                "sq": limits.sq,
                "rq": limits.rq,
                "cq": limits.cq,
                "eq": limits.eq,
                "msix": limits.msix,
            })
        });
        let vport_limits = report.vport_limits.map(|limits| {
            json!({
                "handle": limits.handle,
                "sq": limits.sq,
                "rq": limits.rq,
                "indirection_entries": limits.indirection_entries,
            })
        });
        let driver_declaration = report.driver_declaration.as_ref().map(|declaration| {
            json!({
                "epoch": declaration.epoch,
                "sequence": declaration.sequence,
                "protocol_min": declaration.protocol_min,
                "protocol_max": declaration.protocol_max,
                "capabilities": declaration.capabilities,
                "driver_version": declaration.driver_version,
                "os_type": declaration.os_type,
                "os_version": declaration.os_version,
                "os_version_strings": declaration.os_version_strings,
            })
        });
        json!({
            "schema": "openvmm/gdma-protocol/v1",
            "scope": report.scope.as_str(),
            "epoch": report.epoch,
            "observations": report.observations,
            "queue_tracking_complete": report.tracking_complete,
            "resource_tracking_complete": report.resource_tracking_complete,
            "omitted_findings": report.omitted_findings,
            "uncovered_commands": report.uncovered_commands,
            "incomplete_observations": report.incomplete_observations,
            "rules": rules,
            "findings": findings,
            "exchanges": exchanges,
            "omitted_exchanges": report.omitted_exchanges,
            "advertised_limits": limits,
            "vport_limits": vport_limits,
            "driver_declaration": driver_declaration,
            "ownership": {
                "live_queues": {
                    "sq": report.ownership.live_queues[0],
                    "rq": report.ownership.live_queues[1],
                    "cq": report.ownership.live_queues[2],
                    "eq": report.ownership.live_queues[3],
                },
                "unbound_region_handles": report.ownership.unbound_region_handles,
                "work_objects": report.ownership.work_objects,
                "hwc_active": report.ownership.hwc_active,
            },
            "unobservable": UNOBSERVABLE,
        })
        .to_string()
    }

    pub fn request(&self, gm: &GuestMemory, sq: u32, rq: u32) {
        let Some(state) = &self.0 else {
            return;
        };
        let (send, receive) = {
            let state = state.lock();
            (
                state
                    .descriptors
                    .get(&QueueKey {
                        kind: QueueKind::Sq,
                        id: sq,
                    })
                    .cloned(),
                state
                    .descriptors
                    .get(&QueueKey {
                        kind: QueueKind::Rq,
                        id: rq,
                    })
                    .cloned(),
            )
        };
        let Some((bytes, wire_len, receive_capacity)) =
            send.zip(receive).and_then(|(send, receive)| {
                let send = message_image(gm, &send, CAPTURE_LIMIT)?;
                let capacity = message_capacity(&receive)?;
                Some((send.0, send.1, capacity))
            })
        else {
            self.observe(Event::ObservationUnavailable(Rule::RequestEnvelope));
            tracelimit::warn_ratelimited!("GDMA independent request projection unavailable");
            return;
        };
        self.observe(Event::HwcRequest {
            bytes: &bytes,
            wire_len,
            receive_capacity,
        });
    }

    pub fn response(&self, gm: &GuestMemory, rq: u32, wire_len: u64) {
        let Some(state) = &self.0 else {
            return;
        };
        let receive = state
            .lock()
            .descriptors
            .get(&QueueKey {
                kind: QueueKind::Rq,
                id: rq,
            })
            .cloned();
        let image = receive.and_then(|receive| {
            message_image(gm, &receive, wire_len.min(CAPTURE_LIMIT as u64) as usize)
        });
        let Some((bytes, _)) = image else {
            self.observe(Event::ObservationUnavailable(Rule::ResponseEnvelope));
            tracelimit::warn_ratelimited!("GDMA independent response projection unavailable");
            return;
        };
        self.observe(Event::HwcResponse {
            bytes: &bytes,
            wire_len,
        });
    }
}

// HWC byte projection is independent of WqeAccess. Other OOB/direct/key forms
// remain explicitly unobserved rather than attributing a codec error to a guest.
fn segments(descriptor: &[u8]) -> Option<impl Iterator<Item = &[u8]>> {
    let parameters = u32::from_le_bytes(descriptor.get(4..8)?.try_into().ok()?);
    if parameters & ((1 << 11) | (1 << 31)) != 0 {
        return None;
    }
    let oob = match (parameters >> 8) & 7 {
        2 => 8,
        6 => 24,
        _ => return None,
    };
    let count = (parameters & 0xff) as usize;
    let list = descriptor.get(8 + oob..8 + oob + count * 16)?;
    if !list.chunks_exact(16).all(|sge| sge[8..12] == [0; 4]) {
        return None;
    }
    Some(list.chunks_exact(16))
}

fn message_capacity(descriptor: &[u8]) -> Option<u64> {
    segments(descriptor)?.try_fold(0u64, |total, sge| {
        total.checked_add(u32::from_le_bytes(sge[12..16].try_into().ok()?) as u64)
    })
}

fn message_image(gm: &GuestMemory, descriptor: &[u8], limit: usize) -> Option<(Vec<u8>, u64)> {
    let wire_len = message_capacity(descriptor)?;
    let mut bytes = vec![0; wire_len.min(limit as u64) as usize];
    let mut copied = 0;
    for sge in segments(descriptor)? {
        let address = u64::from_le_bytes(sge[..8].try_into().ok()?);
        let count = u32::from_le_bytes(sge[12..16].try_into().ok()?) as usize;
        let count = count.min(bytes.len() - copied);
        if gm
            .read_at(address, &mut bytes[copied..copied + count])
            .is_err()
        {
            return None;
        }
        copied += count;
        if copied == bytes.len() {
            break;
        }
    }
    (copied == bytes.len()).then_some((bytes, wire_len))
}

impl Inspect for ProtocolObserver {
    fn inspect(&self, req: inspect::Request<'_>) {
        let mut response = req.respond();
        response.field("enabled", self.0.is_some());
        let Some(report) = self.report() else {
            return;
        };
        response
            .field("report_json", Self::encode_report(&report))
            .field("scope", report.scope.as_str())
            .field("epoch", report.epoch)
            .field("observations", report.observations)
            .field("queue_tracking_complete", report.tracking_complete)
            .field(
                "resource_tracking_complete",
                report.resource_tracking_complete,
            )
            .field("omitted_findings", report.omitted_findings)
            .field("uncovered_commands", report.uncovered_commands)
            .field("incomplete_observations", report.incomplete_observations)
            .fields("unobservable", UNOBSERVABLE.iter().enumerate())
            .fields(
                "rules",
                RULES.into_iter().map(|rule| {
                    let stat = report.statistics[rule as usize];
                    (
                        rule.id(),
                        inspect::adhoc(move |req| {
                            req.respond()
                                .field("obligation", rule.obligation())
                                .field("satisfied", stat.satisfied)
                                .field("guest_violations", stat.guest_violations)
                                .field("device_violations", stat.device_violations)
                                .field("inconclusive", stat.inconclusive);
                        }),
                    )
                }),
            )
            .fields(
                "findings",
                report.findings.iter().enumerate().map(|(index, finding)| {
                    (
                        index,
                        inspect::adhoc(|req| {
                            req.respond()
                                .field("rule", finding.rule.id())
                                .field("actor", finding.actor.as_str())
                                .field("sequence", finding.sequence)
                                .field("epoch", finding.epoch)
                                .field("queue_kind", finding.queue.map(|queue| queue.kind.as_str()))
                                .field("queue_id", finding.queue.map(|queue| queue.id))
                                .hex("evidence0", finding.evidence[0])
                                .hex("evidence1", finding.evidence[1])
                                .hex("evidence2", finding.evidence[2]);
                        }),
                    )
                }),
            );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gdma_contract::QueueDescriptor;
    use test_with_tracing::test;

    #[test]
    fn versioned_json_preserves_conditional_scope_and_type_qualified_ownership() {
        assert!(ProtocolObserver::new(false, 64).report_json().is_none());
        let observer = ProtocolObserver::new(true, 64);
        for kind in [QueueKind::Sq, QueueKind::Rq] {
            observer.observe(Event::QueueBound(QueueDescriptor {
                key: QueueKey { kind, id: 0 },
                bytes: 64,
                parent_eq: None,
                msix: None,
            }));
        }
        let report: serde_json::Value =
            serde_json::from_str(&observer.report_json().unwrap()).unwrap();
        assert_eq!(report["schema"], "openvmm/gdma-protocol/v1");
        assert_eq!(report["scope"], "consumer-publications-only");
        assert_eq!(report["ownership"]["live_queues"]["sq"], 1);
        assert_eq!(report["ownership"]["live_queues"]["rq"], 1);
        assert_eq!(report["rules"]["gdma.queue.live-namespace"]["satisfied"], 2);
        assert_eq!(
            report["unobservable"].as_array().unwrap().len(),
            UNOBSERVABLE.len()
        );
        assert!(report["advertised_limits"].is_null());
        assert!(report["driver_declaration"].is_null());
    }

    #[test]
    fn versioned_json_retains_the_observed_driver_declaration_before_any_reply() {
        let observer = ProtocolObserver::new(true, 64);
        let mut bytes = [0; 640];
        bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
        bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
        bytes[12..16].copy_from_slice(&640u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..26].copy_from_slice(&1u16.to_le_bytes());
        bytes[28..32].copy_from_slice(&72u32.to_le_bytes());
        bytes[40..48].copy_from_slice(&1u64.to_le_bytes());
        bytes[48..56].copy_from_slice(&1u64.to_le_bytes());
        bytes[88..96].copy_from_slice(&0x300050000001fu64.to_le_bytes());
        bytes[96..100].copy_from_slice(&16u32.to_le_bytes());
        bytes[128..133].copy_from_slice(b"Linux");
        observer.observe(Event::HwcRequest {
            bytes: &bytes,
            wire_len: 640,
            receive_capacity: 72,
        });
        let report: serde_json::Value =
            serde_json::from_str(&observer.report_json().unwrap()).unwrap();
        assert_eq!(report["driver_declaration"]["epoch"], 0);
        assert_eq!(report["driver_declaration"]["sequence"], 1);
        assert_eq!(
            report["driver_declaration"]["driver_version"],
            0x300050000001fu64
        );
        assert_eq!(
            report["driver_declaration"]["os_version_strings"],
            json!(["Linux", "", "", ""])
        );
        assert!(report["exchanges"].as_array().unwrap().is_empty());
        observer.observe(Event::Reset);
        let report: serde_json::Value =
            serde_json::from_str(&observer.report_json().unwrap()).unwrap();
        assert!(report["driver_declaration"].is_null());
    }
}
