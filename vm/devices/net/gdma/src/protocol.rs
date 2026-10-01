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
