// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Independent byte examples used by ordinary tests and compiled mutations.

use gdma_contract::Actor;
use gdma_contract::Event;
use gdma_contract::Finding;
use gdma_contract::MmioSpace;
use gdma_contract::Monitor;
use gdma_contract::ObservationScope;
use gdma_contract::QueueDescriptor;
use gdma_contract::QueueKey;
use gdma_contract::QueueKind;
use gdma_contract::Rule;

/// Named validity and violation examples, independent of emulator encoders.
pub const CASES: &[&str] = &[
    "atomic-publication",
    "typed-lifetime",
    "work-publication",
    "descriptor-direction",
    "device-consumption",
    "owner-phases",
    "complete-consumer-overflow",
    "native-consumer-gap",
    "legal-rearm-hints",
    "peer-fault-attribution",
    "smc-downlevel",
    "raw-bootstrap",
    "request-envelopes",
    "reply-correlation",
    "driver-declaration",
    "legal-short-rejection",
    "resource-transfer",
    "region-continuation",
    "declined-resource-request",
    "unknown-forms",
    "bounded-evidence",
];

fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn no_finding(value: Option<Finding>) -> Result<(), String> {
    require(value.is_none(), &format!("false accusation: {value:?}"))
}

fn finding(value: Option<Finding>, actor: Actor, rule: Rule) -> Result<(), String> {
    require(
        value.is_some_and(|finding| finding.actor == actor && finding.rule == rule),
        &format!("expected {actor:?}/{rule:?}, observed {value:?}"),
    )
}

fn model() -> Monitor {
    Monitor::new(64, ObservationScope::CompleteConsumerTrace)
}

fn bind(monitor: &mut Monitor, kind: QueueKind, id: u32, bytes: u64) -> Result<QueueKey, String> {
    let key = QueueKey { kind, id };
    no_finding(monitor.observe(Event::QueueBound(QueueDescriptor {
        key,
        bytes,
        parent_eq: None,
        msix: (kind == QueueKind::Eq).then_some(0),
    })))?;
    Ok(key)
}

fn db(monitor: &mut Monitor, key: QueueKey, tail: u32, armed: bool) -> Option<Finding> {
    let offset = match key.kind {
        QueueKind::Sq => 0,
        QueueKind::Rq => 0x400,
        QueueKind::Cq => 0x800,
        QueueKind::Eq => 0xff8,
    };
    let value = u64::from(key.id) | (u64::from(tail) << 32) | (u64::from(armed) << 63);
    monitor.observe(Event::MmioWrite {
        space: MmioSpace::Doorbell,
        offset,
        data: &value.to_le_bytes(),
    })
}

fn post(monitor: &mut Monitor, queue: QueueKey, phase: u32) -> Option<Finding> {
    let mut entry = [0; 16];
    put32(&mut entry, 12, phase << 29);
    monitor.observe(Event::Completion {
        queue,
        entry: &entry,
        body_written: true,
        owner_written: true,
    })
}

fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn request(code: u32, body: &[u8], capacity: u32) -> Vec<u8> {
    let mut bytes = vec![0; 40 + body.len()];
    let length = bytes.len() as u32;
    put32(&mut bytes, 4, code);
    bytes[8] = 1;
    bytes[10..12].copy_from_slice(&0x1357u16.to_le_bytes());
    put32(&mut bytes, 12, length);
    put32(&mut bytes, 20, code);
    bytes[24] = 1;
    bytes[26..28].copy_from_slice(&0x2468u16.to_le_bytes());
    put32(&mut bytes, 28, capacity);
    put32(&mut bytes, 32, 2);
    put32(&mut bytes, 36, 0x57ac_ef01);
    bytes[40..].copy_from_slice(body);
    bytes
}

fn response(request: &[u8], body: &[u8], status: u32) -> Vec<u8> {
    let mut bytes = vec![0; 32 + body.len()];
    bytes[..16].copy_from_slice(&request[16..32]);
    bytes[16..24].copy_from_slice(&request[32..40]);
    put32(&mut bytes, 24, status);
    bytes[32..].copy_from_slice(body);
    bytes
}

fn exchange(
    monitor: &mut Monitor,
    request: &[u8],
    reply: &[u8],
    capacity: u64,
) -> Result<(), String> {
    no_finding(monitor.observe(Event::HwcRequest {
        bytes: request,
        wire_len: request.len() as u64,
        receive_capacity: capacity,
    }))?;
    no_finding(monitor.observe(Event::HwcResponse {
        bytes: reply,
        wire_len: reply.len() as u64,
    }))
}

fn region_request(pages: u32, received: u32) -> Vec<u8> {
    let mut body = vec![0; 24 + received as usize * 8];
    put64(&mut body, 0, u64::from(pages) * 4096);
    put32(&mut body, 16, pages);
    put32(&mut body, 20, received);
    for page in 0..received {
        put64(
            &mut body,
            24 + page as usize * 8,
            0x10_0000 + u64::from(page) * 4096,
        );
    }
    request(25, &body, 40)
}

/// Check one independent example, including expected actor and rule attribution.
pub fn run_case(name: &str) -> Result<(), String> {
    let result = match name {
        "atomic-publication" => {
            let mut monitor = model();
            let queue = bind(&mut monitor, QueueKind::Sq, 24, 128)?;
            let value = 24u64 | (32u64 << 32);
            finding(
                monitor.observe(Event::MmioWrite {
                    space: MmioSpace::Doorbell,
                    offset: 0,
                    data: &value.to_le_bytes()[..4],
                }),
                Actor::Guest,
                Rule::DoorbellWidth,
            )?;
            no_finding(db(&mut monitor, queue, 32, false))?;
            // Client-data/unknown windows are not forced into a known format.
            no_finding(monitor.observe(Event::MmioWrite {
                space: MmioSpace::Doorbell,
                offset: 0x408,
                data: &[0; 4],
            }))
        }
        "typed-lifetime" => {
            let mut monitor = model();
            let sq = bind(&mut monitor, QueueKind::Sq, 24, 128)?;
            let rq = bind(&mut monitor, QueueKind::Rq, 24, 128)?;
            finding(
                monitor.observe(Event::QueueBound(QueueDescriptor {
                    key: sq,
                    bytes: 128,
                    parent_eq: None,
                    msix: None,
                })),
                Actor::Device,
                Rule::QueueLifetime,
            )?;
            monitor.observe(Event::QueueReleased(sq));
            no_finding(db(&mut monitor, rq, 32, false))?;
            finding(
                db(&mut monitor, sq, 32, false),
                Actor::Guest,
                Rule::QueueLifetime,
            )?;
            bind(&mut monitor, QueueKind::Sq, 24, 128)?;
            no_finding(db(&mut monitor, sq, 32, false))?;
            require(
                monitor.report().statistics[Rule::QueueLifetime as usize].satisfied >= 4,
                "valid namespace bind/release/reuse lacks positive witnesses",
            )
        }
        "work-publication" => {
            let mut monitor = model();
            let sq = bind(&mut monitor, QueueKind::Sq, 24, 64)?;
            finding(
                db(&mut monitor, sq, 1, false),
                Actor::Guest,
                Rule::WorkPublication,
            )?;
            finding(
                db(&mut monitor, sq, 96, false),
                Actor::Guest,
                Rule::WorkPublication,
            )?;
            no_finding(db(&mut monitor, sq, 64, false))?;
            no_finding(db(&mut monitor, sq, 64, false))
        }
        "descriptor-direction" => {
            let mut monitor = model();
            let sq = bind(&mut monitor, QueueKind::Sq, 24, 1024)?;
            let rq = bind(&mut monitor, QueueKind::Rq, 24, 1024)?;
            no_finding(db(&mut monitor, sq, 512, false))?;
            no_finding(db(&mut monitor, rq, 512, false))?;
            let mut header = [0; 8];
            put32(&mut header, 4, 31 | (2 << 8));
            no_finding(monitor.observe(Event::WorkHeader {
                queue: sq,
                position: 0,
                header: &header,
            }))?;
            finding(
                monitor.observe(Event::WorkHeader {
                    queue: rq,
                    position: 0,
                    header: &header,
                }),
                Actor::Guest,
                Rule::WorkDescriptor,
            )
        }
        "device-consumption" => {
            let mut monitor = model();
            let sq = bind(&mut monitor, QueueKind::Sq, 24, 64)?;
            finding(
                monitor.observe(Event::WorkConsumed {
                    queue: sq,
                    position: 0,
                    bytes: 32,
                }),
                Actor::Device,
                Rule::WorkConsumption,
            )?;
            let mut monitor = model();
            let sq = bind(&mut monitor, QueueKind::Sq, 24, 64)?;
            no_finding(db(&mut monitor, sq, 32, false))?;
            finding(
                monitor.observe(Event::WorkConsumed {
                    queue: sq,
                    position: 0,
                    bytes: 0,
                }),
                Actor::Device,
                Rule::WorkConsumption,
            )
        }
        "owner-phases" => {
            let mut monitor = model();
            let eq = bind(&mut monitor, QueueKind::Eq, 24, 32)?;
            for producer in 2..66u32 {
                no_finding(post(&mut monitor, eq, (producer / 2) & 7))?;
                no_finding(db(&mut monitor, eq, (producer + 1) & 15, true))?;
            }
            finding(
                post(&mut monitor, eq, 0),
                Actor::Device,
                Rule::CompletionOwner,
            )
        }
        "complete-consumer-overflow" => {
            let mut monitor = model();
            let eq = bind(&mut monitor, QueueKind::Eq, 24, 32)?;
            no_finding(post(&mut monitor, eq, 1))?;
            no_finding(post(&mut monitor, eq, 1))?;
            finding(
                post(&mut monitor, eq, 2),
                Actor::Device,
                Rule::CompletionWindow,
            )
        }
        "native-consumer-gap" => {
            let mut monitor = Monitor::new(64, ObservationScope::ConsumerPublicationsOnly);
            let eq = bind(&mut monitor, QueueKind::Eq, 24, 32)?;
            for producer in 2..34 {
                no_finding(post(&mut monitor, eq, (producer / 2) & 7))?;
            }
            require(
                monitor.report().statistics[Rule::CompletionWindow as usize].inconclusive != 0,
                "missing native observability classification",
            )?;
            no_finding(db(&mut monitor, eq, 2, true))?;
            no_finding(post(&mut monitor, eq, 1))
        }
        "legal-rearm-hints" => {
            let mut monitor = model();
            let eq = bind(&mut monitor, QueueKind::Eq, 24, 32)?;
            no_finding(post(&mut monitor, eq, 1))?;
            no_finding(db(&mut monitor, eq, 3, true))?;
            no_finding(db(&mut monitor, eq, 2, true))?;
            no_finding(db(&mut monitor, eq, 0x7654_3210, false))?;
            require(
                monitor.report().statistics[Rule::ConsumerWindow as usize].inconclusive != 0,
                "unarmed hint was misrepresented",
            )?;
            finding(
                db(&mut monitor, eq, 4, true),
                Actor::Guest,
                Rule::ConsumerWindow,
            )
        }
        "peer-fault-attribution" => {
            let mut monitor = model();
            let sq = bind(&mut monitor, QueueKind::Sq, 24, 64)?;
            let header = [0, 0, 0, 0, 0, 2, 0, 0];
            finding(
                monitor.observe(Event::WorkHeader {
                    queue: sq,
                    position: 0,
                    header: &header,
                }),
                Actor::Device,
                Rule::WorkConsumption,
            )?;
            no_finding(db(&mut monitor, sq, 32, false))?;
            let report = monitor.report();
            require(
                report
                    .statistics
                    .iter()
                    .all(|stat| stat.guest_violations == 0),
                "peer fault blamed on guest",
            )
        }
        "smc-downlevel" => {
            let mut monitor = model();
            let header = 1u32 | (5 << 3);
            no_finding(monitor.observe(Event::MmioWrite {
                space: MmioSpace::SharedMemory,
                offset: 28,
                data: &header.to_le_bytes(),
            }))?;
            // Publication transfers possession; the host need not write it.
            no_finding(monitor.observe(Event::SmcResponse(1 | (1 << 7))))?;
            monitor.observe(Event::MmioWrite {
                space: MmioSpace::SharedMemory,
                offset: 28,
                data: &2u32.to_le_bytes(),
            });
            finding(
                monitor.observe(Event::SmcResponse(2 | (1 << 7) | (1 << 31))),
                Actor::Device,
                Rule::SmcCorrelation,
            )
        }
        "raw-bootstrap" => {
            for bad_identity in [false, true] {
                let mut monitor = model();
                bind(&mut monitor, QueueKind::Sq, 24, 4096)?;
                bind(&mut monitor, QueueKind::Rq, 24, 4096)?;
                bind(&mut monitor, QueueKind::Cq, 24, 4096)?;
                let eq = bind(&mut monitor, QueueKind::Eq, 24, 4096)?;
                let cq = if bad_identity { 1234 } else { 24 };
                for (kind, data) in [
                    (129, 24),
                    (130, (1 << 24) | cq),
                    (130, (2 << 24) | 24),
                    (130, (3 << 24) | 24),
                ] {
                    let mut entry = [0; 16];
                    put32(&mut entry, 0, data);
                    put32(&mut entry, 12, (1 << 29) | kind);
                    no_finding(monitor.observe(Event::Completion {
                        queue: eq,
                        entry: &entry,
                        body_written: true,
                        owner_written: true,
                    }))?;
                }
                let mut done = [0; 16];
                put32(&mut done, 12, (1 << 29) | 131);
                let value = monitor.observe(Event::Completion {
                    queue: eq,
                    entry: &done,
                    body_written: true,
                    owner_written: true,
                });
                if bad_identity {
                    finding(value, Actor::Device, Rule::HwcInitialization)?;
                } else {
                    no_finding(value)?;
                }
            }
            Ok(())
        }
        "request-envelopes" => {
            let mut monitor = model();
            let mut req = request(3, &[], 32);
            put32(&mut req, 12, 41);
            finding(
                monitor.observe(Event::HwcRequest {
                    bytes: &req,
                    wire_len: 40,
                    receive_capacity: 32,
                }),
                Actor::Guest,
                Rule::RequestEnvelope,
            )?;
            let req = request(3, &[], 64);
            finding(
                monitor.observe(Event::HwcRequest {
                    bytes: &req,
                    wire_len: 40,
                    receive_capacity: 32,
                }),
                Actor::Guest,
                Rule::RequestEnvelope,
            )
        }
        "reply-correlation" => {
            let mut monitor = model();
            let req = request(3, &[], 64);
            no_finding(monitor.observe(Event::HwcRequest {
                bytes: &req,
                wire_len: 40,
                receive_capacity: 64,
            }))?;
            let mut reply = response(&req, &[], 0);
            put32(&mut reply, 20, 0x1234);
            finding(
                monitor.observe(Event::HwcResponse {
                    bytes: &reply,
                    wire_len: 32,
                }),
                Actor::Device,
                Rule::ResponseCorrelation,
            )
        }
        "legal-short-rejection" => {
            let mut monitor = model();
            let req = request(0x20006, &0xdead_u64.to_le_bytes(), 64);
            let reply = response(&req, &[], 1);
            exchange(&mut monitor, &req, &reply, 64)
        }
        "driver-declaration" => {
            let mut monitor = model();
            let mut body = [0; 600];
            put64(&mut body, 0, 1);
            put64(&mut body, 8, 3);
            put64(&mut body, 16, 0x27eca6f);
            put64(&mut body, 48, 0x300050000001f);
            put32(&mut body, 56, 16);
            body[88..93].copy_from_slice(b"Linux");
            body[216..226].copy_from_slice(b"kernel-nvr");
            body[344..359].copy_from_slice(b"kernel identity");
            let req = request(1, &body, 72);
            no_finding(monitor.observe(Event::HwcRequest {
                bytes: &req,
                wire_len: 640,
                receive_capacity: 72,
            }))?;
            let report = monitor.report();
            let declaration = report
                .driver_declaration
                .ok_or("missing independently encoded declaration")?;
            require(
                declaration.driver_version == 0x300050000001f
                    && declaration.os_type == 16
                    && declaration.capabilities == [0x27eca6f, 0, 0, 0]
                    && declaration.os_version_strings
                        == ["Linux", "kernel-nvr", "kernel identity", ""],
                "driver declaration changed its raw wire meaning",
            )?;
            no_finding(monitor.observe(Event::Reset))?;
            require(
                monitor.report().driver_declaration.is_none(),
                "reset retained a stale driver declaration",
            )?;
            body[216] = 0xff;
            let req = request(1, &body, 72);
            no_finding(monitor.observe(Event::HwcRequest {
                bytes: &req,
                wire_len: 640,
                receive_capacity: 72,
            }))?;
            require(
                monitor.report().driver_declaration.is_none()
                    && monitor.report().findings.is_empty(),
                "undecodable identity became an attestation or protocol accusation",
            )
        }
        "resource-transfer" => {
            let mut monitor = model();
            let mut req = region_request(1, 1);
            // A PF may advertise the fixed base while posting its page trailer.
            put32(&mut req, 12, 64);
            let reply = response(&req, &1u64.to_le_bytes(), 0);
            exchange(&mut monitor, &req, &reply, 40)?;
            let eq = bind(&mut monitor, QueueKind::Eq, 24, 32)?;
            let mut create = [0; 56];
            put32(&mut create, 0, 4);
            put64(&mut create, 16, 1);
            put32(&mut create, 28, 32);
            let req = request(12, &create, 36);
            let reply = response(&req, &eq.id.to_le_bytes(), 0);
            exchange(&mut monitor, &req, &reply, 36)?;
            // The consumed free handle may be reused for a new declaration.
            let req = region_request(1, 1);
            let reply = response(&req, &1u64.to_le_bytes(), 0);
            exchange(&mut monitor, &req, &reply, 40)
        }
        "region-continuation" => {
            let mut monitor = model();
            let req = region_request(2, 1);
            let reply = response(&req, &7u64.to_le_bytes(), 0);
            exchange(&mut monitor, &req, &reply, 40)?;
            let mut pages = [0; 24];
            put64(&mut pages, 0, 7);
            put32(&mut pages, 8, 1);
            put64(&mut pages, 16, 0x20_0000);
            let req = request(26, &pages, 32);
            let reply = response(&req, &[], 0);
            exchange(&mut monitor, &req, &reply, 32)?;
            let mut create = [0; 56];
            put32(&mut create, 0, 4);
            put64(&mut create, 16, 7);
            put32(&mut create, 28, 8192);
            let eq = bind(&mut monitor, QueueKind::Eq, 25, 8192)?;
            let req = request(12, &create, 36);
            let reply = response(&req, &eq.id.to_le_bytes(), 0);
            exchange(&mut monitor, &req, &reply, 36)
        }
        "declined-resource-request" => {
            let mut monitor = model();
            let req = request(27, &0xdeadu64.to_le_bytes(), 32);
            exchange(&mut monitor, &req, &response(&req, &[], 1), 32)?;
            no_finding(monitor.observe(Event::HwcRequest {
                bytes: &req,
                wire_len: req.len() as u64,
                receive_capacity: 32,
            }))?;
            finding(
                monitor.observe(Event::HwcResponse {
                    bytes: &response(&req, &[], 0),
                    wire_len: 32,
                }),
                Actor::Device,
                Rule::ResourceOwnership,
            )
        }
        "unknown-forms" => {
            let mut monitor = model();
            let sq = bind(&mut monitor, QueueKind::Sq, 24, 64)?;
            no_finding(db(&mut monitor, sq, 32, false))?;
            no_finding(monitor.observe(Event::WorkHeader {
                queue: sq,
                position: 0,
                header: &[0; 8],
            }))?;
            let mut req = request(3, &[], 32);
            put32(&mut req, 0, 7);
            no_finding(monitor.observe(Event::HwcRequest {
                bytes: &req,
                wire_len: 40,
                receive_capacity: 32,
            }))?;
            require(
                monitor.report().incomplete_observations >= 2,
                "unknown forms were treated as checked",
            )
        }
        "bounded-evidence" => {
            let mut monitor = model();
            for id in 100..200 {
                let key = QueueKey {
                    kind: QueueKind::Sq,
                    id,
                };
                finding(
                    db(&mut monitor, key, 32, false),
                    Actor::Guest,
                    Rule::QueueLifetime,
                )?;
            }
            let report = monitor.report();
            require(
                report.findings.len() == 64 && report.omitted_findings == 36,
                "evidence was not bounded or loss was hidden",
            )?;
            monitor.observe(Event::Reset);
            let report = monitor.report();
            require(
                report.epoch == 1 && report.findings.len() == 64,
                "reset erased prior incidents",
            )
        }
        _ => Err(format!("unknown contract case {name}")),
    };
    result.map_err(|error| format!("{name}: {error}"))
}

#[cfg(not(test))]
fn main() -> std::process::ExitCode {
    let selected = std::env::args().nth(1);
    let cases: Vec<_> = selected
        .as_deref()
        .map_or_else(|| CASES.to_vec(), |name| vec![name]);
    for case in cases {
        if let Err(error) = run_case(case) {
            eprintln!("{error}");
            return std::process::ExitCode::FAILURE;
        }
        println!("GDMA contract case passed: {case}");
    }
    std::process::ExitCode::SUCCESS
}
