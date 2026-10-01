// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! An independent, passive contract over observed GDMA boundary events.
//!
//! This crate does not call the emulator's codecs, admission checks, or resource
//! ledger. It decodes the observed legacy wire prefixes and maintains its own
//! state. Findings distinguish the guest from the device; incomplete observations
//! and unsupported forms do not become compliance or violations.

#![forbid(unsafe_code)]
#![expect(missing_docs)]

#[cfg(test)]
extern crate self as gdma_contract;

use std::collections::BTreeMap;
use std::collections::VecDeque;

const MAX_RESOURCES: usize = 2048;
const MAX_FINDINGS: usize = 64;
const WORK_ALIGNMENT: u32 = 32;
const OWNER_PHASES: u32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actor {
    Guest,
    Device,
}

/// Whether consumer releases other than notification publications are observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationScope {
    /// Native guest memory reads are not intercepted.
    ConsumerPublicationsOnly,
    /// A controlled trace supplies every consumer release.
    CompleteConsumerTrace,
}

impl ObservationScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConsumerPublicationsOnly => "consumer-publications-only",
            Self::CompleteConsumerTrace => "complete-consumer-trace",
        }
    }
}

impl Actor {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Guest => "guest",
            Self::Device => "device",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum QueueKind {
    Sq,
    Rq,
    Cq,
    Eq,
}

impl QueueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sq => "sq",
            Self::Rq => "rq",
            Self::Cq => "cq",
            Self::Eq => "eq",
        }
    }

    fn from_wire(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Sq),
            2 => Some(Self::Rq),
            3 => Some(Self::Cq),
            4 => Some(Self::Eq),
            _ => None,
        }
    }

    fn entry_size(self) -> u32 {
        match self {
            Self::Sq | Self::Rq => WORK_ALIGNMENT,
            Self::Cq => 64,
            Self::Eq => 16,
        }
    }

    fn is_work(self) -> bool {
        matches!(self, Self::Sq | Self::Rq)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QueueKey {
    pub kind: QueueKind,
    pub id: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct QueueDescriptor {
    pub key: QueueKey,
    pub bytes: u64,
    pub parent_eq: Option<u32>,
    pub msix: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum Rule {
    SharedMemoryWidth,
    DoorbellWidth,
    QueueGeometry,
    QueueLifetime,
    WorkPublication,
    WorkDescriptor,
    WorkConsumption,
    CompletionWindow,
    CompletionOwner,
    CompletionStorage,
    CompletionRoute,
    ConsumerWindow,
    SmcCorrelation,
    RequestEnvelope,
    ResponseEnvelope,
    ResponseCorrelation,
    ResourceOwnership,
    HwcInitialization,
}

pub const RULES: [Rule; 18] = [
    Rule::SharedMemoryWidth,
    Rule::DoorbellWidth,
    Rule::QueueGeometry,
    Rule::QueueLifetime,
    Rule::WorkPublication,
    Rule::WorkDescriptor,
    Rule::WorkConsumption,
    Rule::CompletionWindow,
    Rule::CompletionOwner,
    Rule::CompletionStorage,
    Rule::CompletionRoute,
    Rule::ConsumerWindow,
    Rule::SmcCorrelation,
    Rule::RequestEnvelope,
    Rule::ResponseEnvelope,
    Rule::ResponseCorrelation,
    Rule::ResourceOwnership,
    Rule::HwcInitialization,
];

impl Rule {
    pub fn id(self) -> &'static str {
        match self {
            Self::SharedMemoryWidth => "gdma.smc.dword-publication",
            Self::DoorbellWidth => "gdma.doorbell.atomic-publication",
            Self::QueueGeometry => "gdma.queue.bound-geometry",
            Self::QueueLifetime => "gdma.queue.live-namespace",
            Self::WorkPublication => "gdma.wq.published-window",
            Self::WorkDescriptor => "gdma.wq.descriptor-extent",
            Self::WorkConsumption => "gdma.device.published-consumption",
            Self::CompletionWindow => "gdma.device.completion-window",
            Self::CompletionOwner => "gdma.device.owner-phase",
            Self::CompletionStorage => "gdma.device.owner-last-publication",
            Self::CompletionRoute => "gdma.device.completion-route",
            Self::ConsumerWindow => "gdma.cqeq.consumer-generation",
            Self::SmcCorrelation => "gdma.device.smc-response",
            Self::RequestEnvelope => "gdma.hwc.request-envelope",
            Self::ResponseEnvelope => "gdma.device.response-envelope",
            Self::ResponseCorrelation => "gdma.device.response-correlation",
            Self::ResourceOwnership => "gdma.device.resource-transition",
            Self::HwcInitialization => "gdma.device.hwc-initialization",
        }
    }

    pub fn obligation(self) -> &'static str {
        match self {
            Self::SharedMemoryWidth => "SMC publication uses aligned DWORD writes",
            Self::DoorbellWidth => "a doorbell is one aligned eight-byte publication",
            Self::QueueGeometry => {
                "a bound ring has usable geometry and an admitted interrupt target"
            }
            Self::QueueLifetime => "queue identities are type-qualified and live",
            Self::WorkPublication => "the aligned published span fits the admitted work ring",
            Self::WorkDescriptor => "a legacy WQE fits its direction limit and published extent",
            Self::WorkConsumption => "consumption makes aligned progress within published work",
            Self::CompletionWindow => "publication does not overwrite unconsumed completions",
            Self::CompletionOwner => "a published owner matches the ring's three-bit phase",
            Self::CompletionStorage => "the device does not publish an owner before its entry body",
            Self::CompletionRoute => "a completion names the bound live work queue",
            Self::ConsumerWindow => "a consumer publication is within the observed producer window",
            Self::SmcCorrelation => "SMC completion correlates and returns possession",
            Self::RequestEnvelope => "a standard HWC request fits posted and advertised storage",
            Self::ResponseEnvelope => {
                "a standard response fits the posted receive and requested bound"
            }
            Self::ResponseCorrelation => "the response retains the requested correlation fields",
            Self::ResourceOwnership => {
                "successful resource replies realize a safe known transition"
            }
            Self::HwcInitialization => "published HWC identity data names the bound channel queues",
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RuleStatistics {
    pub satisfied: u64,
    pub guest_violations: u64,
    pub device_violations: u64,
    pub inconclusive: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finding {
    pub rule: Rule,
    pub actor: Actor,
    pub sequence: u64,
    pub epoch: u64,
    pub queue: Option<QueueKey>,
    /// Rule-specific scalar witnesses, not a copy of guest packet contents.
    pub evidence: [u64; 3],
}

#[derive(Debug, Clone)]
pub struct Report {
    pub scope: ObservationScope,
    pub epoch: u64,
    pub observations: u64,
    pub statistics: [RuleStatistics; RULES.len()],
    pub findings: Vec<Finding>,
    pub omitted_findings: u64,
    pub uncovered_commands: u64,
    pub incomplete_observations: u64,
    pub tracking_complete: bool,
    pub resource_tracking_complete: bool,
}

/// Obligations for which this monitor deliberately supplies no verdict.
pub const UNOBSERVABLE: &[&str] = &[
    "guest OS DMA unmap, allocation, and free",
    "guest CPU barriers and physical PCIe/cache ordering",
    "memory-key resolution and address-translation permissions",
    "packet offload transformations and RSS correctness",
    "per-packet completion/fence-to-buffer release correlation",
    "unmodeled command versions, reserved encodings, and scheduling liveness",
];

#[derive(Debug, Clone, Copy)]
pub enum MmioSpace {
    SharedMemory,
    Doorbell,
}

#[derive(Debug, Clone, Copy)]
pub enum Event<'a> {
    MmioWrite {
        space: MmioSpace,
        offset: u64,
        data: &'a [u8],
    },
    SmcResponse(u32),
    QueueBound(QueueDescriptor),
    QueueReleased(QueueKey),
    EqRoute {
        id: u32,
        msix: u32,
    },
    WorkHeader {
        queue: QueueKey,
        position: u32,
        header: &'a [u8],
    },
    WorkConsumed {
        queue: QueueKey,
        position: u32,
        bytes: u32,
    },
    Completion {
        queue: QueueKey,
        entry: &'a [u8],
        body_written: bool,
        owner_written: bool,
    },
    HwcRequest {
        bytes: &'a [u8],
        wire_len: u64,
        receive_capacity: u64,
    },
    HwcResponse {
        bytes: &'a [u8],
        wire_len: u64,
    },
    ObservationUnavailable(Rule),
    Reset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QueueState {
    bytes: u32,
    producer: u32,
    consumer: u32,
    completion_queue: Option<u32>,
    parent_eq: Option<u32>,
    header_extent: Option<u32>,
    geometry_known: bool,
    peer_tainted: bool,
    completion_window_known: bool,
}

impl QueueState {
    fn capacity(self, kind: QueueKind) -> u32 {
        self.bytes / kind.entry_size()
    }

    fn phase_mask(self, kind: QueueKind) -> u32 {
        self.capacity(kind) * OWNER_PHASES - 1
    }
}

#[derive(Debug, Clone, Copy)]
struct Region {
    bytes: u64,
    pages: u32,
    received: u32,
    valid: bool,
}

#[derive(Debug, Clone, Copy)]
struct WorkObject {
    work: QueueKey,
    cq: u32,
}

#[derive(Debug, Clone, Copy)]
enum Command {
    CreateRegion(Region),
    AddPages {
        region: u64,
        pages: u32,
        valid: bool,
    },
    DestroyRegion(u64),
    CreateQueue {
        kind: QueueKind,
        region: u64,
        bytes: u32,
    },
    DisableQueue(QueueKey),
    CreateWork {
        kind: QueueKind,
        work_region: u64,
        completion_region: u64,
        work_bytes: u32,
        completion_bytes: u32,
        eq: u32,
    },
    DestroyWork {
        kind: QueueKind,
        object: u64,
    },
    Fence(u64),
    Malformed,
}

#[derive(Debug, Clone, Copy)]
struct Request {
    code: u32,
    reply_type: u32,
    reply_id: u16,
    device: u32,
    activity: u32,
    capacity: u64,
    limit: u64,
    command: Option<Command>,
}

#[derive(Debug, Clone, Copy, Default)]
struct Bootstrap {
    eq: Option<u32>,
    cq: Option<u32>,
    sq: Option<u32>,
    rq: Option<u32>,
}

/// A side-effect-free observer. A finding never changes device admission.
#[derive(Debug, Clone)]
pub struct Monitor {
    scope: ObservationScope,
    epoch: u64,
    sequence: u64,
    msix_vectors: u32,
    statistics: [RuleStatistics; RULES.len()],
    findings: VecDeque<Finding>,
    omitted_findings: u64,
    uncovered_commands: u64,
    incomplete_observations: u64,
    tracking_complete: bool,
    resource_tracking_complete: bool,
    queues: BTreeMap<QueueKey, QueueState>,
    regions: BTreeMap<u64, Region>,
    objects: BTreeMap<u64, WorkObject>,
    shared_memory: [u8; 32],
    pending_smc: Option<(u8, bool)>,
    bootstrap: Bootstrap,
    channel_active: bool,
    max_request: u32,
    max_response: u32,
    request: Option<Request>,
}

impl Monitor {
    pub fn new(msix_vectors: u32, scope: ObservationScope) -> Self {
        Self {
            scope,
            epoch: 0,
            sequence: 0,
            msix_vectors,
            statistics: [RuleStatistics::default(); RULES.len()],
            findings: VecDeque::new(),
            omitted_findings: 0,
            uncovered_commands: 0,
            incomplete_observations: 0,
            tracking_complete: true,
            resource_tracking_complete: true,
            queues: BTreeMap::new(),
            regions: BTreeMap::new(),
            objects: BTreeMap::new(),
            shared_memory: [0; 32],
            pending_smc: None,
            bootstrap: Bootstrap::default(),
            channel_active: false,
            max_request: 0,
            max_response: 0,
            request: None,
        }
    }

    pub fn report(&self) -> Report {
        Report {
            scope: self.scope,
            epoch: self.epoch,
            observations: self.sequence,
            statistics: self.statistics,
            findings: self.findings.iter().copied().collect(),
            omitted_findings: self.omitted_findings,
            uncovered_commands: self.uncovered_commands,
            incomplete_observations: self.incomplete_observations,
            tracking_complete: self.tracking_complete,
            resource_tracking_complete: self.resource_tracking_complete,
        }
    }

    pub fn observe(&mut self, event: Event<'_>) -> Option<Finding> {
        self.sequence = self.sequence.saturating_add(1);
        match event {
            Event::MmioWrite {
                space,
                offset,
                data,
            } => self.mmio(space, offset, data),
            Event::SmcResponse(header) => self.smc_response(header),
            Event::QueueBound(descriptor) => self.bind_queue(descriptor),
            Event::QueueReleased(key) => {
                self.queues.remove(&key);
                None
            }
            Event::EqRoute { id, msix } => self.check(
                Rule::QueueGeometry,
                Actor::Device,
                msix < self.msix_vectors,
                Some(QueueKey {
                    kind: QueueKind::Eq,
                    id,
                }),
                [msix.into(), self.msix_vectors.into(), 0],
            ),
            Event::WorkHeader {
                queue,
                position,
                header,
            } => self.work_header(queue, position, header),
            Event::WorkConsumed {
                queue,
                position,
                bytes,
            } => self.consume(queue, position, bytes),
            Event::Completion {
                queue,
                entry,
                body_written,
                owner_written,
            } => self.complete(queue, entry, body_written, owner_written),
            Event::HwcRequest {
                bytes,
                wire_len,
                receive_capacity,
            } => self.control_request(bytes, wire_len, receive_capacity),
            Event::HwcResponse { bytes, wire_len } => self.control_response(bytes, wire_len),
            Event::ObservationUnavailable(rule) => {
                if matches!(
                    rule,
                    Rule::RequestEnvelope | Rule::ResponseEnvelope | Rule::ResourceOwnership
                ) {
                    self.resource_tracking_complete = false;
                }
                self.inconclusive(rule);
                None
            }
            Event::Reset => {
                self.epoch = self.epoch.saturating_add(1);
                self.queues.clear();
                self.regions.clear();
                self.objects.clear();
                self.pending_smc = None;
                self.bootstrap = Bootstrap::default();
                self.channel_active = false;
                self.max_request = 0;
                self.max_response = 0;
                self.request = None;
                self.shared_memory = [0; 32];
                self.tracking_complete = true;
                self.resource_tracking_complete = true;
                None
            }
        }
    }

    fn check(
        &mut self,
        rule: Rule,
        actor: Actor,
        condition: bool,
        queue: Option<QueueKey>,
        evidence: [u64; 3],
    ) -> Option<Finding> {
        let stat = &mut self.statistics[rule as usize];
        if condition {
            stat.satisfied = stat.satisfied.saturating_add(1);
            return None;
        }
        match actor {
            Actor::Guest => stat.guest_violations = stat.guest_violations.saturating_add(1),
            Actor::Device => stat.device_violations = stat.device_violations.saturating_add(1),
        }
        let finding = Finding {
            rule,
            actor,
            sequence: self.sequence,
            epoch: self.epoch,
            queue,
            evidence,
        };
        if self.findings.len() == MAX_FINDINGS {
            self.findings.pop_front();
            self.omitted_findings = self.omitted_findings.saturating_add(1);
        }
        self.findings.push_back(finding);
        Some(finding)
    }

    fn inconclusive(&mut self, rule: Rule) {
        let stat = &mut self.statistics[rule as usize];
        stat.inconclusive = stat.inconclusive.saturating_add(1);
        self.incomplete_observations = self.incomplete_observations.saturating_add(1);
    }

    fn queue(
        &mut self,
        key: QueueKey,
        actor: Actor,
        rule: Rule,
    ) -> Result<QueueState, Option<Finding>> {
        match self.queues.get(&key).copied() {
            Some(state) if state.geometry_known => Ok(state),
            Some(_) => {
                self.inconclusive(rule);
                Err(None)
            }
            None if !self.tracking_complete => {
                self.inconclusive(rule);
                Err(None)
            }
            None => Err(self.check(
                Rule::QueueLifetime,
                actor,
                false,
                Some(key),
                [key.id.into(), 0, 0],
            )),
        }
    }

    fn mmio(&mut self, space: MmioSpace, offset: u64, data: &[u8]) -> Option<Finding> {
        match space {
            MmioSpace::SharedMemory => {
                let valid = data.len() == 4 && offset.is_multiple_of(4) && offset <= 28;
                let finding = self.check(
                    Rule::SharedMemoryWidth,
                    Actor::Guest,
                    valid,
                    None,
                    [offset, data.len() as u64, 4],
                );
                if !valid {
                    return finding;
                }
                let start = offset as usize;
                self.shared_memory[start..start + 4].copy_from_slice(data);
                if offset == 28 {
                    let header = read32(&self.shared_memory, 28)?;
                    self.pending_smc = Some(((header & 7) as u8, self.channel_active));
                }
                finding
            }
            MmioSpace::Doorbell => {
                let base = [0, 0x400, 0x800, 0xff8]
                    .into_iter()
                    .find(|base| offset >= *base && offset < *base + 8);
                let Some(base) = base else {
                    self.inconclusive(Rule::DoorbellWidth);
                    return None;
                };
                let valid = data.len() == 8 && offset == base;
                let finding = self.check(
                    Rule::DoorbellWidth,
                    Actor::Guest,
                    valid,
                    None,
                    [offset, data.len() as u64, 8],
                );
                if !valid {
                    return finding;
                }
                let value = read64(data, 0)?;
                let kind = match base {
                    0 => QueueKind::Sq,
                    0x400 => QueueKind::Rq,
                    0x800 => QueueKind::Cq,
                    0xff8 => QueueKind::Eq,
                    _ => {
                        self.inconclusive(Rule::DoorbellWidth);
                        return None;
                    }
                };
                let key = QueueKey {
                    kind,
                    id: value as u32 & 0xff_ffff,
                };
                let tail = (value >> 32) as u32;
                if kind.is_work() {
                    self.publish(key, tail)
                } else if value & (1 << 63) == 0 {
                    // An unarmed notification write is not evidence that the
                    // guest has released any particular completion prefix.
                    self.inconclusive(Rule::ConsumerWindow);
                    None
                } else {
                    self.consumer(key, tail & 0x7fff_ffff)
                }
            }
        }
    }

    fn smc_response(&mut self, header: u32) -> Option<Finding> {
        let Some((kind, was_active)) = self.pending_smc.take() else {
            self.inconclusive(Rule::SmcCorrelation);
            return None;
        };
        let success = (header >> 8) & 0xff == 0;
        let valid = header & 7 == u32::from(kind)
            && header & (1 << 7) != 0
            && header & (1 << 31) == 0
            && !(success && kind == 1 && was_active);
        let finding = self.check(
            Rule::SmcCorrelation,
            Actor::Device,
            valid,
            None,
            [header.into(), kind.into(), u64::from(was_active)],
        );
        if success && valid {
            match kind {
                1 => self.channel_active = true,
                2 => {
                    self.channel_active = false;
                    self.request = None;
                    self.regions.clear();
                    self.objects.clear();
                }
                _ => {}
            }
        }
        finding
    }

    fn bind_queue(&mut self, descriptor: QueueDescriptor) -> Option<Finding> {
        let key = descriptor.key;
        let unit = key.kind.entry_size();
        let minimum = if key.kind.is_work() { unit } else { unit * 2 };
        let valid = descriptor.bytes >= u64::from(minimum)
            && descriptor.bytes <= u64::from(u32::MAX)
            && descriptor.bytes.is_power_of_two()
            && key.id < (1 << 24)
            && descriptor
                .msix
                .is_none_or(|index| index < self.msix_vectors);
        let mut finding = self.check(
            Rule::QueueGeometry,
            Actor::Device,
            valid,
            Some(key),
            [
                descriptor.bytes,
                minimum.into(),
                descriptor.msix.map_or(u64::MAX, u64::from),
            ],
        );
        if self.queues.contains_key(&key) {
            finding = self.check(
                Rule::QueueLifetime,
                Actor::Device,
                false,
                Some(key),
                [key.id.into(), 1, 0],
            );
        }
        if self.queues.len() >= MAX_RESOURCES && !self.queues.contains_key(&key) {
            self.tracking_complete = false;
            self.inconclusive(Rule::QueueLifetime);
            return finding;
        }
        let bytes = u32::try_from(descriptor.bytes).unwrap_or(0);
        let start = if key.kind.is_work() { 0 } else { bytes / unit };
        self.queues.insert(
            key,
            QueueState {
                bytes,
                producer: start,
                consumer: start,
                completion_queue: None,
                parent_eq: descriptor.parent_eq,
                header_extent: None,
                geometry_known: valid,
                peer_tainted: !valid,
                completion_window_known: true,
            },
        );
        if let Some(parent) = descriptor.parent_eq {
            if self.tracking_complete
                && !self.queues.contains_key(&QueueKey {
                    kind: QueueKind::Eq,
                    id: parent,
                })
            {
                // Reserved/no-notification parent forms are not interpreted.
                self.inconclusive(Rule::CompletionRoute);
            }
        }
        finding
    }

    fn publish(&mut self, key: QueueKey, tail: u32) -> Option<Finding> {
        let state = match self.queue(key, Actor::Guest, Rule::WorkPublication) {
            Ok(state) => state,
            Err(finding) => return finding,
        };
        if state.peer_tainted {
            self.inconclusive(Rule::WorkPublication);
            return None;
        }
        let old = state.producer.wrapping_sub(state.consumer);
        let new = tail.wrapping_sub(state.consumer);
        let valid = tail.is_multiple_of(WORK_ALIGNMENT) && new >= old && new <= state.bytes;
        let finding = self.check(
            Rule::WorkPublication,
            Actor::Guest,
            valid,
            Some(key),
            [tail.into(), state.consumer.into(), state.bytes.into()],
        );
        if valid && let Some(queue) = self.queues.get_mut(&key) {
            queue.producer = tail;
        }
        finding
    }

    fn work_header(&mut self, key: QueueKey, position: u32, header: &[u8]) -> Option<Finding> {
        let state = match self.queue(key, Actor::Device, Rule::WorkDescriptor) {
            Ok(state) => state,
            Err(finding) => return finding,
        };
        if !key.kind.is_work() {
            self.inconclusive(Rule::WorkDescriptor);
            return None;
        }
        if state.peer_tainted {
            self.inconclusive(Rule::WorkDescriptor);
            return None;
        }
        if position != state.consumer || state.producer.wrapping_sub(state.consumer) < 8 {
            if let Some(queue) = self.queues.get_mut(&key) {
                queue.peer_tainted = true;
            }
            return self.check(
                Rule::WorkConsumption,
                Actor::Device,
                false,
                Some(key),
                [position.into(), state.consumer.into(), 0],
            );
        }
        let Some(parameters) = read32(header, 4) else {
            self.inconclusive(Rule::WorkDescriptor);
            return None;
        };
        let oob = match (parameters >> 8) & 7 {
            2 => 8,
            6 => 24,
            7 => 32,
            _ => {
                self.inconclusive(Rule::WorkDescriptor);
                if let Some(queue) = self.queues.get_mut(&key) {
                    queue.header_extent = None;
                }
                return None;
            }
        };
        let extent = (8 + oob + (parameters & 0xff) * 16 + 31) & !31;
        let limit = if key.kind == QueueKind::Sq { 512 } else { 256 };
        let available = state.producer.wrapping_sub(state.consumer);
        let valid = extent <= limit && extent <= available;
        let finding = self.check(
            Rule::WorkDescriptor,
            Actor::Guest,
            valid,
            Some(key),
            [extent.into(), available.into(), limit.into()],
        );
        if let Some(queue) = self.queues.get_mut(&key) {
            queue.header_extent = Some(extent);
        }
        finding
    }

    fn consume(&mut self, key: QueueKey, position: u32, bytes: u32) -> Option<Finding> {
        let state = match self.queue(key, Actor::Device, Rule::WorkConsumption) {
            Ok(state) => state,
            Err(finding) => return finding,
        };
        if !key.kind.is_work() {
            self.inconclusive(Rule::WorkConsumption);
            return None;
        }
        let valid = bytes != 0
            && bytes.is_multiple_of(WORK_ALIGNMENT)
            && position == state.consumer
            && bytes <= state.producer.wrapping_sub(state.consumer)
            && state.header_extent.is_none_or(|extent| bytes == extent);
        let finding = self.check(
            Rule::WorkConsumption,
            Actor::Device,
            valid,
            Some(key),
            [position.into(), bytes.into(), state.producer.into()],
        );
        if let Some(queue) = self.queues.get_mut(&key) {
            queue.consumer = position.wrapping_add(bytes);
            queue.header_extent = None;
            queue.peer_tainted |= !valid;
        }
        finding
    }

    fn consumer(&mut self, key: QueueKey, tail: u32) -> Option<Finding> {
        let state = match self.queue(key, Actor::Guest, Rule::ConsumerWindow) {
            Ok(state) => state,
            Err(finding) => return finding,
        };
        if key.kind.is_work() || state.peer_tainted {
            self.inconclusive(Rule::ConsumerWindow);
            return None;
        }
        let mask = state.phase_mask(key.kind);
        let distance = state.producer.wrapping_sub(tail) & mask;
        let previous = state.producer.wrapping_sub(state.consumer) & mask;
        let valid = distance <= state.capacity(key.kind);
        let finding = self.check(
            Rule::ConsumerWindow,
            Actor::Guest,
            valid,
            Some(key),
            [
                tail.into(),
                state.producer.into(),
                state.capacity(key.kind).into(),
            ],
        );
        if valid && let Some(queue) = self.queues.get_mut(&key) {
            // A stale rearm hint does not retract a previously observed
            // release. A fresh hint can recover an incomplete native window.
            let released = if state.completion_window_known {
                distance.min(previous)
            } else {
                distance
            };
            queue.consumer = state.producer.wrapping_sub(released) & mask;
            queue.completion_window_known = true;
        }
        finding
    }

    fn complete(
        &mut self,
        key: QueueKey,
        entry: &[u8],
        body: bool,
        owner: bool,
    ) -> Option<Finding> {
        let state = match self.queue(key, Actor::Device, Rule::CompletionWindow) {
            Ok(state) => state,
            Err(finding) => return finding,
        };
        if key.kind.is_work() {
            self.inconclusive(Rule::CompletionWindow);
            return None;
        }
        if entry.len() != key.kind.entry_size() as usize {
            return self.check(
                Rule::CompletionStorage,
                Actor::Device,
                false,
                Some(key),
                [entry.len() as u64, key.kind.entry_size().into(), 0],
            );
        }
        let Some(parameters) = read32(entry, entry.len() - 4) else {
            self.inconclusive(Rule::CompletionStorage);
            return None;
        };
        let capacity = state.capacity(key.kind);
        let mask = state.phase_mask(key.kind);
        let used = state.producer.wrapping_sub(state.consumer) & mask;
        let window_known = state.completion_window_known && used < capacity;
        let mut finding = if self.scope == ObservationScope::CompleteConsumerTrace || window_known {
            self.check(
                Rule::CompletionWindow,
                Actor::Device,
                used < capacity,
                Some(key),
                [used.into(), capacity.into(), state.producer.into()],
            )
        } else {
            self.inconclusive(Rule::CompletionWindow);
            None
        };
        let observed_owner = parameters >> 29;
        let expected_owner = (state.producer / capacity) & 7;
        if let Some(value) = self.check(
            Rule::CompletionOwner,
            Actor::Device,
            observed_owner == expected_owner,
            Some(key),
            [
                observed_owner.into(),
                expected_owner.into(),
                state.producer.into(),
            ],
        ) {
            finding = Some(value);
        }
        if let Some(value) = self.check(
            Rule::CompletionStorage,
            Actor::Device,
            body && owner,
            Some(key),
            [u64::from(body), u64::from(owner), 0],
        ) {
            finding = Some(value);
        }
        if key.kind == QueueKind::Cq {
            let work = QueueKey {
                kind: if parameters & (1 << 24) != 0 {
                    QueueKind::Sq
                } else {
                    QueueKind::Rq
                },
                id: parameters & 0xff_ffff,
            };
            if let Some(work_state) = self.queues.get(&work).copied() {
                if let Some(cq) = work_state.completion_queue
                    && let Some(value) = self.check(
                        Rule::CompletionRoute,
                        Actor::Device,
                        cq == key.id,
                        Some(work),
                        [key.id.into(), cq.into(), 0],
                    )
                {
                    finding = Some(value);
                } else if work_state.completion_queue.is_none() {
                    self.inconclusive(Rule::CompletionRoute);
                }
            } else if self.tracking_complete {
                finding = self.check(
                    Rule::CompletionRoute,
                    Actor::Device,
                    false,
                    Some(work),
                    [key.id.into(), 0, 0],
                );
            } else {
                self.inconclusive(Rule::CompletionRoute);
            }
        }
        if let Some(queue) = self.queues.get_mut(&key) {
            queue.producer = state.producer.wrapping_add(1) & mask;
            queue.peer_tainted |= finding.is_some();
            queue.completion_window_known = window_known;
        }
        if key.kind == QueueKind::Eq
            && body
            && owner
            && let Some(value) = self.bootstrap_entry(key, parameters as u8, &entry[..12])
        {
            finding = Some(value);
        }
        finding
    }

    fn bootstrap_entry(&mut self, eq: QueueKey, event_type: u8, data: &[u8]) -> Option<Finding> {
        let word = read32(data, 0)?;
        match event_type {
            129 => {
                let id = word & 0xffff;
                self.bootstrap.eq = Some(id);
                self.check(
                    Rule::HwcInitialization,
                    Actor::Device,
                    id == eq.id,
                    Some(eq),
                    [id.into(), eq.id.into(), 0],
                )
            }
            130 => {
                let value = word & 0xff_ffff;
                match word >> 24 {
                    1 => self.bootstrap.cq = Some(value),
                    2 => self.bootstrap.rq = Some(value),
                    3 => self.bootstrap.sq = Some(value),
                    5 => self.max_request = value,
                    6 => self.max_response = value,
                    _ => {}
                }
                None
            }
            131 => {
                let Bootstrap {
                    eq: eq_id,
                    cq,
                    sq,
                    rq,
                } = self.bootstrap;
                let (Some(eq_id), Some(cq), Some(sq), Some(rq)) = (eq_id, cq, sq, rq) else {
                    self.inconclusive(Rule::HwcInitialization);
                    return None;
                };
                let valid = eq_id == eq.id
                    && self.queues.contains_key(&QueueKey {
                        kind: QueueKind::Cq,
                        id: cq,
                    })
                    && self.queues.contains_key(&QueueKey {
                        kind: QueueKind::Sq,
                        id: sq,
                    })
                    && self.queues.contains_key(&QueueKey {
                        kind: QueueKind::Rq,
                        id: rq,
                    });
                if valid {
                    self.channel_active = true;
                    for (kind, id) in [(QueueKind::Sq, sq), (QueueKind::Rq, rq)] {
                        if let Some(queue) = self.queues.get_mut(&QueueKey { kind, id }) {
                            queue.completion_queue = Some(cq);
                        }
                    }
                }
                self.check(
                    Rule::HwcInitialization,
                    Actor::Device,
                    valid,
                    Some(eq),
                    [cq.into(), sq.into(), rq.into()],
                )
            }
            _ => None,
        }
    }

    fn control_request(&mut self, bytes: &[u8], wire_len: u64, capacity: u64) -> Option<Finding> {
        if read32(bytes, 0).is_some_and(|format| format != 0)
            || read32(bytes, 16).is_some_and(|format| format != 0)
        {
            self.uncovered_commands = self.uncovered_commands.saturating_add(1);
            self.request = None;
            self.inconclusive(Rule::RequestEnvelope);
            return None;
        }
        let Some(mut request) = parse_request(bytes, capacity) else {
            self.request = None;
            if bytes.len() as u64 != wire_len {
                self.inconclusive(Rule::RequestEnvelope);
                return None;
            }
            return self.check(
                Rule::RequestEnvelope,
                Actor::Guest,
                false,
                None,
                [wire_len, 40, capacity],
            );
        };
        let declared = read32(bytes, 12).map(u64::from);
        let valid = wire_len >= 40
            && declared.is_some_and(|len| len >= 40 && len <= wire_len)
            && request.limit >= 32
            && request.limit <= capacity
            && (self.max_request == 0 || wire_len <= u64::from(self.max_request))
            && (self.max_response == 0 || request.limit <= u64::from(self.max_response));
        let mut finding = self.check(
            Rule::RequestEnvelope,
            Actor::Guest,
            valid,
            None,
            [wire_len, request.limit, capacity],
        );
        if self.request.is_some() {
            self.inconclusive(Rule::ResponseCorrelation);
        }
        if bytes.len() as u64 != wire_len {
            request.command = None;
            self.inconclusive(Rule::ResourceOwnership);
        }
        if request.command.is_none() {
            self.uncovered_commands = self.uncovered_commands.saturating_add(1);
        }
        if matches!(request.command, Some(Command::Malformed)) && bytes.len() as u64 == wire_len {
            finding = self.check(
                Rule::RequestEnvelope,
                Actor::Guest,
                false,
                None,
                [wire_len, 0, 0],
            );
        }
        self.request = Some(request);
        finding
    }

    fn control_response(&mut self, bytes: &[u8], wire_len: u64) -> Option<Finding> {
        let Some(request) = self.request.take() else {
            self.resource_tracking_complete = false;
            self.inconclusive(Rule::ResponseCorrelation);
            return None;
        };
        if read32(bytes, 0).is_some_and(|format| format != 0) {
            self.resource_tracking_complete = false;
            self.inconclusive(Rule::ResponseEnvelope);
            return None;
        }
        let valid = wire_len >= 32
            && wire_len <= request.capacity
            && wire_len <= request.limit
            && bytes.len() >= 32;
        let mut finding = self.check(
            Rule::ResponseEnvelope,
            Actor::Device,
            valid,
            None,
            [wire_len, request.capacity, request.limit],
        );
        if !valid {
            return finding;
        }
        let correlated = read32(bytes, 4) == Some(request.reply_type)
            && read16(bytes, 10) == Some(request.reply_id)
            && read32(bytes, 16) == Some(request.device)
            && read32(bytes, 20) == Some(request.activity);
        if let Some(value) = self.check(
            Rule::ResponseCorrelation,
            Actor::Device,
            correlated,
            None,
            [
                read32(bytes, 20).map_or(u64::MAX, u64::from),
                request.activity.into(),
                request.reply_id.into(),
            ],
        ) {
            finding = Some(value);
        }
        if !correlated || read32(bytes, 24) != Some(0) {
            return finding;
        }
        let changes_resources = matches!(
            request.code,
            12 | 13 | 25 | 26 | 27 | 0x20004 | 0x20005 | 0x20006
        );
        if request.command.is_none() && changes_resources {
            self.resource_tracking_complete = false;
            self.inconclusive(Rule::ResourceOwnership);
            return finding;
        }
        // Versions evolve independently. Only this implemented reply prefix is
        // interpreted; an unknown response is not an invalid device variation.
        if read16(bytes, 8) != Some(1) || bytes.len() as u64 != wire_len {
            if changes_resources {
                self.resource_tracking_complete = false;
            }
            self.inconclusive(Rule::ResourceOwnership);
            return finding;
        }
        if let Some(command) = request.command
            && let Some(value) = self.apply(command, &bytes[32..])
        {
            finding = Some(value);
        }
        finding
    }

    fn apply(&mut self, command: Command, body: &[u8]) -> Option<Finding> {
        let valid = match command {
            Command::Malformed => false,
            Command::CreateRegion(region) => {
                let Some(handle) = read64(body, 0) else {
                    return self.check(
                        Rule::ResourceOwnership,
                        Actor::Device,
                        false,
                        None,
                        [body.len() as u64, 8, 0],
                    );
                };
                let valid = region.valid && !self.regions.contains_key(&handle);
                if valid {
                    if self.regions.len() == MAX_RESOURCES {
                        self.resource_tracking_complete = false;
                        self.inconclusive(Rule::ResourceOwnership);
                        return None;
                    }
                    self.regions.insert(handle, region);
                }
                valid
            }
            Command::AddPages {
                region,
                pages,
                valid,
            } => {
                if let Some(entry) = self.regions.get_mut(&region) {
                    let total = entry.received.checked_add(pages);
                    let valid = valid
                        && entry.received < entry.pages
                        && total.is_some_and(|total| total <= entry.pages);
                    if valid && let Some(total) = total {
                        entry.received = total;
                    }
                    valid
                } else {
                    return self.missing_resource(region);
                }
            }
            Command::DestroyRegion(region) => {
                if self.regions.remove(&region).is_none() {
                    return self.missing_resource(region);
                }
                true
            }
            Command::CreateQueue {
                kind,
                region,
                bytes,
            } => {
                let Some(id) = read32(body, 0) else {
                    return self.check(
                        Rule::ResourceOwnership,
                        Actor::Device,
                        false,
                        None,
                        [body.len() as u64, 4, 0],
                    );
                };
                self.take_region(region, QueueKey { kind, id }, bytes)
            }
            Command::DisableQueue(key) => !self.queues.contains_key(&key),
            Command::CreateWork {
                kind,
                work_region,
                completion_region,
                work_bytes,
                completion_bytes,
                eq,
            } => {
                let Some(work_id) = read32(body, 0) else {
                    return self.check(
                        Rule::ResourceOwnership,
                        Actor::Device,
                        false,
                        None,
                        [body.len() as u64, 16, 0],
                    );
                };
                let Some(cq_id) = read32(body, 4) else {
                    return self.check(
                        Rule::ResourceOwnership,
                        Actor::Device,
                        false,
                        None,
                        [body.len() as u64, 16, 0],
                    );
                };
                let Some(object) = read64(body, 8) else {
                    return self.check(
                        Rule::ResourceOwnership,
                        Actor::Device,
                        false,
                        None,
                        [body.len() as u64, 16, 0],
                    );
                };
                let work = QueueKey { kind, id: work_id };
                let cq = QueueKey {
                    kind: QueueKind::Cq,
                    id: cq_id,
                };
                let valid = kind.is_work()
                    && !self.objects.contains_key(&object)
                    && work_region != completion_region
                    && self.regions.get(&work_region).is_some_and(|r| {
                        r.valid && r.received == r.pages && u64::from(work_bytes) <= r.bytes
                    })
                    && self.regions.get(&completion_region).is_some_and(|r| {
                        r.valid && r.received == r.pages && u64::from(completion_bytes) <= r.bytes
                    })
                    && self
                        .queues
                        .get(&work)
                        .is_some_and(|q| q.bytes == work_bytes)
                    && self
                        .queues
                        .get(&cq)
                        .is_some_and(|q| q.bytes == completion_bytes && q.parent_eq == Some(eq));
                if valid {
                    if self.objects.len() == MAX_RESOURCES {
                        self.resource_tracking_complete = false;
                        self.inconclusive(Rule::ResourceOwnership);
                        return None;
                    }
                    self.regions.remove(&work_region);
                    self.regions.remove(&completion_region);
                    self.objects.insert(object, WorkObject { work, cq: cq_id });
                    if let Some(queue) = self.queues.get_mut(&work) {
                        queue.completion_queue = Some(cq_id);
                    }
                }
                valid
            }
            Command::DestroyWork { kind, object } => {
                if let Some(entry) = self.objects.get(&object).copied() {
                    let valid = entry.work.kind == kind
                        && !self.queues.contains_key(&entry.work)
                        && !self.queues.contains_key(&QueueKey {
                            kind: QueueKind::Cq,
                            id: entry.cq,
                        });
                    if valid {
                        self.objects.remove(&object);
                    }
                    valid
                } else {
                    return self.missing_resource(object);
                }
            }
            Command::Fence(object) => {
                if let Some(entry) = self.objects.get(&object) {
                    entry.work.kind == QueueKind::Rq
                        && self.queues.contains_key(&entry.work)
                        && self.queues.contains_key(&QueueKey {
                            kind: QueueKind::Cq,
                            id: entry.cq,
                        })
                } else {
                    return self.missing_resource(object);
                }
            }
        };
        if !self.resource_tracking_complete && !valid && !matches!(command, Command::Malformed) {
            self.inconclusive(Rule::ResourceOwnership);
            return None;
        }
        self.check(
            Rule::ResourceOwnership,
            Actor::Device,
            valid,
            None,
            [0, 0, 0],
        )
    }

    fn take_region(&mut self, handle: u64, queue: QueueKey, bytes: u32) -> bool {
        let valid = self
            .regions
            .get(&handle)
            .is_some_and(|r| r.valid && r.received == r.pages && u64::from(bytes) <= r.bytes)
            && self.queues.get(&queue).is_some_and(|q| q.bytes == bytes);
        if valid {
            // A successful bind consumes the free handle, not the DMA backing.
            // Its numeric value may subsequently name a newly registered region.
            self.regions.remove(&handle);
        }
        valid
    }

    fn missing_resource(&mut self, handle: u64) -> Option<Finding> {
        if !self.resource_tracking_complete {
            self.inconclusive(Rule::ResourceOwnership);
            None
        } else {
            self.check(
                Rule::ResourceOwnership,
                Actor::Device,
                false,
                None,
                [handle, 0, 0],
            )
        }
    }
}

fn read16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn read32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn read64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}

fn parse_request(bytes: &[u8], capacity: u64) -> Option<Request> {
    let command = if read16(bytes, 8)? == 1 {
        parse_command(read32(bytes, 4)?, bytes.get(40..)?)
    } else {
        None
    };
    Some(Request {
        code: read32(bytes, 4)?,
        reply_type: read32(bytes, 20)?,
        reply_id: read16(bytes, 26)?,
        device: read32(bytes, 32)?,
        activity: read32(bytes, 36)?,
        capacity,
        limit: read32(bytes, 28)?.into(),
        command,
    })
}

fn parse_command(code: u32, body: &[u8]) -> Option<Command> {
    let decoded = || -> Option<Command> {
        let minimum = match code {
            25 => 24,
            26 => 16,
            27 | 0x20006 => 8,
            12 => 56,
            13 => 12,
            0x20004 => 48,
            0x20005 => 16,
            _ => return None,
        };
        if body.len() < minimum {
            return Some(Command::Malformed);
        }

        match code {
            25 => {
                let bytes = read64(body, 0)?;
                let offset = read32(body, 8)?;
                if read32(body, 12)? != 0 {
                    return None;
                }
                let pages = read32(body, 16)?;
                let received = read32(body, 20)?;
                let page_bytes = u64::from(pages) * 4096;
                let page_list = body.get(24..)?;
                let complete_list = u64::from(received) * 8 <= page_list.len() as u64;
                let aligned = page_list
                    .chunks_exact(8)
                    .take(received as usize)
                    .all(|address| read64(address, 0).is_some_and(|a| a.is_multiple_of(4096)));
                Some(Command::CreateRegion(Region {
                    bytes,
                    pages,
                    received,
                    valid: bytes != 0
                        && offset < 4096
                        && pages != 0
                        && received <= pages
                        && page_bytes
                            .checked_sub(offset.into())
                            .is_some_and(|capacity| bytes <= capacity)
                        && complete_list
                        && aligned,
                }))
            }
            26 => {
                let region = read64(body, 0)?;
                let pages = read32(body, 8)?;
                let list = body.get(16..)?;
                Some(Command::AddPages {
                    region,
                    pages,
                    valid: u64::from(pages) * 8 <= list.len() as u64
                        && list
                            .chunks_exact(8)
                            .take(pages as usize)
                            .all(|a| read64(a, 0).is_some_and(|a| a.is_multiple_of(4096))),
                })
            }
            27 => Some(Command::DestroyRegion(read64(body, 0)?)),
            12 => Some(Command::CreateQueue {
                kind: QueueKind::from_wire(read32(body, 0)?)?,
                region: read64(body, 16)?,
                bytes: read32(body, 28)?,
            }),
            13 => Some(Command::DisableQueue(QueueKey {
                kind: QueueKind::from_wire(read32(body, 0)?)?,
                id: read32(body, 4)?,
            })),
            0x20004 => Some(Command::CreateWork {
                kind: QueueKind::from_wire(read32(body, 8)?)?,
                work_region: read64(body, 16)?,
                completion_region: read64(body, 24)?,
                work_bytes: read32(body, 32)?,
                completion_bytes: read32(body, 36)?,
                eq: read32(body, 44)?,
            }),
            0x20005 => Some(Command::DestroyWork {
                kind: QueueKind::from_wire(read32(body, 0)?)?,
                object: read64(body, 8)?,
            }),
            0x20006 => Some(Command::Fence(read64(body, 0)?)),
            _ => None,
        }
    };
    match decoded() {
        Some(command) => Some(command),
        None if matches!(code, 12 | 13 | 25 | 26 | 27 | 0x20004 | 0x20005 | 0x20006) => {
            // Unknown page and queue forms are scope limits, not malformed
            // instances of the legacy forms this monitor understands.
            let unknown_form = (code == 25 && read32(body, 12).is_some_and(|p| p != 0))
                || (matches!(code, 12 | 13 | 0x20005)
                    && read32(body, 0).is_some_and(|k| QueueKind::from_wire(k).is_none()))
                || (code == 0x20004
                    && read32(body, 8).is_some_and(|k| QueueKind::from_wire(k).is_none()));
            if unknown_form {
                None
            } else {
                Some(Command::Malformed)
            }
        }
        None => None,
    }
}

#[cfg(test)]
mod tests;
