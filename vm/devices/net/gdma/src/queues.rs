// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::dma::DmaRegion;
use crate::protocol::ProtocolObserver;
use gdma_contract::Event;
use gdma_contract::QueueDescriptor;
use gdma_contract::QueueKey;
use gdma_contract::QueueKind;
use gdma_contract::Rule;
use gdma_defs::CqEqDoorbellValue;
use gdma_defs::Cqe;
use gdma_defs::CqeParams;
use gdma_defs::Eqe;
use gdma_defs::EqeParams;
use gdma_defs::GDMA_EQE_COMPLETION;
use gdma_defs::OWNER_BITS;
use gdma_defs::OWNER_MASK;
use gdma_defs::PAGE_SIZE64;
use gdma_defs::WQE_ALIGNMENT;
use gdma_defs::WqDoorbellValue;
use gdma_defs::Wqe;
use gdma_defs::WqeHeader;
use guestmem::GuestMemory;
use guestmem::MemoryRead;
use guestmem::MemoryWrite;
use guestmem::ranges::GuestMemoryView;
use inspect::Inspect;
use parking_lot::MappedMutexGuard;
use parking_lot::Mutex;
use parking_lot::MutexGuard;
use pci_core::capabilities::msix::MsixEmulator;
use std::marker::PhantomData;
use std::sync::atomic::Ordering::Release;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;
use thiserror::Error;
use vmcore::interrupt::Interrupt;
use vmcore::vm_task::VmTaskDriver;
use zerocopy::FromZeros;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

// Offset the queue IDs seen by the guest.
const ID_OFFSET: usize = 24;

struct CqEq<T> {
    region: DmaRegion,
    shift: u32,
    cap: u32,
    tail: u32,
    armed: bool,
    _phantom: PhantomData<fn(T)>,
}

impl<T> Inspect for CqEq<T> {
    fn inspect(&self, req: inspect::Request<'_>) {
        req.respond()
            .hex("size", self.cap)
            .hex("tail", self.tail)
            .field("armed", self.armed);
    }
}

#[derive(Debug, Error)]
pub enum QueueAllocError {
    #[error("invalid queue alignment")]
    InvalidAlignment,
    #[error("invalid queue length")]
    InvalidLen,
    #[error("out of queues")]
    NoMoreQueues,
    #[error("invalid MSI-X index {0}")]
    InvalidMsix(u32),
}

impl<T: IntoBytes + Immutable + KnownLayout> CqEq<T> {
    fn new(region: DmaRegion) -> Result<Self, QueueAllocError> {
        if !region.is_aligned_to(size_of::<T>()) {
            return Err(QueueAllocError::InvalidAlignment);
        }
        let len = region.len();
        if len < PAGE_SIZE64 as usize || len > u32::MAX as usize || !region.len().is_power_of_two()
        {
            return Err(QueueAllocError::InvalidLen);
        }

        let count = len as u32 / size_of::<T>() as u32;

        Ok(Self {
            region,
            shift: count.trailing_zeros(),
            cap: count,
            tail: count, // start with owner_count = 1
            armed: true, // start in armed state
            _phantom: PhantomData,
        })
    }

    fn owner_count(&self) -> u8 {
        ((self.tail >> self.shift) & OWNER_MASK) as u8
    }

    fn post(
        &mut self,
        gm: &GuestMemory,
        entry: &T,
        protocol: &ProtocolObserver,
        key: QueueKey,
    ) -> bool {
        let offset = (self.tail & (self.cap - 1)) as usize * size_of::<T>();
        let mut range = self.region.range();
        range.skip(offset);
        let mut writer = range.writer(gm);
        let raw = entry.as_bytes();
        let (entry, last) = raw.split_at(raw.len() - 1);
        if let Err(err) = writer.write(entry) {
            tracelimit::warn_ratelimited!(
                err = &err as &dyn std::error::Error,
                "failed to write entry"
            );
            protocol.observe(Event::ObservationUnavailable(Rule::CompletionStorage));
            return false;
        }
        // Write the final byte last after a release fence to ensure that the
        // guest sees the entire entry before the owner count is updated.
        std::sync::atomic::fence(Release);
        if let Err(err) = writer.write(last) {
            tracelimit::warn_ratelimited!(
                err = &err as &dyn std::error::Error,
                "failed to write last"
            );
            protocol.observe(Event::ObservationUnavailable(Rule::CompletionStorage));
            return false;
        }
        // Ensure the write is flushed before sending the interrupt.
        std::sync::atomic::fence(Release);
        protocol.observe(Event::Completion {
            queue: key,
            entry: raw,
            body_written: true,
            owner_written: true,
        });
        let new_tail = self.tail.wrapping_add(1);
        self.tail = new_tail;
        std::mem::take(&mut self.armed)
    }

    fn doorbell(&mut self, tail: u32, arm: bool) -> bool {
        if arm {
            let n = self.tail.wrapping_sub(tail) & ((self.cap << OWNER_BITS) - 1);
            if n == 0 {
                // The guest's tail matches our tail, so arm the queue.
                self.armed = true;
                false
            } else if n <= self.cap {
                // The guest's tail does not match, so trigger the queue action
                // immediately.
                self.armed = false;
                true
            } else {
                // Overflow condition. It seems that real hardware skips
                // notifying in this scenario.
                tracing::warn!(
                    tail = self.tail,
                    doorbell = tail,
                    "invalid doorbell, overflow likely"
                );
                false
            }
        } else {
            self.armed = false;
            false
        }
    }
}

#[derive(Inspect)]
struct Cq {
    #[inspect(flatten)]
    q: CqEq<Cqe>,
    eq_id: u32,
}

struct Eq {
    q: CqEq<Eqe>,
    msix: u32,
}

impl Inspect for Eq {
    fn inspect(&self, req: inspect::Request<'_>) {
        req.respond().field("msix", self.msix).merge(&self.q);
    }
}

struct Wq {
    region: DmaRegion,
    cap: u32,
    head: u32,
    tail: u32,
    waker: Option<Waker>,
}

impl Inspect for Wq {
    fn inspect(&self, req: inspect::Request<'_>) {
        req.respond()
            .hex("size", self.cap)
            .hex("head", self.head)
            .hex("tail", self.tail);
    }
}

impl Wq {
    fn new(mut region: DmaRegion) -> Result<Self, QueueAllocError> {
        if !region.is_aligned_to(PAGE_SIZE64 as usize) {
            return Err(QueueAllocError::InvalidAlignment);
        }
        let len = region.len();
        if len > u32::MAX as usize || !region.len().is_power_of_two() {
            return Err(QueueAllocError::InvalidLen);
        }

        // Double up the region to make it easier to access WQEs that straddle
        // the end of the region.
        region.double();

        Ok(Self {
            region,
            cap: len as u32,
            head: 0,
            tail: 0,
            waker: None,
        })
    }

    fn poll_wqe(
        &mut self,
        gm: &GuestMemory,
        cx: &mut Context<'_>,
        protocol: &ProtocolObserver,
        key: QueueKey,
    ) -> Poll<(u32, Wqe)> {
        if self.head == self.tail {
            self.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        tracing::trace!(head = self.head, tail = self.tail, "popping wqe");

        let head = self.head;
        let mut range = self.region.range();
        range.skip((head & (self.cap - 1)) as usize);
        let mut reader = range.reader(gm);
        let header: WqeHeader = match reader.read_plain() {
            Ok(header) => header,
            Err(err) => {
                tracelimit::warn_ratelimited!(
                    error = &err as &dyn std::error::Error,
                    "wqe read error"
                );
                protocol.observe(Event::ObservationUnavailable(Rule::WorkDescriptor));
                return Poll::Pending;
            }
        };

        protocol.observe(Event::WorkHeader {
            queue: key,
            position: head,
            header: header.as_bytes(),
        });
        let mut snapshot = self.region.range();
        snapshot.skip((head & (self.cap - 1)) as usize + 8);
        protocol.descriptor(
            key,
            header.as_bytes(),
            snapshot.reader(gm),
            self.available(),
        );
        let total_len = header.total_len();
        if total_len > size_of::<Wqe>() || total_len > self.available() as usize {
            tracelimit::warn_ratelimited!(total_len, available = self.available(), "invalid wqe");
            return Poll::Pending;
        }

        let mut wqe = Wqe {
            header,
            data: FromZeros::new_zeroed(),
        };

        if let Err(err) = reader.read(&mut wqe.data[..wqe.header.data_len()]) {
            tracelimit::warn_ratelimited!(error = &err as &dyn std::error::Error, "wqe read error");
            protocol.observe(Event::ObservationUnavailable(Rule::WorkDescriptor));
            return Poll::Pending;
        }

        self.head = head.wrapping_add(total_len as u32);
        protocol.observe(Event::WorkConsumed {
            queue: key,
            position: head,
            bytes: total_len as u32,
        });
        Poll::Ready((head, wqe))
    }

    fn available(&self) -> u32 {
        self.tail.wrapping_sub(self.head)
    }

    fn doorbell(&mut self, val: u32) -> Option<Waker> {
        let old_len = self.available();
        assert!(old_len <= self.cap);
        let new_len = val.wrapping_sub(self.head);
        if val.is_multiple_of(WQE_ALIGNMENT as u32) && new_len > old_len && new_len <= self.cap {
            self.tail = val;
            self.waker.take()
        } else {
            None
        }
    }
}

pub struct Queues {
    pub gm: GuestMemory,
    pub driver: VmTaskDriver,
    pub(crate) protocol: ProtocolObserver,
    pub(crate) scenario: crate::conformance::DeviceScenario,
    sqs: Vec<Mutex<Option<Wq>>>,
    rqs: Vec<Mutex<Option<Wq>>>,
    cqs: Vec<Mutex<Option<Cq>>>,
    eqs: Vec<Mutex<Option<Eq>>>,
    msis: Vec<Interrupt>,
}

impl Inspect for Queues {
    fn inspect(&self, req: inspect::Request<'_>) {
        fn inspect_list<T: Inspect>(
            resp: &mut inspect::Response<'_>,
            name: &str,
            list: &[Mutex<Option<T>>],
        ) {
            resp.fields_mut(
                name,
                list.iter().enumerate().map(|(i, entry)| {
                    (
                        i + ID_OFFSET,
                        inspect::adhoc(|req| {
                            if let Some(entry) = &*entry.lock() {
                                entry.inspect(req)
                            } else {
                                req.ignore()
                            }
                        }),
                    )
                }),
            );
        }

        let mut resp = req.respond();
        inspect_list(&mut resp, "sq", &self.sqs);
        inspect_list(&mut resp, "rq", &self.rqs);
        inspect_list(&mut resp, "cq", &self.cqs);
        inspect_list(&mut resp, "eq", &self.eqs);
    }
}

#[derive(Debug, Error)]
#[error("queue {0} not found")]
pub struct QueueNotFound(u32);

#[derive(Debug, Error)]
pub enum QueueUpdateError {
    #[error(transparent)]
    NotFound(#[from] QueueNotFound),
    #[error("invalid MSI-X index {0}")]
    InvalidMsix(u32),
}

impl Queues {
    pub fn new(
        gm: GuestMemory,
        driver: VmTaskDriver,
        msix: &MsixEmulator,
        protocol: ProtocolObserver,
        scenario: Option<gdma_resources::ConformanceScenario>,
    ) -> Self {
        let msis = (0..64)
            .map(|index| msix.interrupt(index).unwrap())
            .collect();
        Self {
            gm,
            driver,
            protocol,
            scenario: crate::conformance::DeviceScenario::new(scenario),
            sqs: [(); 64].map(|_| Mutex::new(None)).into(),
            rqs: [(); 64].map(|_| Mutex::new(None)).into(),
            cqs: [(); 128].map(|_| Mutex::new(None)).into(),
            eqs: (0..scenario.map_or(64, |scenario| scenario.max_eqs()))
                .map(|_| Mutex::new(None))
                .collect(),
            msis,
        }
    }

    pub fn max_sqs(&self) -> u32 {
        self.sqs.len() as u32
    }

    pub fn max_rqs(&self) -> u32 {
        self.rqs.len() as u32
    }

    pub fn max_cqs(&self) -> u32 {
        self.cqs.len() as u32
    }

    pub fn max_eqs(&self) -> u32 {
        self.eqs.len() as u32
    }

    pub fn alloc_wq(&self, is_send: bool, region: DmaRegion) -> Result<u32, QueueAllocError> {
        let bytes = region.len() as u64;
        let wqs = if is_send { &self.sqs } else { &self.rqs };
        for (i, wq) in wqs.iter().enumerate() {
            let mut wq = wq.lock();
            if wq.is_none() {
                *wq = Some(Wq::new(region)?);
                let id = (i + ID_OFFSET) as u32;
                self.protocol.observe(Event::QueueBound(QueueDescriptor {
                    key: QueueKey {
                        kind: if is_send {
                            QueueKind::Sq
                        } else {
                            QueueKind::Rq
                        },
                        id,
                    },
                    bytes,
                    parent_eq: None,
                    msix: None,
                }));
                return Ok(id);
            }
        }
        Err(QueueAllocError::NoMoreQueues)
    }

    pub fn free_wq(&self, is_send: bool, id: u32) -> Result<(), QueueNotFound> {
        let wqs = if is_send { &self.sqs } else { &self.rqs };
        let index = (id as usize)
            .checked_sub(ID_OFFSET)
            .ok_or(QueueNotFound(id))?;
        let mut queue = wqs.get(index).ok_or(QueueNotFound(id))?.lock();
        queue.take().ok_or(QueueNotFound(id))?;
        self.protocol.observe(Event::QueueReleased(QueueKey {
            kind: if is_send {
                QueueKind::Sq
            } else {
                QueueKind::Rq
            },
            id,
        }));
        Ok(())
    }

    pub fn alloc_cq(&self, region: DmaRegion, eq_id: u32) -> Result<u32, QueueAllocError> {
        let bytes = region.len() as u64;
        for (i, cq) in self.cqs.iter().enumerate() {
            let mut cq = cq.lock();
            if cq.is_none() {
                *cq = Some(Cq {
                    q: CqEq::new(region)?,
                    eq_id,
                });
                let id = (i + ID_OFFSET) as u32;
                self.protocol.observe(Event::QueueBound(QueueDescriptor {
                    key: QueueKey {
                        kind: QueueKind::Cq,
                        id,
                    },
                    bytes,
                    parent_eq: Some(eq_id),
                    msix: None,
                }));
                return Ok(id);
            }
        }
        Err(QueueAllocError::NoMoreQueues)
    }

    pub fn free_wq_cq(&self, is_send: bool, wq_id: u32, cq_id: u32) -> Result<(), QueueNotFound> {
        let wqs = if is_send { &self.sqs } else { &self.rqs };
        let wq_index = (wq_id as usize)
            .checked_sub(ID_OFFSET)
            .ok_or(QueueNotFound(wq_id))?;
        let cq_index = (cq_id as usize)
            .checked_sub(ID_OFFSET)
            .ok_or(QueueNotFound(cq_id))?;
        let mut wq = wqs.get(wq_index).ok_or(QueueNotFound(wq_id))?.lock();
        let mut cq = self.cqs.get(cq_index).ok_or(QueueNotFound(cq_id))?.lock();
        if wq.is_none() {
            return Err(QueueNotFound(wq_id));
        }
        if cq.is_none() {
            return Err(QueueNotFound(cq_id));
        }
        *wq = None;
        *cq = None;
        self.protocol.observe(Event::QueueReleased(QueueKey {
            kind: if is_send {
                QueueKind::Sq
            } else {
                QueueKind::Rq
            },
            id: wq_id,
        }));
        self.protocol.observe(Event::QueueReleased(QueueKey {
            kind: QueueKind::Cq,
            id: cq_id,
        }));
        Ok(())
    }

    pub fn alloc_eq(&self, region: DmaRegion, msix: u32) -> Result<u32, QueueAllocError> {
        if self.msis.get(msix as usize).is_none() {
            return Err(QueueAllocError::InvalidMsix(msix));
        }
        let bytes = region.len() as u64;
        for (i, eq) in self.eqs.iter().enumerate() {
            let mut eq = eq.lock();
            if eq.is_none() {
                *eq = Some(Eq {
                    q: CqEq::new(region)?,
                    msix,
                });
                let id = (i + ID_OFFSET) as u32;
                self.protocol.observe(Event::QueueBound(QueueDescriptor {
                    key: QueueKey {
                        kind: QueueKind::Eq,
                        id,
                    },
                    bytes,
                    parent_eq: None,
                    msix: Some(msix),
                }));
                return Ok(id);
            }
        }
        Err(QueueAllocError::NoMoreQueues)
    }

    pub fn update_eq_msix(&self, eq_id: u32, msix: u32) -> Result<(), QueueUpdateError> {
        if self.msis.get(msix as usize).is_none() {
            return Err(QueueUpdateError::InvalidMsix(msix));
        }
        self.eq(eq_id)
            .map(|mut eq| {
                eq.msix = msix;
                Some(eq_id)
            })
            .ok_or(QueueNotFound(eq_id))?;
        self.protocol.observe(Event::EqRoute { id: eq_id, msix });
        Ok(())
    }

    pub fn free_eq(&self, eq_id: u32) -> Result<(), QueueNotFound> {
        let index = (eq_id as usize)
            .checked_sub(ID_OFFSET)
            .ok_or(QueueNotFound(eq_id))?;
        let mut queue = self.eqs.get(index).ok_or(QueueNotFound(eq_id))?.lock();
        queue.take().ok_or(QueueNotFound(eq_id))?;
        self.protocol.observe(Event::QueueReleased(QueueKey {
            kind: QueueKind::Eq,
            id: eq_id,
        }));
        Ok(())
    }

    /// Clears all queue allocations, returning the engine to its initial state.
    ///
    /// Used when the device is reset so that a subsequent HW channel
    /// establishment starts from a clean slate, even if the guest never
    /// released the queues it previously allocated.
    pub fn reset(&self) {
        for sq in &self.sqs {
            *sq.lock() = None;
        }
        for rq in &self.rqs {
            *rq.lock() = None;
        }
        for cq in &self.cqs {
            *cq.lock() = None;
        }
        for eq in &self.eqs {
            *eq.lock() = None;
        }
        self.protocol.observe(Event::Reset);
    }

    fn sq(&self, sq_id: u32) -> Option<MappedMutexGuard<'_, Wq>> {
        MutexGuard::try_map(
            self.sqs
                .get((sq_id as usize).wrapping_sub(ID_OFFSET))?
                .lock(),
            Option::as_mut,
        )
        .ok()
    }

    fn rq(&self, rq_id: u32) -> Option<MappedMutexGuard<'_, Wq>> {
        MutexGuard::try_map(
            self.rqs
                .get((rq_id as usize).wrapping_sub(ID_OFFSET))?
                .lock(),
            Option::as_mut,
        )
        .ok()
    }

    fn cq(&self, cq_id: u32) -> Option<MappedMutexGuard<'_, Cq>> {
        MutexGuard::try_map(
            self.cqs
                .get((cq_id as usize).wrapping_sub(ID_OFFSET))?
                .lock(),
            Option::as_mut,
        )
        .ok()
    }

    fn eq(&self, eq_id: u32) -> Option<MappedMutexGuard<'_, Eq>> {
        MutexGuard::try_map(
            self.eqs
                .get((eq_id as usize).wrapping_sub(ID_OFFSET))?
                .lock(),
            Option::as_mut,
        )
        .ok()
    }

    pub fn post_cq(&self, cq_id: u32, data: &[u8], wq_id: u32, is_send: bool) {
        let post_to_eq = self.cq(cq_id).and_then(|mut cq| {
            let mut cqe = Cqe {
                data: FromZeros::new_zeroed(),
                params: CqeParams::new()
                    .with_is_send_wq(is_send)
                    .with_wq_number(wq_id)
                    .with_owner_count(cq.q.owner_count()),
            };
            cqe.data[..data.len()].copy_from_slice(data);
            cq.q.post(
                &self.gm,
                &cqe,
                &self.protocol,
                QueueKey {
                    kind: QueueKind::Cq,
                    id: cq_id,
                },
            )
            .then_some(cq.eq_id)
        });

        if let Some(eq_id) = post_to_eq {
            tracing::trace!(cq_id, eq_id, "eq completion on cq post");
            self.post_eq(eq_id, GDMA_EQE_COMPLETION, &cq_id.to_ne_bytes());
        }
    }

    pub fn post_eq(&self, eq_id: u32, ty: u8, data: &[u8]) {
        let post_msi = self.eq(eq_id).and_then(|mut eq| {
            let mut eqe = Eqe {
                data: FromZeros::new_zeroed(),
                params: EqeParams::new()
                    .with_event_type(ty)
                    .with_owner_count(eq.q.owner_count()),
            };
            eqe.data[..data.len()].copy_from_slice(data);
            eq.q.post(
                &self.gm,
                &eqe,
                &self.protocol,
                QueueKey {
                    kind: QueueKind::Eq,
                    id: eq_id,
                },
            )
            .then_some(eq.msix)
        });

        if let Some(msix) = post_msi {
            tracing::trace!(eq_id, msix, "interrupt on eq post");
            self.msis[msix as usize].deliver();
        }
    }

    pub fn poll_sq(&self, sq_id: u32, cx: &mut Context<'_>) -> Poll<Wqe> {
        self.poll_sq_with_offset(sq_id, cx).map(|(_, wqe)| wqe)
    }

    pub fn poll_sq_with_offset(&self, sq_id: u32, cx: &mut Context<'_>) -> Poll<(u32, Wqe)> {
        if let Some(mut sq) = self.sq(sq_id) {
            sq.poll_wqe(
                &self.gm,
                cx,
                &self.protocol,
                QueueKey {
                    kind: QueueKind::Sq,
                    id: sq_id,
                },
            )
        } else {
            Poll::Pending
        }
    }

    pub fn poll_rq(&self, rq_id: u32, cx: &mut Context<'_>) -> Poll<(u32, Wqe)> {
        if let Some(mut rq) = self.rq(rq_id) {
            rq.poll_wqe(
                &self.gm,
                cx,
                &self.protocol,
                QueueKey {
                    kind: QueueKind::Rq,
                    id: rq_id,
                },
            )
        } else {
            Poll::Pending
        }
    }

    pub fn doorbell_sq(&self, val: WqDoorbellValue) {
        let waker = self.sq(val.id()).and_then(|mut sq| sq.doorbell(val.tail()));
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    pub fn doorbell_rq(&self, val: WqDoorbellValue) {
        let waker = self.rq(val.id()).and_then(|mut rq| rq.doorbell(val.tail()));
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    pub fn doorbell_cq(&self, val: CqEqDoorbellValue) {
        let cq_id = val.id();
        let post_to_eq = self
            .cq(cq_id)
            .and_then(|mut cq| cq.q.doorbell(val.tail(), val.arm()).then_some(cq.eq_id));

        if let Some(eq_id) = post_to_eq {
            tracing::trace!(cq_id, eq_id, "eq completion on cq doorbell");
            self.post_eq(eq_id, GDMA_EQE_COMPLETION, &cq_id.to_ne_bytes());
        }
    }

    pub fn doorbell_eq(&self, val: CqEqDoorbellValue) {
        let eq_id = val.id();
        let post_msi = self
            .eq(eq_id)
            .and_then(|mut eq| eq.q.doorbell(val.tail(), val.arm()).then_some(eq.msix));

        if let Some(msix) = post_msi {
            tracing::trace!(eq_id, msix, "interrupt on eq doorbell");
            self.msis[msix as usize].deliver();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    #[test]
    fn unaligned_work_tail_does_not_publish() {
        let region = DmaRegion::new(vec![0], 0, 4096).unwrap();
        let mut queue = Wq::new(region).unwrap();
        queue.doorbell(1);
        assert_eq!(queue.tail, 0);
        queue.doorbell(33);
        assert_eq!(queue.tail, 0);
        queue.doorbell(32);
        assert_eq!(queue.tail, 32);
    }

    #[test]
    fn failed_completion_store_does_not_advance_or_fire() {
        let gm = GuestMemory::allocate(4096);
        let region = DmaRegion::new(vec![0x10000], 0, 4096).unwrap();
        let mut queue = CqEq::<Eqe>::new(region).unwrap();
        let protocol = ProtocolObserver::new(true, 64);
        let key = QueueKey {
            kind: QueueKind::Eq,
            id: 24,
        };
        protocol.observe(Event::QueueBound(QueueDescriptor {
            key,
            bytes: 4096,
            parent_eq: None,
            msix: Some(0),
        }));
        let before = queue.tail;
        assert!(!queue.post(&gm, &Eqe::new_zeroed(), &protocol, key));
        assert_eq!(queue.tail, before);
        assert!(queue.armed);
        let report = protocol.report().unwrap();
        assert_eq!(
            report.statistics[Rule::CompletionStorage as usize].inconclusive,
            1
        );
        assert!(report.findings.is_empty());
    }
}
