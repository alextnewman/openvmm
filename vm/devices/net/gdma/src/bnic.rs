// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use self::bnic_defs::CQE_RX_TRUNCATED;
use self::bnic_defs::CQE_TX_GDMA_ERR;
use self::bnic_defs::CQE_TX_OKAY;
use self::bnic_defs::MANA_CQE_COMPLETION;
use self::bnic_defs::MANA_LONG_PKT_FMT;
use self::bnic_defs::ManaCommandCode;
use self::bnic_defs::ManaCqeHeader;
use self::bnic_defs::ManaQueryStatisticsRequest;
use self::bnic_defs::ManaQueryStatisticsResponse;
use self::bnic_defs::ManaQueryVportCfgReq;
use self::bnic_defs::ManaRxcompOob;
use self::bnic_defs::ManaRxcompOobFlags;
use self::bnic_defs::ManaSetVportSerialNo;
use self::bnic_defs::ManaTxCompOob;
use self::bnic_defs::ManaTxCompOobOffsets;
use crate::VportConfig;
use crate::bnic::bnic_defs::CQE_RX_OKAY;
use crate::bnic::bnic_defs::ManaCfgRxSteerReq;
use crate::bnic::bnic_defs::ManaConfigVportReq;
use crate::bnic::bnic_defs::ManaConfigVportResp;
use crate::bnic::bnic_defs::ManaCreateWqobjReq;
use crate::bnic::bnic_defs::ManaCreateWqobjResp;
use crate::bnic::bnic_defs::ManaQueryDeviceCfgReq;
use crate::bnic::bnic_defs::ManaQueryDeviceCfgResp;
use crate::bnic::bnic_defs::ManaQueryVportCfgResp;
use crate::bnic::bnic_defs::ManaTxOob;
use crate::hwc::HwState;
use crate::queues::Queues;
use anyhow::Context;
use anyhow::anyhow;
use gdma_defs::GdmaQueueType;
use gdma_defs::GdmaReqHdr;
use gdma_defs::Wqe;
use gdma_defs::access::WqeAccess;
use gdma_defs::bnic as bnic_defs;
use gdma_defs::bnic::ManaDestroyWqobjReq;
use gdma_defs::bnic::ManaTxShortOob;
use gdma_defs::bnic::Tristate;
use guestmem::GuestMemory;
use guestmem::Limit;
use guestmem::MemoryRead;
use guestmem::MemoryWrite;
use inspect::InspectMut;
use net_backend::BufferAccess;
use net_backend::Endpoint;
use net_backend::Queue;
use net_backend::QueueConfig;
use net_backend::RssConfig;
use net_backend::RxBufferSegment;
use net_backend::RxChecksumState;
use net_backend::RxId;
use net_backend::RxMetadata;
use net_backend::TxId;
use net_backend::TxMetadata;
use net_backend::TxSegment;
use net_backend::TxSegmentType;
use net_backend_resources::mac_address::MacAddress;
use slab::Slab;
use std::future::poll_fn;
use std::sync::Arc;
use std::task::Poll;
use task_control::AsyncRun;
use task_control::InspectTaskMut;
use task_control::StopTask;
use task_control::TaskControl;
use zerocopy::FromBytes;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

/// Default adapter MTU reported in the `MANA_QUERY_DEV_CONFIG` response.
///
/// MANA drivers that negotiate `GDMA_MESSAGE_V2` or later require
/// `adapter_mtu >= ETH_MIN_MTU + ETH_HLEN` and reject a zero value with
/// `-EPROTO` ("Adapter MTU too small"). Report the standard Ethernet frame
/// length (1514), which matches the driver's own V1-era default and yields a
/// 1500-byte L3 MTU once the 14-byte Ethernet header is subtracted.
const MANA_DEFAULT_ADAPTER_MTU: u16 = 1514;

/// Number of entries in the RSS indirection table advertised to the guest.
/// The guest hashes each received flow into this many buckets, then maps each
/// bucket to a receive queue.
const MANA_INDIRECTION_TABLE_SIZE: u32 = 128;

/// Upper bound on the number of send/receive queues advertised per vport. The
/// effective count is additionally clamped to what the backend endpoint
/// supports.
const MANA_MAX_QUEUES_PER_VPORT: u16 = 16;

pub struct GuestBuffers {
    gm: GuestMemory,
    rx_packets: Slab<RxPacket>,
}

struct RxPacket {
    segments: Vec<RxBufferSegment>,
    len: u32,
    wqe_offset: u32,
    oob: ManaRxcompOob,
}

impl BufferAccess for GuestBuffers {
    fn guest_memory(&self) -> &GuestMemory {
        &self.gm
    }

    fn write_data(&mut self, id: RxId, mut data: &[u8]) {
        let mut addrs = self.rx_packets[id.0 as usize].segments.iter();
        while !data.is_empty() {
            let Some(addr) = addrs.next() else {
                // Packet exceeds buffer capacity; will be reported as
                // CQE_RX_TRUNCATED by write_header.
                break;
            };
            let len = data.len().min(addr.len as usize);
            let (this, next) = data.split_at(len);
            if let Err(err) = self.gm.write_at(addr.gpa, this) {
                tracing::warn!(
                    gpa = addr.gpa,
                    len,
                    error = &err as &dyn std::error::Error,
                    "rx memory write failure"
                );
            }
            data = next;
        }
    }

    fn push_guest_addresses(&self, id: RxId, buf: &mut Vec<RxBufferSegment>) {
        buf.extend_from_slice(&self.rx_packets[id.0 as usize].segments);
    }

    fn capacity(&self, id: RxId) -> u32 {
        self.rx_packets[id.0 as usize].len
    }

    fn write_header(&mut self, id: RxId, metadata: &RxMetadata) {
        assert_eq!(metadata.offset, 0);

        let mut flags = ManaRxcompOobFlags::new();
        match metadata.ip_checksum {
            RxChecksumState::Unknown => {}
            RxChecksumState::Good => flags.set_rx_iphdr_csum_succeed(true),
            RxChecksumState::Bad => flags.set_rx_iphdr_csum_fail(true),
            RxChecksumState::ValidatedButWrong => {}
        }
        match metadata.l4_protocol {
            net_backend::L4Protocol::Unknown => {}
            net_backend::L4Protocol::Tcp => match metadata.l4_checksum {
                RxChecksumState::Unknown => {}
                RxChecksumState::Good => flags.set_rx_tcp_csum_succeed(true),
                RxChecksumState::Bad => flags.set_rx_tcp_csum_fail(true),
                RxChecksumState::ValidatedButWrong => {}
            },
            net_backend::L4Protocol::Udp => match metadata.l4_checksum {
                RxChecksumState::Unknown => {}
                RxChecksumState::Good => flags.set_rx_udp_csum_succeed(true),
                RxChecksumState::Bad => flags.set_rx_udp_csum_fail(true),
                RxChecksumState::ValidatedButWrong => {}
            },
        }

        if let Some(vlan) = &metadata.vlan {
            flags.set_rx_vlantag_present(true);
            flags.set_rx_vlan_id(vlan.vlan_id() as u32);
        }

        let packet = &mut self.rx_packets[id.0 as usize];

        let cqe_type = if metadata.len > packet.len as usize {
            CQE_RX_TRUNCATED
        } else {
            CQE_RX_OKAY
        };

        packet.oob = ManaRxcompOob {
            cqe_hdr: ManaCqeHeader::new()
                .with_cqe_type(cqe_type)
                .with_client_type(MANA_CQE_COMPLETION),
            rx_wqe_offset: packet.wqe_offset,
            flags,
            ..FromZeros::new_zeroed()
        };
        packet.oob.ppi[0].pkt_len = metadata.len as u16;
    }
}

/// Configuration for the emulated BNIC device.
#[derive(Default)]
pub struct BnicConfig {
    /// Adapter link speed in megabits per second.
    pub adapter_link_speed_mbps: u32,
}

pub struct BasicNic {
    vports: Vec<Vport>,
    config: BnicConfig,
    /// Monotonic allocator for `wq_obj` handles returned by
    /// `MANA_CREATE_WQ_OBJ`. Each work-queue object gets a distinct, opaque
    /// handle so the guest can reference individual RX queues (e.g. in the RSS
    /// indirection table) and destroy them independently.
    next_wq_obj: u64,
}

impl InspectMut for BasicNic {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        req.respond()
            .fields_mut("vports", self.vports.iter_mut().enumerate());
    }
}

struct Vport {
    mac_address: MacAddress,
    endpoint: Box<dyn Endpoint>,
    /// One datapath task per active queue pair. Empty when the receive path is
    /// disabled.
    tasks: Vec<TaskControl<TxRxState, TxRxTask>>,
    queue_cfg: QueueCfg,
    serial_no: u32,
}

impl InspectMut for Vport {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        req.respond()
            .field("mac_address", self.mac_address)
            .field_mut("endpoint", self.endpoint.as_mut())
            .field("tx_wqs", self.queue_cfg.tx.len())
            .field("rx_wqs", self.queue_cfg.rx.len())
            .fields_mut("queues", self.tasks.iter_mut().enumerate());
    }
}

impl Vport {
    /// Stops and tears down every datapath task, then stops the backend
    /// endpoint. The backend's queues are owned by the tasks, so the tasks must
    /// be dropped before the endpoint is stopped.
    async fn stop_datapath(&mut self) {
        if self.tasks.is_empty() {
            return;
        }
        for mut task in self.tasks.drain(..) {
            if task.is_running() {
                task.stop().await;
            }
            // Dropping the task releases its backend queue.
        }
        self.endpoint.stop().await;
    }
}

/// A work-queue object created via `MANA_CREATE_WQ_OBJ`: an associated
/// work queue and completion queue, addressed by the opaque `wq_obj` handle
/// returned to the guest.
struct WqObject {
    wq_obj: u64,
    wq_id: u32,
    cq_id: u32,
}

#[derive(Default)]
struct QueueCfg {
    tx: Vec<WqObject>,
    rx: Vec<WqObject>,
}

impl BasicNic {
    pub fn new(vports: Vec<VportConfig>, config: BnicConfig) -> Self {
        assert!(!vports.is_empty());

        let vports = vports
            .into_iter()
            .map(
                |VportConfig {
                     mac_address,
                     endpoint,
                 }| {
                    assert!(endpoint.is_ordered());
                    Vport {
                        mac_address,
                        endpoint,
                        tasks: Vec::new(),
                        queue_cfg: QueueCfg::default(),
                        serial_no: 0,
                    }
                },
            )
            .collect();

        Self {
            vports,
            config,
            next_wq_obj: 1,
        }
    }

    /// Tears down every vport's datapath, returning the NIC to its initial
    /// state. This mirrors the teardown performed when a vport's receive path
    /// is disabled, but applies to all vports unconditionally so the device can
    /// be reset even when the guest never disabled them.
    pub async fn shutdown(&mut self) {
        for vport in &mut self.vports {
            vport.stop_datapath().await;
            vport.queue_cfg = QueueCfg::default();
            vport.serial_no = 0;
        }
    }

    pub async fn handle_req(
        &mut self,
        state: &mut HwState,
        hdr: &GdmaReqHdr,
        mut read: Limit<WqeAccess<'_>>,
        mut write: Limit<WqeAccess<'_>>,
    ) -> anyhow::Result<usize> {
        tracing::debug!(msg_type = ?ManaCommandCode(hdr.req.msg_type), "bnic request");

        // Zero the guest response buffer before writing the actual response
        // to maintain forward compatibility: a newer VF driver may request
        // fields added in a later protocol version that this emulator does
        // not yet populate. Zeroing ensures those fields read as zero rather
        // than containing undefined data.
        let guest_resp_size = MemoryWrite::len(&write);
        let mut zero_write = write.clone();
        zero_write.write(&vec![0u8; guest_resp_size])?;

        match ManaCommandCode(hdr.req.msg_type) {
            ManaCommandCode::MANA_QUERY_DEV_CONFIG => {
                let _req: ManaQueryDeviceCfgReq = read
                    .read_plain()
                    .context("reading query dev config request")?;

                let resp = ManaQueryDeviceCfgResp {
                    pf_cap_flags1: 0.into(),
                    pf_cap_flags2: 0,
                    pf_cap_flags3: 0,
                    pf_cap_flags4: 0,
                    max_num_vports: self.vports.len() as u16,
                    reserved: 0,
                    max_num_eqs: 64,
                    adapter_mtu: MANA_DEFAULT_ADAPTER_MTU,
                    reserved2: 0,
                    adapter_link_speed_mbps: self.config.adapter_link_speed_mbps,
                };

                let resp_bytes = resp.as_bytes();
                let write_len = guest_resp_size.min(resp_bytes.len());
                write.write(&resp_bytes[..write_len])?;
            }
            ManaCommandCode::MANA_CONFIG_VPORT_TX => {
                let req: ManaConfigVportReq = read
                    .read_plain()
                    .context("reading config vport tx request")?;
                let _vport = self
                    .vports
                    .get_mut(req.vport as usize)
                    .context("invalid vport")?;

                let resp = ManaConfigVportResp {
                    tx_vport_offset: 0,
                    short_form_allowed: 1,
                    reserved: 0,
                };
                write.write(resp.as_bytes())?;
            }
            ManaCommandCode::MANA_CREATE_WQ_OBJ => {
                let req: ManaCreateWqobjReq =
                    read.read_plain().context("reading create wq obj request")?;

                let is_send = match req.wq_type {
                    GdmaQueueType::GDMA_RQ => false,
                    GdmaQueueType::GDMA_SQ => true,
                    ty => anyhow::bail!("unsupported queue type: {:?}", ty),
                };

                let vport_idx = req.vport as usize;
                if vport_idx >= self.vports.len() {
                    anyhow::bail!("invalid vport");
                }

                let wq_region = state.get_dma_region(req.wq_gdma_region, req.wq_size)?;
                let cq_region = state.get_dma_region(req.cq_gdma_region, req.cq_size)?;

                let wq_id = state
                    .queues
                    .alloc_wq(is_send, wq_region.clone())
                    .context("failed to allocate wq")?;

                let cq_id = state
                    .queues
                    .alloc_cq(cq_region.clone(), req.cq_parent_qid)
                    .context("failed to allocate cq")?;

                // Allocate a distinct, opaque handle for this work-queue object.
                // The guest uses it to address individual queues (notably in the
                // RSS indirection table) and to destroy them, so it must be
                // unique across all of a vport's queues rather than aliasing the
                // vport index.
                let wq_obj = self.next_wq_obj;
                self.next_wq_obj += 1;

                let resp = ManaCreateWqobjResp {
                    wq_id,
                    cq_id,
                    wq_obj,
                };

                let vport = &mut self.vports[vport_idx];
                let list = if is_send {
                    &mut vport.queue_cfg.tx
                } else {
                    &mut vport.queue_cfg.rx
                };
                list.push(WqObject {
                    wq_obj,
                    wq_id,
                    cq_id,
                });

                write.write(resp.as_bytes())?;

                // Take ownership of the DMA regions.
                state.remove_dma_region(req.wq_gdma_region).unwrap();
                state.remove_dma_region(req.cq_gdma_region).unwrap();
            }
            ManaCommandCode::MANA_DESTROY_WQ_OBJ => {
                let req: ManaDestroyWqobjReq = read
                    .read_plain()
                    .context("failed to read destroy wq obj request")?;
                let is_send = match req.wq_type {
                    GdmaQueueType::GDMA_RQ => false,
                    GdmaQueueType::GDMA_SQ => true,
                    ty => anyhow::bail!("unsupported queue type: {:?}", ty),
                };

                // Look the object up by its handle across every vport, since the
                // handle is no longer the vport index.
                let mut removed = None;
                for vport in &mut self.vports {
                    let list = if is_send {
                        &mut vport.queue_cfg.tx
                    } else {
                        &mut vport.queue_cfg.rx
                    };
                    if let Some(pos) = list.iter().position(|w| w.wq_obj == req.wq_obj_handle) {
                        if vport.tasks.iter().any(|t| t.has_state()) {
                            anyhow::bail!("queue still in use");
                        }
                        removed = Some(list.remove(pos));
                        break;
                    }
                }
                let wq = removed.context("specified queue does not exist")?;
                state.queues.free_wq(is_send, wq.wq_id).unwrap();
                state.queues.free_cq(wq.cq_id).unwrap();
            }
            ManaCommandCode::MANA_CONFIG_VPORT_RX => {
                let req: ManaCfgRxSteerReq = read
                    .read_plain()
                    .context("reading config vport rx request")?;
                tracing::debug!(?req, "rx config");
                let vport = self
                    .vports
                    .get_mut(req.vport as usize)
                    .context("invalid vport")?;

                match req.rx_enable {
                    Tristate::FALSE => {
                        vport.stop_datapath().await;
                    }
                    Tristate::TRUE if vport.tasks.is_empty() => {
                        let n = vport.queue_cfg.tx.len().min(vport.queue_cfg.rx.len());
                        if n == 0 {
                            anyhow::bail!("queues not configured");
                        }

                        // When RSS is enabled the indirection table follows the
                        // request header in the payload as `num_indir_entries`
                        // 64-bit work-queue object handles. Translate each handle
                        // into the index of the receive queue it names. Steering
                        // itself is performed by the backend (modeling the PF /
                        // physical wire), so the device only has to plumb the
                        // resolved table and hash key down to it.
                        let rss = if matches!(req.rss_enable, Tristate::TRUE)
                            && req.num_indir_entries > 0
                        {
                            let mut table = Vec::with_capacity(req.num_indir_entries as usize);
                            for _ in 0..req.num_indir_entries {
                                let handle: u64 = read
                                    .read_plain()
                                    .context("reading rss indirection entry")?;
                                let idx = vport
                                    .queue_cfg
                                    .rx
                                    .iter()
                                    .position(|w| w.wq_obj == handle)
                                    .context("indirection table references unknown rx queue")?;
                                table.push(idx as u16);
                            }
                            Some((req.hashkey, table))
                        } else {
                            None
                        };

                        let configs = (0..n)
                            .map(|_| QueueConfig {
                                driver: Box::new(state.queues.driver.clone()),
                            })
                            .collect();

                        let rss_cfg = rss.as_ref().map(|(key, table)| RssConfig {
                            key: key.as_slice(),
                            indirection_table: table.as_slice(),
                            flags: 0,
                        });

                        let mut queues = vec![];
                        vport
                            .endpoint
                            .get_queues(configs, rss_cfg.as_ref(), &mut queues)
                            .await?;
                        anyhow::ensure!(
                            queues.len() == n,
                            "backend returned {} queues, expected {n}",
                            queues.len()
                        );

                        for (k, epqueue) in queues.into_iter().enumerate() {
                            let (sq_id, sq_cq_id) =
                                (vport.queue_cfg.tx[k].wq_id, vport.queue_cfg.tx[k].cq_id);
                            let (rq_id, rq_cq_id) =
                                (vport.queue_cfg.rx[k].wq_id, vport.queue_cfg.rx[k].cq_id);

                            let mut task = TaskControl::new(TxRxState);
                            task.insert(
                                &state.queues.driver,
                                "gdma-bnic",
                                TxRxTask {
                                    queues: state.queues.clone(),
                                    epqueue,
                                    pool: GuestBuffers {
                                        gm: state.queues.gm.clone(),
                                        rx_packets: Default::default(),
                                    },
                                    sq_id,
                                    sq_cq_id,
                                    rq_id,
                                    rq_cq_id,
                                    tx_segment_buffer: Vec::new(),
                                    rx_buf_count: 0,
                                },
                            );
                            task.start();
                            vport.tasks.push(task);
                        }
                    }
                    _ => {}
                }
            }
            ManaCommandCode::MANA_VTL2_MOVE_FILTER => {
                anyhow::bail!("unsupported command MANA_VTL2_MOVE_FILTER");
            }
            ManaCommandCode::MANA_VTL2_QUERY_FILTER_STATE => {
                let req: gdma_defs::bnic::ManaQueryFilterStateReq = read
                    .read_plain()
                    .context("reading query vport filter state request")?;
                let _ = self
                    .vports
                    .get_mut(req.vport as usize)
                    .context("invalid vport")?;

                let resp = gdma_defs::bnic::ManaQueryFilterStateResponse {
                    direction_to_vtl0: 0,
                    reserved: [0; 7],
                };

                write.write(resp.as_bytes())?;
            }
            ManaCommandCode::MANA_QUERY_VPORT_CONFIG => {
                let req: ManaQueryVportCfgReq = read
                    .read_plain()
                    .context("reading query vport config request")?;
                let vport = self
                    .vports
                    .get_mut(req.vport_index as usize)
                    .context("invalid vport")?;

                // Advertise as many queues as the backend can service, capped to
                // a sane maximum. The guest uses this to decide how many receive
                // queues to create and steer across.
                let max_queues = (vport.endpoint.multiqueue_support().max_queues)
                    .clamp(1, MANA_MAX_QUEUES_PER_VPORT) as u32;

                let resp = ManaQueryVportCfgResp {
                    max_num_sq: max_queues,
                    max_num_rq: max_queues,
                    num_indirection_ent: MANA_INDIRECTION_TABLE_SIZE,
                    reserved1: 0,
                    mac_addr: vport.mac_address.to_bytes(),
                    reserved2: [0; 2],
                    vport: req.vport_index.into(),
                };

                write.write(resp.as_bytes())?;
            }
            ManaCommandCode::MANA_QUERY_STATS => {
                let req: ManaQueryStatisticsRequest = read
                    .read_plain()
                    .context("reading query stats request")?;

                // The emulated datapath keeps no traffic counters yet, so report
                // the requested statistics as available with zeroed values. The
                // driver only requires a successful response whose
                // `reported_statistics` mask covers what it asked for.
                let resp = ManaQueryStatisticsResponse {
                    reported_statistics: req.requested_statistics,
                    ..FromZeros::new_zeroed()
                };

                let resp_bytes = resp.as_bytes();
                let write_len = guest_resp_size.min(resp_bytes.len());
                write.write(&resp_bytes[..write_len])?;
            }
            ManaCommandCode::MANA_VTL2_ASSIGN_SERIAL_NUMBER => {
                let req: ManaSetVportSerialNo =
                    read.read_plain().context("set vport serial number")?;
                let vport = self
                    .vports
                    .get_mut(req.vport as usize)
                    .context("invalid vport")?;
                vport.serial_no = req.serial_no;
            }
            n => anyhow::bail!("unsupported request {:?}", n),
        }
        Ok(guest_resp_size)
    }
}

pub struct TxRxTask {
    queues: Arc<Queues>,
    epqueue: Box<dyn Queue>,
    pool: GuestBuffers,
    sq_id: u32,
    sq_cq_id: u32,
    rq_id: u32,
    rq_cq_id: u32,
    tx_segment_buffer: Vec<TxSegment>,
    rx_buf_count: u32,
}

impl InspectTaskMut<TxRxTask> for TxRxState {
    fn inspect_mut(&mut self, req: inspect::Request<'_>, task: Option<&mut TxRxTask>) {
        let mut resp = req.respond();
        if let Some(task) = task {
            resp.field_mut("queue", &mut task.epqueue)
                .field("rx_bufs", task.pool.rx_packets.len());
        }
    }
}

impl TxRxTask {
    async fn process(&mut self) -> anyhow::Result<()> {
        let max_rx_buf = 256;

        enum Event {
            Sqe(Wqe),
            Rqe(u32, Wqe),
            Ready,
        }

        loop {
            let event = poll_fn(|cx| {
                // Fill rx before transmitting to avoid rx buffer starvation
                // (particularly in tests, but seems reasonable in general).
                if self.rx_buf_count < max_rx_buf {
                    if let Poll::Ready((wqe_offset, wqe)) = self.queues.poll_rq(self.rq_id, cx) {
                        self.rx_buf_count += 1;
                        return Poll::Ready(Event::Rqe(wqe_offset, wqe));
                    }
                }
                if let Poll::Ready(wqe) = self.queues.poll_sq(self.sq_id, cx) {
                    return Poll::Ready(Event::Sqe(wqe));
                }
                if self.epqueue.poll_ready(cx, &mut self.pool).is_ready() {
                    return Poll::Ready(Event::Ready);
                }
                Poll::Pending
            })
            .await;
            match event {
                Event::Sqe(sqe) => self.process_sqe(sqe)?,
                Event::Rqe(wqe_offset, wqe) => self.process_rqe(wqe, wqe_offset)?,
                Event::Ready => self.process_backend()?,
            }
        }
    }

    fn process_sqe(&mut self, sqe: Wqe) -> anyhow::Result<()> {
        tracing::trace!("tx wqe");
        let oob = sqe.oob();
        let oob = if oob.len() >= size_of::<ManaTxOob>() {
            ManaTxOob::read_from_prefix(oob).unwrap().0
        } else {
            ManaTxOob {
                // TODO: zerocopy: use details from SizeError in the returned context (https://github.com/microsoft/openvmm/issues/759)
                s_oob: ManaTxShortOob::read_from_prefix(oob)
                    .map_err(|_| anyhow!("oob too small"))?
                    .0,
                ..FromZeros::new_zeroed()
            }
        };

        let sge0 = sqe.sgl().first().context("no sgl")?;
        let total_len: usize = sqe.sgl().iter().map(|sge| sge.size as usize).sum();
        let (l2_len, vlan) =
            if oob.s_oob.pkt_fmt() == MANA_LONG_PKT_FMT && oob.l_oob.inject_vlan_pri_tag() {
                (
                    net_backend::ETHERNET_VLAN_HEADER_LEN,
                    Some(
                        net_backend::VlanMetadata::new()
                            .with_priority(oob.l_oob.pcp())
                            .with_drop_eligible_indicator(oob.l_oob.dei())
                            .with_vlan_id(oob.l_oob.vlan_id()),
                    ),
                )
            } else {
                (net_backend::ETHERNET_HEADER_LEN, None)
            };

        let mut meta = TxMetadata {
            id: TxId(0),
            segment_count: sqe.sgl().len().try_into().unwrap(),
            len: total_len.try_into().unwrap(),
            flags: net_backend::TxFlags::new()
                .with_offload_ip_header_checksum(oob.s_oob.comp_iphdr_csum())
                .with_offload_tcp_checksum(oob.s_oob.comp_tcp_csum())
                .with_offload_udp_checksum(oob.s_oob.comp_udp_csum())
                .with_is_ipv4(oob.s_oob.is_outer_ipv4())
                .with_is_ipv6(oob.s_oob.is_outer_ipv6() && !oob.s_oob.is_outer_ipv4()),
            l2_len: l2_len as u8,
            l3_len: oob.s_oob.trans_off().clamp(l2_len as u16, 255) - l2_len as u16,
            l4_len: 0,
            transport_header_offset: oob.s_oob.trans_off(),
            max_segment_size: 0,
            vlan,
        };

        if sqe.header.params.client_oob_in_sgl() {
            meta.l4_len =
                sge0.size
                    .saturating_sub(meta.l2_len as u32 + meta.l3_len as u32) as u8;
            meta.max_segment_size = sqe.header.params.gd_client_unit_data();
            meta.flags.set_offload_tcp_segmentation(true);
        }

        // With LSO, the first SGE is the header and the rest are the payload.
        // For LSO, the requirements by the GDMA hardware are:
        // - The first SGE must be the header and must be <= 256 bytes.
        // - There should be at least two SGEs.
        // Possible test improvement: Disable the Queue to mimick the hardware behavior.
        if meta.flags.offload_tcp_segmentation() {
            if sqe.sgl().len() < 2 {
                tracelimit::error_ratelimited!(
                    sgl_count = sqe.sgl().len(),
                    "LSO enabled, but only one SGE"
                );
                self.post_tx_completion_error();
                return Ok(());
            }
            if sge0.size > 256 {
                tracelimit::error_ratelimited!(
                    sge0_size = sge0.size,
                    "LSO enabled and SGE[0] size > 256 bytes"
                );
                self.post_tx_completion_error();
                return Ok(());
            }
        }

        let tx_segments = &mut self.tx_segment_buffer;
        tx_segments.clear();
        tx_segments.push(TxSegment {
            ty: TxSegmentType::Head(meta),
            gpa: sge0.address,
            len: sge0.size,
        });
        for sge in &sqe.sgl()[1..] {
            tx_segments.push(TxSegment {
                ty: TxSegmentType::Tail,
                gpa: sge.address,
                len: sge.size,
            });
        }
        let (sync, count) = self.epqueue.tx_avail(&mut self.pool, tx_segments)?;
        if sync || count == 0 {
            tracing::trace!("tx sync complete");
            self.post_tx_completion();
        }
        Ok(())
    }

    // Possible test improvement: provide proper OOB data for the GDMA error.
    fn post_tx_completion_error(&mut self) {
        let tx_oob = ManaTxCompOob {
            cqe_hdr: ManaCqeHeader::new()
                .with_client_type(MANA_CQE_COMPLETION)
                .with_cqe_type(CQE_TX_GDMA_ERR),
            tx_data_offset: 0,
            offsets: ManaTxCompOobOffsets::new(),
            reserved: [0; 12],
        };
        self.queues
            .post_cq(self.sq_cq_id, tx_oob.as_bytes(), self.sq_id, true);
    }

    fn post_tx_completion(&mut self) {
        let tx_oob = ManaTxCompOob {
            cqe_hdr: ManaCqeHeader::new()
                .with_client_type(MANA_CQE_COMPLETION)
                .with_cqe_type(CQE_TX_OKAY),
            tx_data_offset: 0,
            offsets: ManaTxCompOobOffsets::new(),
            reserved: [0; 12],
        };
        self.queues
            .post_cq(self.sq_cq_id, tx_oob.as_bytes(), self.sq_id, true);
    }

    fn process_rqe(&mut self, wqe: Wqe, wqe_offset: u32) -> anyhow::Result<()> {
        let segments = wqe
            .sgl()
            .iter()
            .map(|sge| RxBufferSegment {
                gpa: sge.address,
                len: sge.size,
            })
            .collect();

        let len = wqe.sgl().iter().map(|sge| sge.size).sum();
        tracing::trace!(?segments, len, "rx wqe");
        let packet = RxPacket {
            segments,
            len,
            wqe_offset,
            oob: FromZeros::new_zeroed(),
        };
        let id = RxId(self.pool.rx_packets.insert(packet) as u32);
        self.epqueue.rx_avail(&mut self.pool, &[id]);
        Ok(())
    }

    fn process_backend(&mut self) -> anyhow::Result<()> {
        let mut packets = [RxId(0)];
        if self.epqueue.rx_poll(&mut self.pool, &mut packets)? > 0 {
            tracing::trace!("rx complete");
            let packet = self
                .pool
                .rx_packets
                .try_remove(packets[0].0 as usize)
                .context("invalid rx id")?;

            self.queues
                .post_cq(self.rq_cq_id, packet.oob.as_bytes(), self.rq_id, false);

            self.rx_buf_count -= 1;
        }

        let mut packets = [TxId(0)];
        if self.epqueue.tx_poll(&mut self.pool, &mut packets)? > 0 {
            tracing::trace!("tx async complete");
            self.post_tx_completion();
        }

        Ok(())
    }
}

struct TxRxState;

impl AsyncRun<TxRxTask> for TxRxState {
    async fn run(
        &mut self,
        stop: &mut StopTask<'_>,
        task: &mut TxRxTask,
    ) -> Result<(), task_control::Cancelled> {
        stop.until_stopped(async {
            if let Err(err) = task.process().await {
                tracing::error!(err = err.as_ref() as &dyn std::error::Error, "bnic failure");
            }
        })
        .await
    }
}
