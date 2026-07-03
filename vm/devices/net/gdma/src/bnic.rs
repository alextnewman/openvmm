// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use self::bnic_defs::CQE_RX_OBJECT_FENCE;
use self::bnic_defs::CQE_RX_TRUNCATED;
use self::bnic_defs::CQE_TX_GDMA_ERR;
use self::bnic_defs::CQE_TX_OKAY;
use self::bnic_defs::MANA_CQE_COMPLETION;
use self::bnic_defs::MANA_LONG_PKT_FMT;
use self::bnic_defs::ManaCommandCode;
use self::bnic_defs::ManaCqeHeader;
use self::bnic_defs::ManaQueryLinkConfigReq;
use self::bnic_defs::ManaQueryLinkConfigResp;
use self::bnic_defs::ManaQueryPhyStatisticsRequest;
use self::bnic_defs::ManaQueryPhyStatisticsResponse;
use self::bnic_defs::ManaQueryStatisticsRequest;
use self::bnic_defs::ManaQueryStatisticsResponse;
use self::bnic_defs::ManaQueryVportCfgReq;
use self::bnic_defs::ManaRxcompOob;
use self::bnic_defs::ManaRxcompOobFlags;
use self::bnic_defs::ManaSetVportSerialNo;
use self::bnic_defs::ManaTxCompOob;
use self::bnic_defs::ManaTxCompOobOffsets;
use crate::VportConfig;
use crate::bnic::bnic_defs::BasicNicDriverFlags;
use crate::bnic::bnic_defs::CQE_RX_COALESCED_4;
use crate::bnic::bnic_defs::CQE_RX_OKAY;
use crate::bnic::bnic_defs::ManaCfgRxSteerReq;
use crate::bnic::bnic_defs::ManaConfigVportReq;
use crate::bnic::bnic_defs::ManaConfigVportResp;
use crate::bnic::bnic_defs::ManaCreateWqobjReq;
use crate::bnic::bnic_defs::ManaCreateWqobjResp;
use crate::bnic::bnic_defs::ManaPfCreateFilterReq;
use crate::bnic::bnic_defs::ManaPfCreateFilterResp;
use crate::bnic::bnic_defs::ManaPfCreateVportReq;
use crate::bnic::bnic_defs::ManaPfCreateVportResp;
use crate::bnic::bnic_defs::ManaQueryDeviceCfgReq;
use crate::bnic::bnic_defs::ManaQueryDeviceCfgResp;
use crate::bnic::bnic_defs::ManaQueryVportCfgResp;
use crate::bnic::bnic_defs::ManaTxOob;
use crate::hwc::HwState;
use crate::queues::Queues;
use anyhow::Context;
use anyhow::anyhow;
use futures::FutureExt;
use gdma_defs::GDMA_MESSAGE_V2;
use gdma_defs::GDMA_STATUS_CMD_UNSUPPORTED;
use gdma_defs::GdmaQueueType;
use gdma_defs::GdmaReqHdr;
use gdma_defs::Wqe;
use gdma_defs::access::WqeAccess;
use gdma_defs::bnic as bnic_defs;
use gdma_defs::bnic::MANA_DEFAULT_LINK_SPEED_MBPS;
use gdma_defs::bnic::MANA_RXCOMP_OOB_NUM_PPI;
use gdma_defs::bnic::ManaCfgRxSteerResp;
use gdma_defs::bnic::ManaDestroyWqobjReq;
use gdma_defs::bnic::ManaFenceRqReq;
use gdma_defs::bnic::ManaTxShortOob;
use gdma_defs::bnic::Tristate;
use gdma_defs::bnic::bnic_status;
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
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::task::Poll;
use task_control::AsyncRun;
use task_control::InspectTaskMut;
use task_control::StopTask;
use task_control::TaskControl;
use zerocopy::FromBytes;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

/// A command-handler error tagged with the specific BNIC command status code the
/// device reports for this failure. The HW channel dispatch downcasts to this to
/// surface the code in the response header ([`GdmaRespHdr::status`]) instead of
/// the generic failure code, keeping rejections faithful to real hardware (which
/// returns a distinct code per negative path) and legible in command traces.
///
/// The wrapped [`anyhow::Error`] carries the human-readable cause; it is kept as
/// the source so the chain still appears in logs.
///
/// [`GdmaRespHdr::status`]: gdma_defs::GdmaRespHdr
#[derive(Debug)]
pub(crate) struct BnicStatusError {
    pub(crate) status: u32,
    source: anyhow::Error,
}

impl BnicStatusError {
    /// Wraps `source` with the BNIC command `status` the device reports for this
    /// rejection. Convert with `.into()` to flow through the existing
    /// `anyhow::Result` handler signatures.
    fn new(status: u32, source: anyhow::Error) -> Self {
        Self { status, source }
    }
}

impl std::fmt::Display for BnicStatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.source, f)
    }
}

impl std::error::Error for BnicStatusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.source()
    }
}

/// Attaches a BNIC command status code to the error path of a result, so a
/// rejected command reports the code the device uses rather than the generic
/// failure default.
trait BnicStatusResultExt<T> {
    fn bnic_status(self, status: u32) -> anyhow::Result<T>;
}

impl<T> BnicStatusResultExt<T> for anyhow::Result<T> {
    fn bnic_status(self, status: u32) -> anyhow::Result<T> {
        self.map_err(|source| BnicStatusError::new(status, source).into())
    }
}

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

/// RX CQE coalescing window, in nanoseconds, reported to the driver in the
/// `GDMA_MESSAGE_V2` `MANA_CONFIG_VPORT_RX` response. The hardware programs a
/// 512-cycle timeout at 250 MHz (512 / 250e6 = 2048 ns); the Linux driver uses
/// the same value (`MANA_RX_CQE_NSEC_DEF`) as its fallback default. The emulated
/// datapath does not arm a real timer -- it coalesces whatever receive
/// completions are ready in a single poll -- but reports the canonical window so
/// the value the driver surfaces (e.g. via `ethtool -c`) matches real hardware.
const MANA_RX_CQE_COALESCING_TIMEOUT_NS: u32 = 2048;

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
    /// Present the device as a bare-metal physical function: report
    /// `bm_hostmode=1` in the device-config response so the guest exercises the
    /// driver's bare-metal-host paths. Paired with the PF PCI device id and PF
    /// register window set up by [`crate::GdmaDevice::new_with_config`].
    pub bm_hostmode: bool,
    /// Expose a read-only PF capability register block in BAR0 advertising the
    /// device's resource limits. Composes with [`Self::bm_hostmode`].
    pub pf_caps: bool,
}

impl BnicConfig {
    /// The adapter's effective link speed in Mbps: the configured value, or the
    /// device's nominal line rate ([`MANA_DEFAULT_LINK_SPEED_MBPS`]) when it is
    /// left unconfigured (0). A modern PF that implements `MANA_QUERY_LINK_CONFIG`
    /// always knows its link speed, so the handler reports this rather than a
    /// zero the guest would render as an unknown speed.
    fn link_speed_mbps(&self) -> u32 {
        if self.adapter_link_speed_mbps > 0 {
            self.adapter_link_speed_mbps
        } else {
            MANA_DEFAULT_LINK_SPEED_MBPS
        }
    }
}

pub struct BasicNic {
    vports: Vec<Vport>,
    config: BnicConfig,
    /// Monotonic allocator for `wq_obj` handles returned by
    /// `MANA_CREATE_WQ_OBJ`. Each work-queue object gets a distinct, opaque
    /// handle so the guest can reference individual RX queues (e.g. in the RSS
    /// indirection table) and destroy them independently.
    next_wq_obj: u64,
    /// Monotonic allocator for filter handles returned by
    /// `MANA_PF_CREATE_FILTER`. The emulator keeps no filter table (its single
    /// vport receives all traffic the backend delivers), but a privileged
    /// physical-function client still expects a distinct, non-invalid handle to
    /// track for later teardown.
    next_filter_handle: u64,
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
    /// Whether the driver opted into RX CQE coalescing for this vport via the
    /// `GDMA_MESSAGE_V2` `MANA_CONFIG_VPORT_RX` request (`cqe_coalescing_enable`).
    /// When set, the datapath packs up to `MANA_RXCOMP_OOB_NUM_PPI` receive
    /// completions into a single `CQE_RX_COALESCED_4`.
    ///
    /// Shared with the running [`TxRxTask`]s (each holds a clone) so a live
    /// toggle -- the `ethtool -C rx-frames` path, which re-asserts
    /// `rx_enable=TRUE` without updating the indirection table or hash key and
    /// so does not cycle the datapath -- is observed by the receive path on its
    /// next completion batch, matching a device that applies the coalescing
    /// setting to in-flight traffic.
    cqe_coalescing: Arc<AtomicBool>,
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
        // The receive tasks are gone, so drop their fence senders: any future
        // fence has nothing in flight to order against and is posted inline.
        for rx in &mut self.queue_cfg.rx {
            rx.fence_tx = None;
        }
        self.endpoint.stop().await;
    }

    /// Poll-driven equivalent of [`Vport::stop_datapath`], for tearing the
    /// datapath down from a synchronous context (a PCIe FLR) via
    /// `poll_device`. Datapath tasks are stopped and dropped one at a time so
    /// that progress is preserved across polls: a task that has not finished
    /// stopping is left in place and re-polled on the next call.
    fn poll_stop_datapath(&mut self, cx: &mut std::task::Context<'_>) -> Poll<()> {
        while !self.tasks.is_empty() {
            let task = &mut self.tasks[0];
            if task.is_running() {
                std::task::ready!(task.poll_stop(cx));
            }
            // Dropping the task releases its backend queue.
            self.tasks.remove(0);
        }
        // The receive tasks are gone, so drop their fence senders: any future
        // fence has nothing in flight to order against and is posted inline.
        for rx in &mut self.queue_cfg.rx {
            rx.fence_tx = None;
        }
        // The backend queues are released (tasks dropped above), so stop the
        // endpoint. The emulated backends this device is built against stop
        // promptly (for example `NullEndpoint::stop` is a no-op), so the
        // residual stop completes without parking the poller.
        self.endpoint.stop().now_or_never();
        Poll::Ready(())
    }
}

/// Builds and starts one datapath task per queue pair for `vport`, resolving the
/// RSS indirection table (if present in the request payload) and plumbing the
/// resolved table + hash key down to the backend, which owns steering.
///
/// The receive path must be stopped (`tasks` empty) before calling: the initial
/// `rx_enable=TRUE` transition arrives that way, and a live re-steer must
/// `stop_datapath()` first so the backend queues are released before they are
/// re-acquired via `get_queues`.
async fn start_vport_datapath(
    vport: &mut Vport,
    state: &mut HwState,
    req: &ManaCfgRxSteerReq,
    read: &mut Limit<WqeAccess<'_>>,
) -> anyhow::Result<()> {
    let n = vport.queue_cfg.tx.len().min(vport.queue_cfg.rx.len());
    if n == 0 {
        anyhow::bail!("queues not configured");
    }

    // The guest may create more queue pairs than the backend endpoint can
    // service. The Windows VF driver, for example, creates one queue pair per
    // CPU (it does not clamp to the per-vport `max_num_rq`/`max_num_sq` the way
    // the Linux driver does), while the `consomme` NAT backend is single-queue.
    // Honor the backend's advertised limit: request only that many backend
    // queues and funnel the guest's queue pairs onto them, rather than asking
    // the backend for more queues than it supports (which single-queue backends
    // assert against).
    let backend_queues = (vport.endpoint.multiqueue_support().max_queues as usize).clamp(1, n);

    let cqe_coalescing = vport.cqe_coalescing.clone();

    // When an indirection table is supplied it is located at `indir_tab_offset`
    // bytes from the start of the GDMA request (including the request header) --
    // NOT necessarily immediately after the fixed request struct. The V2
    // steering request the Linux driver sends (GDMA_MESSAGE_V2) inserts
    // `cqe_coalescing_enable` plus reserved padding between the fixed fields and
    // the table, so the table starts 8 bytes later than the V1 layout. Honor the
    // declared offset rather than assuming the table is contiguous with the
    // struct; otherwise the device reads the table 8 bytes early and every
    // handle fails to resolve ("unknown rx queue"), which the real driver
    // surfaces as `mana_open` failing to configure the RSS table. Each entry is a
    // 64-bit work-queue object handle; translate it into the index of the receive
    // queue it names. Steering itself is performed by the backend (modeling the
    // PF / physical wire), so the device only has to plumb the resolved table and
    // hash key down to it.
    let rss = if req.update_indir_tab != 0 && req.num_indir_entries > 0 {
        let consumed = size_of::<GdmaReqHdr>() + size_of::<ManaCfgRxSteerReq>();
        let skip = (req.indir_tab_offset as usize)
            .checked_sub(consumed)
            .context("indirection table offset overlaps fixed request fields")?;
        read.skip(skip).context("seeking to indirection table")?;

        let mut table = Vec::with_capacity(req.num_indir_entries as usize);
        for _ in 0..req.num_indir_entries {
            let handle: u64 = read.read_plain().context("reading rss indirection entry")?;
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

    let configs = (0..backend_queues)
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
        queues.len() == backend_queues,
        "backend returned {} queues, expected {backend_queues}",
        queues.len()
    );

    for (j, epqueue) in queues.into_iter().enumerate() {
        // Funnel every guest send queue that maps to this backend queue
        // (round-robin over the backend queues) through it, so all of the
        // guest's transmit queues reach the backend even when there are more of
        // them than backend queues. Each send queue's completions are routed
        // back to its own CQ via the transmit id set in `process_sqe`.
        let sqs: Vec<SqChannel> = (j..n)
            .step_by(backend_queues)
            .map(|i| SqChannel {
                sq_id: vport.queue_cfg.tx[i].wq_id,
                sq_cq_id: vport.queue_cfg.tx[i].cq_id,
            })
            .collect();

        // This backend queue delivers received packets to a single guest
        // receive queue -- the backend does not itself steer across the guest's
        // queues. When the guest created more queue pairs than the backend can
        // service, the surplus receive queues stay idle (their posted buffers
        // are simply not consumed, which the driver tolerates); only these
        // primary receive queues get a fence sender, so a fence on an idle
        // queue is posted inline (nothing is in flight to order).
        let (rq_id, rq_cq_id) = (vport.queue_cfg.rx[j].wq_id, vport.queue_cfg.rx[j].cq_id);

        // Route fences for this receive object through its task so the fence
        // CQE is ordered after the task's prior receive completions.
        let (fence_tx, fence_rx) = mesh::channel();
        vport.queue_cfg.rx[j].fence_tx = Some(fence_tx);

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
                sqs,
                rq_id,
                rq_cq_id,
                tx_segment_buffer: Vec::new(),
                rx_buf_count: 0,
                cqe_coalescing: cqe_coalescing.clone(),
                fence_rx,
            },
        );
        task.start();
        vport.tasks.push(task);
    }
    Ok(())
}

/// A work-queue object created via `MANA_CREATE_WQ_OBJ`: an associated
/// work queue and completion queue, addressed by the opaque `wq_obj` handle
/// returned to the guest.
struct WqObject {
    wq_obj: u64,
    wq_id: u32,
    cq_id: u32,
    /// Set while the receive datapath task for this object is live. The
    /// `MANA_FENCE_RQ` handler sends on this channel to route the fence through
    /// the owning task, so the `CQE_RX_OBJECT_FENCE` is posted strictly after
    /// every receive completion the task has already produced (a true ordering
    /// barrier). `None` for send objects and whenever the datapath is stopped,
    /// in which case the fence is posted inline (nothing is in flight to order).
    fence_tx: Option<mesh::Sender<()>>,
}

#[derive(Default)]
struct QueueCfg {
    tx: Vec<WqObject>,
    rx: Vec<WqObject>,
}

/// A guest send queue serviced by a [`TxRxTask`]: the work-queue id polled for
/// transmit WQEs and the completion-queue id its transmit completions are
/// posted to.
struct SqChannel {
    sq_id: u32,
    sq_cq_id: u32,
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
                        cqe_coalescing: Arc::new(AtomicBool::new(false)),
                    }
                },
            )
            .collect();

        Self {
            vports,
            config,
            next_wq_obj: 1,
            next_filter_handle: 1,
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

    /// Poll-driven equivalent of [`BasicNic::shutdown`], used to tear down every
    /// vport datapath from a synchronous context (a PCIe FLR) via
    /// `poll_device`. Returns `Poll::Pending` while any vport is still
    /// stopping; earlier vports are already torn down and re-running over them
    /// on a later poll is idempotent.
    pub fn poll_shutdown(&mut self, cx: &mut std::task::Context<'_>) -> Poll<()> {
        for vport in &mut self.vports {
            std::task::ready!(vport.poll_stop_datapath(cx));
            vport.queue_cfg = QueueCfg::default();
            vport.serial_no = 0;
        }
        Poll::Ready(())
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
                    // Advertise MANA Direct: the emulated VF is presented as a
                    // standalone directly-assigned NIC with no paired synthetic
                    // (failover) partner. Without this the Windows MANA VF driver
                    // stack enumerates the VF as the accelerated member of a
                    // synthetic/VF failover pair and binds TCP/IP to the (absent)
                    // synthetic NIC instead of the VF, so the guest brings the
                    // datapath fully up yet never transmits. Linux ignores this
                    // bit (it binds its VF unconditionally), so setting it is
                    // safe for both guests.
                    pf_cap_flags1: BasicNicDriverFlags::new().with_mana_direct(1),
                    pf_cap_flags2: 0,
                    pf_cap_flags3: 0,
                    pf_cap_flags4: 0,
                    max_num_vports: self.vports.len() as u16,
                    bm_hostmode: self.config.bm_hostmode as u8,
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
                    .context("invalid vport")
                    .bnic_status(bnic_status::INVALID_VPORT_HANDLE)?;

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
                    ty => {
                        return Err(BnicStatusError::new(
                            bnic_status::UNSUPPORTED_QUEUE_TYPE,
                            anyhow!("unsupported queue type: {:?}", ty),
                        )
                        .into());
                    }
                };

                let vport_idx = req.vport as usize;
                if vport_idx >= self.vports.len() {
                    return Err(BnicStatusError::new(
                        bnic_status::INVALID_VPORT_HANDLE,
                        anyhow!("invalid vport"),
                    )
                    .into());
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
                    fence_tx: None,
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
                    ty => {
                        return Err(BnicStatusError::new(
                            bnic_status::INVALID_WQ_TYPE,
                            anyhow!("unsupported queue type: {:?}", ty),
                        )
                        .into());
                    }
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
                let wq = removed
                    .context("specified queue does not exist")
                    .bnic_status(bnic_status::INVALID_WQ_HANDLE)?;
                state.queues.free_wq(is_send, wq.wq_id).unwrap();
                state.queues.free_cq(wq.cq_id).unwrap();
            }
            ManaCommandCode::MANA_FENCE_RQ => {
                let req: ManaFenceRqReq =
                    read.read_plain().context("failed to read fence rq request")?;

                // The driver fences a receive queue (on RSS reconfiguration and
                // on vport teardown) by sending this command and then blocking
                // until a fence completion lands on the queue's CQ. The fence is
                // an ordering barrier: every receive completion already produced
                // for the queue must be visible on its CQ ahead of the
                // CQE_RX_OBJECT_FENCE. When the datapath is live, route the fence
                // through the owning receive task (the sole producer of the CQ),
                // which drains any ready receives and then posts the fence, so
                // program order provides the barrier. With no live task (during
                // teardown, or before rx_enable) nothing is in flight, so post
                // the fence inline.
                let target = self.vports.iter().find_map(|vport| {
                    vport
                        .queue_cfg
                        .rx
                        .iter()
                        .find(|w| w.wq_obj == req.wq_obj_handle)
                        .map(|w| (w.cq_id, w.wq_id, w.fence_tx.clone()))
                });
                let (cq_id, wq_id, fence_tx) = target
                    .context("specified rq does not exist")
                    .bnic_status(bnic_status::INVALID_WQ_HANDLE)?;

                let routed = match &fence_tx {
                    Some(tx) if !tx.is_closed() => {
                        tx.send(());
                        true
                    }
                    _ => false,
                };

                if !routed {
                    let fence = ManaRxcompOob {
                        cqe_hdr: ManaCqeHeader::new()
                            .with_cqe_type(CQE_RX_OBJECT_FENCE)
                            .with_client_type(MANA_CQE_COMPLETION),
                        ..FromZeros::new_zeroed()
                    };
                    state.queues.post_cq(cq_id, fence.as_bytes(), wq_id, false);
                }
            }
            ManaCommandCode::MANA_CONFIG_VPORT_RX => {
                let req: ManaCfgRxSteerReq = read
                    .read_plain()
                    .context("reading config vport rx request")?;
                tracing::debug!(?req, "rx config");

                // The driver negotiates RX CQE coalescing through the
                // `GDMA_MESSAGE_V2` form of this request. V2 inserts a
                // `cqe_coalescing_enable` byte (followed by 7 reserved bytes)
                // between the fixed request struct and the indirection table;
                // it is meaningful only when the receive path is being enabled
                // (`rx_enable != FALSE`). Peek the byte without disturbing the
                // read cursor, which `start_vport_datapath` relies on to seek to
                // the table at `indir_tab_offset`.
                let is_v2 = hdr.req.msg_version >= GDMA_MESSAGE_V2;

                let vport = self
                    .vports
                    .get_mut(req.vport as usize)
                    .context("invalid vport")
                    .bnic_status(bnic_status::INVALID_VPORT_HANDLE)?;

                if is_v2 && req.rx_enable != Tristate::FALSE {
                    let mut peek = read.clone();
                    let enable: u8 = peek.read_plain().context("reading cqe_coalescing_enable")?;
                    // Store rather than rebuild: the running receive tasks share
                    // this flag and read it on their next backend poll, so a pure
                    // coalescing toggle takes effect on live traffic without
                    // cycling the datapath (which would drop the RSS table).
                    vport.cqe_coalescing.store(enable != 0, Ordering::Relaxed);
                }

                match req.rx_enable {
                    Tristate::FALSE => {
                        vport.stop_datapath().await;
                        // The guest disabled vport receive: the port is going
                        // down, so report link-down to the driver. (A pure RSS
                        // reconfiguration cycles the datapath internally in the
                        // arm below and keeps the port up -- it must not flap
                        // the link.)
                        state.post_vport_link_status(req.vport as u32, false);
                    }
                    Tristate::TRUE if vport.tasks.is_empty() => {
                        start_vport_datapath(vport, state, &req, &mut read).await?;
                        // The vport is now fully configured and receiving. A
                        // MANA link does not come up implicitly; the device
                        // must signal it. Report link-up so the driver (the
                        // Windows VF in particular) indicates media-connect and
                        // the guest stack begins transmitting.
                        state.post_vport_link_status(req.vport as u32, true);
                    }
                    _ => {
                        // Live RSS reconfiguration on an already-running vport.
                        // The real driver (ethtool -X / `mana_config_rss` ->
                        // `mana_cfg_vport_steering`) re-asserts `rx_enable=TRUE`
                        // and sets `update_indir_tab` / `update_hashkey` to push
                        // a new indirection table or hash key WITHOUT bringing
                        // the vport down (it fences each RQ around the change).
                        // Steering is backend-owned and its only (re)config entry
                        // point is `get_queues`, so re-apply by briefly cycling
                        // the datapath: drop the tasks (releasing the backend
                        // queues) and rebuild them with the new table/key. Without
                        // this the update falls through and is silently ignored --
                        // the device acks success but the steering never changes.
                        //
                        // A pure coalescing toggle (ethtool -C rx-frames) also
                        // arrives here but carries no table or key, so it must
                        // NOT rebuild -- doing so would drop the live RSS table.
                        // The `cqe_coalescing` store above already updated the
                        // flag the running tasks share, so the toggle is honored
                        // without disturbing the datapath.
                        if !vport.tasks.is_empty()
                            && (req.update_indir_tab != 0 || req.update_hashkey != 0)
                        {
                            vport.stop_datapath().await;
                            start_vport_datapath(vport, state, &req, &mut read).await?;
                        }
                    }
                }

                // V2 requests expect a response body reporting the coalescing
                // window the device honors. V1 requests allocate no body, so the
                // `min` collapses the write to nothing.
                if is_v2 {
                    let resp = ManaCfgRxSteerResp {
                        cqe_coalescing_timeout_ns: MANA_RX_CQE_COALESCING_TIMEOUT_NS,
                        reserved1: 0,
                    };
                    let resp_bytes = resp.as_bytes();
                    let write_len = guest_resp_size.min(resp_bytes.len());
                    write.write(&resp_bytes[..write_len])?;
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
            ManaCommandCode::MANA_PF_CREATE_VPORT => {
                let _req: ManaPfCreateVportReq = read
                    .read_plain()
                    .context("reading pf create vport request")?;

                // Privileged command issued only by a physical-function client
                // that manages the NIC on behalf of the host. The client creates
                // a vport to obtain an operational handle, which it then passes
                // back as the `vport` field of the shared vport commands
                // (`MANA_CONFIG_VPORT_TX`, `MANA_CREATE_WQ_OBJ`,
                // `MANA_CONFIG_VPORT_RX`). The emulator addresses vports by index
                // and uses that index as the handle throughout (see
                // `MANA_QUERY_VPORT_CONFIG`), so the vport handle is simply the
                // index of the device's single vport. The creation-spec fields
                // (MAC, VLAN policy) are accepted but the device's configured
                // vport stays authoritative -- the client passes back the same
                // MAC it read from `MANA_QUERY_VPORT_CONFIG`.
                let resp = ManaPfCreateVportResp { vport_handle: 0 };

                write.write(resp.as_bytes())?;
            }
            ManaCommandCode::MANA_PF_CREATE_FILTER => {
                let req: ManaPfCreateFilterReq = read
                    .read_plain()
                    .context("reading pf create filter request")?;

                // The handle must resolve to an existing vport (the emulator's
                // handle is the vport index), mirroring the device rejecting an
                // unknown vport handle.
                let _vport = self
                    .vports
                    .get(req.vport_handle as usize)
                    .context("invalid vport")
                    .bnic_status(bnic_status::INVALID_VPORT_HANDLE)?;

                // The emulator keeps no MAC-filter table -- its single vport
                // receives all traffic the backend delivers -- so the filter is
                // accepted and a distinct, non-invalid handle is returned for
                // the privileged client to track. The handle is opaque to the
                // client until teardown, which the host-NIC bring-up path does
                // not reach.
                let filter_handle = self.next_filter_handle;
                self.next_filter_handle += 1;
                let resp = ManaPfCreateFilterResp { filter_handle };

                write.write(resp.as_bytes())?;
            }
            ManaCommandCode::MANA_QUERY_FILTER_CAP => {
                // Privileged query issued only by a physical-function client that
                // manages the NIC on behalf of the host (a virtual function never
                // sends it). The client uses the reported capacity to size its
                // receive-filter and receive-object pools. Report the same modest
                // limits the host miniport assumes for a basic NIC when it cannot
                // query them (one MAC filter, 64 receive objects). One filter is
                // consistent with the emulator presenting zero SR-IOV virtual
                // functions and basic networking only.
                let resp = gdma_defs::bnic::ManaQueryFilterCapResponse {
                    max_num_filters: 1,
                    max_num_rx_objects: 64,
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
                    .context("invalid vport")
                    .bnic_status(bnic_status::INVALID_VPORT_INDEX)?;

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
            ManaCommandCode::MANA_QUERY_PHY_STAT => {
                let req: ManaQueryPhyStatisticsRequest = read
                    .read_plain()
                    .context("reading query phy stats request")?;

                // `ethtool -S` triggers this physical-port statistics query. The
                // emulator models a virtual function with no physical port, so it
                // has no PHY counters to report -- mirror a real PF that returns
                // success with zeroed counters (the same path the host takes when
                // device-stats reporting is disabled), echoing the requested
                // bitmap so the driver's response validation passes. The driver
                // (`mana_query_phy_stats`) copies the fields into its per-port
                // stats unconditionally and tolerates them all being zero.
                let resp = ManaQueryPhyStatisticsResponse {
                    reported_statistics: req.requested_statistics,
                    ..FromZeros::new_zeroed()
                };

                let resp_bytes = resp.as_bytes();
                let write_len = guest_resp_size.min(resp_bytes.len());
                write.write(&resp_bytes[..write_len])?;
            }
            ManaCommandCode::MANA_QUERY_LINK_CONFIG => {
                let _req: ManaQueryLinkConfigReq = read
                    .read_plain()
                    .context("reading query link config request")?;

                // ethtool link queries (`mana_get_link_ksettings`) and the QoS
                // shaper issue this to learn the vport's link speed. Report the
                // adapter's tracked link speed; the speed is an adapter-wide
                // property in this device, so it is returned for every vport.
                // `qos_unconfigured` MUST be 0 -- the driver rejects a non-zero
                // value with -EINVAL -- and `qos_speed_mbps` is the shaper clamp
                // (the full line rate when no narrower clamp is in effect). When
                // no speed is configured we report the device's nominal line
                // rate rather than 0, which the guest would surface as an unknown
                // link speed (ethtool "Unknown!"); a PF that implements this
                // command always knows its speed.
                let speed_mbps = self.config.link_speed_mbps();
                let resp = ManaQueryLinkConfigResp {
                    qos_speed_mbps: speed_mbps,
                    qos_unconfigured: 0,
                    reserved1: [0; 3],
                    link_speed_mbps: speed_mbps,
                    reserved2: [0; 4],
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
            n => {
                // A command with no handler is one this device does not
                // implement. Report it with the GDMA core "command unsupported"
                // status (0xffffffff) rather than the generic BNIC failure
                // default: the guest's GDMA client maps this specific code to
                // -EOPNOTSUPP and tolerates it (logging at most once), whereas
                // any other non-zero status is a hard -EPROTO it logs on every
                // occurrence. This distinguishes "command not implemented" from
                // "an implemented handler failed", which keeps the generic
                // NOT_SET_BY_HANDLER default and stays -EPROTO. The real driver
                // probes optional commands (for example MANA_QUERY_LINK_CONFIG)
                // and expects 0xffffffff for the ones the device lacks.
                return Err(anyhow::anyhow!("unsupported request {:?}", n))
                    .bnic_status(GDMA_STATUS_CMD_UNSUPPORTED);
            }
        }
        Ok(guest_resp_size)
    }
}

pub struct TxRxTask {
    queues: Arc<Queues>,
    epqueue: Box<dyn Queue>,
    pool: GuestBuffers,
    /// The guest send queues funneled through this task's single backend queue.
    /// A transmit completion the backend reports carries the transmit id set in
    /// [`TxRxTask::process_sqe`] -- the index into this vector -- so the
    /// completion is posted back to the CQ of the send queue it came from.
    /// Usually a single entry (one guest queue pair per backend queue); it holds
    /// several only when the guest created more queue pairs than the backend can
    /// service.
    sqs: Vec<SqChannel>,
    rq_id: u32,
    rq_cq_id: u32,
    tx_segment_buffer: Vec<TxSegment>,
    rx_buf_count: u32,
    /// When set, pack up to `MANA_RXCOMP_OOB_NUM_PPI` ready receive completions
    /// into a single `CQE_RX_COALESCED_4` instead of posting one `CQE_RX_OKAY`
    /// per packet. Negotiated per-vport via the V2 `MANA_CONFIG_VPORT_RX` and
    /// shared with the owning [`Vport`], so a live toggle is observed here on
    /// the next backend poll without rebuilding the task.
    cqe_coalescing: Arc<AtomicBool>,
    /// Receives fence requests routed from the `MANA_FENCE_RQ` handler. Handling
    /// a fence drains the backend's ready receives and then posts a
    /// `CQE_RX_OBJECT_FENCE`, so the fence is ordered after them on the CQ.
    fence_rx: mesh::Receiver<()>,
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
            Sqe(usize, Wqe),
            Rqe(u32, Wqe),
            Ready,
            Fence,
        }

        loop {
            let event = poll_fn(|cx| {
                // Handle a pending fence before servicing the datapath. The
                // fence is a control-plane barrier the driver blocks on (with a
                // bounded ~10s timeout per queue); polling it after the receive
                // and transmit sources -- as this loop previously did -- lets
                // sustained backend readiness starve it, so the driver's fence
                // wait times out and `mana_config_rss` stalls (visible as a hang
                // on, for example, an `ethtool` reconfigure). Poll it first.
                // Ordering after in-flight receives is still guaranteed because
                // `post_fence` drains every ready receive completion onto the CQ
                // before posting the fence CQE.
                if let Poll::Ready(Ok(())) = self.fence_rx.poll_recv(cx) {
                    return Poll::Ready(Event::Fence);
                }
                // Fill rx before transmitting to avoid rx buffer starvation
                // (particularly in tests, but seems reasonable in general).
                if self.rx_buf_count < max_rx_buf {
                    if let Poll::Ready((wqe_offset, wqe)) = self.queues.poll_rq(self.rq_id, cx) {
                        self.rx_buf_count += 1;
                        return Poll::Ready(Event::Rqe(wqe_offset, wqe));
                    }
                }
                for (slot, sq) in self.sqs.iter().enumerate() {
                    if let Poll::Ready(wqe) = self.queues.poll_sq(sq.sq_id, cx) {
                        return Poll::Ready(Event::Sqe(slot, wqe));
                    }
                }
                if self.epqueue.poll_ready(cx, &mut self.pool).is_ready() {
                    return Poll::Ready(Event::Ready);
                }
                Poll::Pending
            })
            .await;
            match event {
                Event::Sqe(slot, sqe) => self.process_sqe(slot, sqe)?,
                Event::Rqe(wqe_offset, wqe) => self.process_rqe(wqe, wqe_offset)?,
                Event::Ready => self.process_backend()?,
                Event::Fence => self.post_fence()?,
            }
        }
    }

    fn process_sqe(&mut self, slot: usize, sqe: Wqe) -> anyhow::Result<()> {
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
            id: TxId(slot as u32),
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
                self.post_tx_completion_error(slot);
                return Ok(());
            }
            if sge0.size > 256 {
                tracelimit::error_ratelimited!(
                    sge0_size = sge0.size,
                    "LSO enabled and SGE[0] size > 256 bytes"
                );
                self.post_tx_completion_error(slot);
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
            self.post_tx_completion(slot);
        }
        Ok(())
    }

    // Possible test improvement: provide proper OOB data for the GDMA error.
    fn post_tx_completion_error(&mut self, slot: usize) {
        let sq = &self.sqs[slot.min(self.sqs.len() - 1)];
        let (sq_cq_id, sq_id) = (sq.sq_cq_id, sq.sq_id);
        let tx_oob = ManaTxCompOob {
            cqe_hdr: ManaCqeHeader::new()
                .with_client_type(MANA_CQE_COMPLETION)
                .with_cqe_type(CQE_TX_GDMA_ERR),
            tx_data_offset: 0,
            offsets: ManaTxCompOobOffsets::new(),
            reserved: [0; 12],
        };
        self.queues
            .post_cq(sq_cq_id, tx_oob.as_bytes(), sq_id, true);
    }

    fn post_tx_completion(&mut self, slot: usize) {
        let sq = &self.sqs[slot.min(self.sqs.len() - 1)];
        let (sq_cq_id, sq_id) = (sq.sq_cq_id, sq.sq_id);
        let tx_oob = ManaTxCompOob {
            cqe_hdr: ManaCqeHeader::new()
                .with_client_type(MANA_CQE_COMPLETION)
                .with_cqe_type(CQE_TX_OKAY),
            tx_data_offset: 0,
            offsets: ManaTxCompOobOffsets::new(),
            reserved: [0; 12],
        };
        self.queues
            .post_cq(sq_cq_id, tx_oob.as_bytes(), sq_id, true);
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
        // Pull up to `MANA_RXCOMP_OOB_NUM_PPI` ready receive completions when the
        // driver has enabled coalescing, otherwise one at a time (the historic
        // one-CQE-per-packet behavior). Packets are returned in receive-queue
        // post order, which is the order the driver consumes its posted buffers.
        let max = if self.cqe_coalescing.load(Ordering::Relaxed) {
            MANA_RXCOMP_OOB_NUM_PPI
        } else {
            1
        };
        let mut ids = [RxId(0); MANA_RXCOMP_OOB_NUM_PPI];
        let n = self.epqueue.rx_poll(&mut self.pool, &mut ids[..max])?;
        if n > 0 {
            tracing::trace!(n, "rx complete");
            self.post_rx_completions(&ids[..n])?;
            self.rx_buf_count -= n as u32;
        }

        let mut packets = [TxId(0)];
        if self.epqueue.tx_poll(&mut self.pool, &mut packets)? > 0 {
            tracing::trace!("tx async complete");
            self.post_tx_completion(packets[0].0 as usize);
        }

        Ok(())
    }

    /// Posts receive completions for `ids` (given in receive-queue post order).
    ///
    /// When coalescing is enabled a maximal run of consecutive packets that
    /// carry identical completion metadata -- a `CQE_RX_OKAY` type and the same
    /// OOB `flags` (checksum result, VLAN presence/tag, hash type), which the
    /// driver reads once per CQE and applies to every packet in the batch -- is
    /// packed into one `CQE_RX_COALESCED_4` carrying up to
    /// `MANA_RXCOMP_OOB_NUM_PPI` per-packet lengths and hashes, zero-terminated.
    /// A run of one, or any non-`CQE_RX_OKAY` completion (e.g. a truncation), is
    /// posted as its own single CQE -- matching the device rule that a batch of
    /// one is reported as `CQE_RX_OKAY`. The driver consumes one posted receive
    /// buffer per packet, in order, so coalescing never changes which buffer a
    /// packet lands in.
    fn post_rx_completions(&mut self, ids: &[RxId]) -> anyhow::Result<()> {
        let mut start = 0;
        while start < ids.len() {
            let first = self
                .pool
                .rx_packets
                .try_remove(ids[start].0 as usize)
                .context("invalid rx id")?;

            let mut oob = first.oob;
            let coalescing = self.cqe_coalescing.load(Ordering::Relaxed);
            let can_coalesce = coalescing && oob.cqe_hdr.cqe_type() == CQE_RX_OKAY;
            let first_flags = oob.flags.into_bits();

            let mut count = 1;
            if can_coalesce {
                while start + count < ids.len() && count < MANA_RXCOMP_OOB_NUM_PPI {
                    let next = &self.pool.rx_packets[ids[start + count].0 as usize];
                    if next.oob.cqe_hdr.cqe_type() != CQE_RX_OKAY
                        || next.oob.flags.into_bits() != first_flags
                    {
                        break;
                    }
                    oob.ppi[count] = next.oob.ppi[0];
                    count += 1;
                }
            }

            if count > 1 {
                oob.cqe_hdr = oob.cqe_hdr.with_cqe_type(CQE_RX_COALESCED_4);
                for k in 1..count {
                    self.pool
                        .rx_packets
                        .try_remove(ids[start + k].0 as usize)
                        .context("invalid rx id")?;
                }
            }

            self.queues
                .post_cq(self.rq_cq_id, oob.as_bytes(), self.rq_id, false);
            start += count;
        }
        Ok(())
    }

    /// Drains every receive completion the backend has already produced and then
    /// posts a `CQE_RX_OBJECT_FENCE`, making the fence a true ordering barrier:
    /// because this task is the sole producer of the receive CQ, draining first
    /// guarantees the driver observes all prior receive completions ahead of the
    /// fence. The real hardware posts the fence after in-flight receives so the
    /// driver's `fence_event` completes only once the queue has quiesced.
    fn post_fence(&mut self) -> anyhow::Result<()> {
        let max = if self.cqe_coalescing.load(Ordering::Relaxed) {
            MANA_RXCOMP_OOB_NUM_PPI
        } else {
            1
        };
        loop {
            let mut ids = [RxId(0); MANA_RXCOMP_OOB_NUM_PPI];
            let n = self.epqueue.rx_poll(&mut self.pool, &mut ids[..max])?;
            if n == 0 {
                break;
            }
            self.post_rx_completions(&ids[..n])?;
            self.rx_buf_count -= n as u32;
        }

        let fence = ManaRxcompOob {
            cqe_hdr: ManaCqeHeader::new()
                .with_cqe_type(CQE_RX_OBJECT_FENCE)
                .with_client_type(MANA_CQE_COMPLETION),
            ..FromZeros::new_zeroed()
        };
        self.queues
            .post_cq(self.rq_cq_id, fence.as_bytes(), self.rq_id, false);
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
