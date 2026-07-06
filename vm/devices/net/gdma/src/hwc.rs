// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::bnic::BasicNic;
use crate::bnic::BnicStatusError;
use crate::dma::DmaRegion;
use crate::dma::DmaRegionBuilder;
use crate::queues::QueueAllocError;
use crate::queues::Queues;
use anyhow::Context;
use anyhow::anyhow;
use gdma_defs::EqeDataReconfig;
use gdma_defs::EqeVfReset;
use gdma_defs::GDMA_EQE_HWC_INIT_DATA;
use gdma_defs::GDMA_EQE_HWC_INIT_DONE;
use gdma_defs::GDMA_EQE_HWC_INIT_EQ_ID_DB;
use gdma_defs::GDMA_EQE_HWC_RECONFIG_DATA;
use gdma_defs::GDMA_EQE_HWC_RESET_REQUEST;
use gdma_defs::GDMA_EQE_TEST_EVENT;
use gdma_defs::GdmaChangeMsixVectorIndexForEq;
use gdma_defs::GdmaCreateDmaRegionReq;
use gdma_defs::GdmaCreateDmaRegionResp;
use gdma_defs::GdmaCreateMrReq;
use gdma_defs::GdmaCreateMrResp;
use gdma_defs::GdmaCreatePdReq;
use gdma_defs::GdmaCreatePdResp;
use gdma_defs::GdmaCreateQueueReq;
use gdma_defs::GdmaCreateQueueResp;
use gdma_defs::GdmaDestroyDmaRegionReq;
use gdma_defs::GdmaDestroyMrReq;
use gdma_defs::GdmaDestroyPdReq;
use gdma_defs::GdmaDevId;
use gdma_defs::GdmaDevType;
use gdma_defs::GdmaDisableQueueReq;
use gdma_defs::GdmaDmaRegionAddPagesReq;
use gdma_defs::GdmaGenerateResetEventReq;
use gdma_defs::GdmaGenerateTestEventReq;
use gdma_defs::GdmaListDevicesResp;
use gdma_defs::GdmaQueryMaxResourcesResp;
use gdma_defs::GdmaQueueType;
use gdma_defs::GdmaRegisterDeviceResp;
use gdma_defs::GdmaReqHdr;
use gdma_defs::GdmaRequestType;
use gdma_defs::GdmaRespHdr;
use gdma_defs::GdmaVerifyVerReq;
use gdma_defs::GdmaVerifyVerResp;
use gdma_defs::HWC_DATA_TYPE_HW_VPORT_LINK_CONNECT;
use gdma_defs::HWC_DATA_TYPE_HW_VPORT_LINK_DISCONNECT;
use gdma_defs::HWC_DEV_ID;
use gdma_defs::HWC_INIT_DATA_CQID;
use gdma_defs::HWC_INIT_DATA_GPA_MKEY;
use gdma_defs::HWC_INIT_DATA_MAX_NUM_CQS;
use gdma_defs::HWC_INIT_DATA_MAX_REQUEST;
use gdma_defs::HWC_INIT_DATA_MAX_RESPONSE;
use gdma_defs::HWC_INIT_DATA_PDID;
use gdma_defs::HWC_INIT_DATA_QUEUE_DEPTH;
use gdma_defs::HWC_INIT_DATA_RQID;
use gdma_defs::HWC_INIT_DATA_SQID;
use gdma_defs::HwcInitEqIdDb;
use gdma_defs::HwcInitTypeData;
use gdma_defs::HwcRxOob;
use gdma_defs::HwcTxOob;
use gdma_defs::PAGE_SIZE64;
use gdma_defs::access::WqeAccess;
use gdma_defs::bnic::bnic_status;
use guestmem::Limit;
use guestmem::MemoryRead;
use guestmem::MemoryWrite;
use slab::Slab;
use std::future::poll_fn;
use std::sync::Arc;
use task_control::AsyncRun;
use task_control::InspectTaskMut;
use task_control::StopTask;
use zerocopy::FromBytes;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

// `instance` must be 0. Different drivers interpret the device-list response
// in two ways: one treats each entry as an opaque `{ ty, instance }` device id
// and round-trips whatever instance we report; another reads the same 16-bit
// field as a secondary client-instance index and silently discards any entry
// whose value is non-zero. A non-zero value here would cause that second driver
// to drop the basic-NIC client, so its child device is never enumerated.
const BNIC_DEV_ID: GdmaDevId = GdmaDevId {
    ty: GdmaDevType::GDMA_DEVICE_MANA,
    instance: 0,
};

pub struct HwControl {
    state: HwState,
    cq_id: u32,
    sq_id: u32,
    rq_id: u32,

    bnic_enabled: bool,
}

impl InspectTaskMut<HwControl> for Devices {
    fn inspect_mut(&mut self, req: inspect::Request<'_>, hwc: Option<&mut HwControl>) {
        let mut resp = req.respond();
        if let Some(hwc) = hwc {
            resp.child("hwc", |req| {
                req.respond()
                    .field("eq_id", hwc.state.hwc_eq_id)
                    .field("cq_id", hwc.cq_id)
                    .field("sq_id", hwc.sq_id)
                    .field("rq_id", hwc.rq_id)
                    .field("pds", hwc.state.pds.len())
                    .field("mrs", hwc.state.mrs.len());
            })
            .field("bnic/enabled", hwc.bnic_enabled);
        }
        resp.field_mut("bnic", &mut self.bnic);
    }
}

pub struct Devices {
    pub bnic: BasicNic,
}

pub struct HwState {
    pub queues: Arc<Queues>,
    /// The event queue created for the HW channel during HWC init. Async
    /// device events that the driver's HW-channel EQE handler processes (for
    /// example vport link-status changes) are posted here.
    pub hwc_eq_id: u32,
    pub dma_regions: Slab<DmaRegionState>,
    /// Live protection-domain handles. A protection domain is a handle
    /// namespace for memory regions; the emulated data path addresses guest
    /// memory by GPA and never resolves a memory key, so a domain needs no
    /// backing state beyond a live handle. Tracked so create/destroy pair up
    /// and a memory-region create can be validated against a live domain.
    pub pds: Slab<()>,
    /// Live memory-region handles. Modeled as opaque handles for the same
    /// reason as [`HwState::pds`]: the data path does not consult memory keys.
    pub mrs: Slab<()>,
}

/// A DMA region slot. A region whose page list spans multiple HW channel
/// messages stays `Building` until every page has arrived, then becomes
/// `Ready`; single-message regions are `Ready` immediately. Only `Ready`
/// regions can be bound to a queue.
pub enum DmaRegionState {
    Building(DmaRegionBuilder),
    Ready(DmaRegion),
}

impl HwState {
    pub fn get_dma_region(
        &self,
        gdma_region: u64,
        expected_size: u32,
    ) -> anyhow::Result<&DmaRegion> {
        let region = self
            .dma_regions
            .get(gdma_region.wrapping_sub(1) as usize)
            .context("dma region not found")?;
        let region = match region {
            DmaRegionState::Ready(region) => region,
            DmaRegionState::Building(_) => {
                anyhow::bail!("dma region page list is incomplete")
            }
        };
        if region.len() != expected_size as usize {
            anyhow::bail!("dma region size does not match");
        }
        Ok(region)
    }

    pub fn remove_dma_region(&mut self, gdma_region: u64) -> anyhow::Result<()> {
        self.dma_regions
            .try_remove(gdma_region.wrapping_sub(1) as usize)
            .context("invalid gdma region")?;
        Ok(())
    }

    /// Post an asynchronous vport link-status event on the HW channel EQ.
    ///
    /// A MANA vport does not implicitly come up "link up": the device reports
    /// the operational link state to the driver through a reconfig EQE on the
    /// HW channel event queue. The Windows VF miniport waits for this event
    /// before it indicates media-connect to NDIS, so until the device sends it
    /// the guest network stack stays media-disconnected and transmits nothing
    /// (no ARP/DHCP) even though the data path is fully configured. (The Linux
    /// netdev driver is not sensitive to this because it marks the carrier up
    /// unconditionally at probe and treats the reconfig event as supplementary.)
    /// Report link-up when the guest enables vport receive, link-down when it
    /// disables it. The event names the affected vport by index in its 24-bit
    /// value field.
    pub fn post_vport_link_status(&self, vport_index: u32, connected: bool) {
        let data_type = if connected {
            HWC_DATA_TYPE_HW_VPORT_LINK_CONNECT
        } else {
            HWC_DATA_TYPE_HW_VPORT_LINK_DISCONNECT
        };
        let value = vport_index.to_le_bytes();
        self.queues.post_eq(
            self.hwc_eq_id,
            GDMA_EQE_HWC_RECONFIG_DATA,
            EqeDataReconfig {
                data: [value[0], value[1], value[2]],
                data_type,
                reserved1: [0; 8],
            }
            .as_bytes(),
        );
    }

    /// Post an asynchronous device reset-request event on the HW channel EQ
    /// (`GDMA_EQE_HWC_RESET_REQUEST` == 135).
    ///
    /// This is the one device->guest asynchronous lever that forces the guest
    /// to tear the function all the way down and rebuild it. The Windows VF
    /// responds by halting its NIC, re-establishing the HW channel, and
    /// re-running its entire bring-up (vport create, receive-filter install,
    /// receive-indication enable). Because the receive-indication gate that
    /// blocks the Windows DHCP path has no device-observable input, forcing a
    /// clean rebirth this way is the only device-side means to make the guest
    /// re-run that path -- so it serves as a diagnostic crutch, not a
    /// production behavior. `revoke_vtl0_vf=false`: a plain VF has no
    /// subordinate VTL0 to revoke and re-offer.
    pub fn post_hwc_reset_request(&self) {
        self.queues.post_eq(
            self.hwc_eq_id,
            GDMA_EQE_HWC_RESET_REQUEST,
            EqeVfReset::new().as_bytes(),
        );
    }
}

impl HwControl {
    pub fn new(
        queues: Arc<Queues>,
        sq_gpa: u64,
        rq_gpa: u64,
        cq_gpa: u64,
        eq_gpa: u64,
        eq_msix: u32,
    ) -> Result<Self, QueueAllocError> {
        tracing::info!(sq_gpa, rq_gpa, cq_gpa, eq_gpa, eq_msix, "enabling hwc");

        let sq_region = DmaRegion::new(vec![sq_gpa], 0, PAGE_SIZE64).unwrap();
        let rq_region = DmaRegion::new(vec![rq_gpa], 0, PAGE_SIZE64).unwrap();
        let eq_region = DmaRegion::new(vec![eq_gpa], 0, PAGE_SIZE64).unwrap();
        let cq_region = DmaRegion::new(vec![cq_gpa], 0, PAGE_SIZE64).unwrap();

        let sq_id = queues.alloc_wq(true, sq_region)?;
        let rq_id = queues.alloc_wq(false, rq_region)?;
        let eq_id = queues.alloc_eq(eq_region, eq_msix)?;
        let cq_id = queues.alloc_cq(cq_region, eq_id)?;

        queues.post_eq(
            eq_id,
            GDMA_EQE_HWC_INIT_EQ_ID_DB,
            HwcInitEqIdDb::new()
                .with_eq_id(eq_id as u16)
                .with_doorbell(0)
                .as_bytes(),
        );

        let data = [
            (HWC_INIT_DATA_CQID, cq_id),
            (HWC_INIT_DATA_RQID, rq_id),
            (HWC_INIT_DATA_SQID, sq_id),
            (HWC_INIT_DATA_QUEUE_DEPTH, 1),
            (HWC_INIT_DATA_MAX_REQUEST, 0x1000),
            (HWC_INIT_DATA_MAX_RESPONSE, 0x1000),
            (HWC_INIT_DATA_MAX_NUM_CQS, queues.max_cqs()),
            (HWC_INIT_DATA_PDID, 0),
            (HWC_INIT_DATA_GPA_MKEY, 0),
        ];

        for (ty, val) in data {
            queues.post_eq(
                eq_id,
                GDMA_EQE_HWC_INIT_DATA,
                HwcInitTypeData::new()
                    .with_ty(ty)
                    .with_value(val)
                    .as_bytes(),
            );
        }

        queues.post_eq(eq_id, GDMA_EQE_HWC_INIT_DONE, &[]);

        Ok(Self {
            state: HwState {
                queues,
                hwc_eq_id: eq_id,
                dma_regions: Slab::new(),
                pds: Slab::new(),
                mrs: Slab::new(),
            },
            cq_id,
            sq_id,
            rq_id,

            bnic_enabled: false,
        })
    }

    async fn process(&mut self, devices: &mut Devices) -> anyhow::Result<()> {
        tracing::info!("starting hwc");

        loop {
            let sqe = poll_fn(|cx| self.state.queues.poll_sq(self.sq_id, cx)).await;
            let (rqe_offset, rqe) = poll_fn(|cx| self.state.queues.poll_rq(self.rq_id, cx)).await;

            let queues = self.state.queues.clone();
            let tx_oob = HwcTxOob::read_from_prefix(sqe.oob())
                .map_err(|_| anyhow!("reading tx oob"))?
                .0; // TODO: zerocopy: map_err, use-rest-of-range, use error details in the returned `anyhow!` (https://github.com/microsoft/openvmm/issues/759)
            if tx_oob.flags3.vscq_id() != self.cq_id {
                anyhow::bail!(
                    "mismatched cq id: {} != {}",
                    tx_oob.flags3.vscq_id(),
                    self.cq_id
                );
            }

            if tx_oob.flags4.vsq_id() != self.sq_id {
                anyhow::bail!(
                    "mismatched sq id: {} != {}",
                    tx_oob.flags4.vsq_id(),
                    self.sq_id
                );
            }

            let read = sqe.access(&queues.gm);
            let hdr: GdmaReqHdr = read
                .clone()
                .read_plain()
                .context("reading request message header")?;

            // The authoritative request length is the work request's posted data
            // length (its out-of-band length), not the header's self-reported
            // `msg_size`. A physical function sets `msg_size` to the request's
            // fixed base size and conveys the true length -- including a
            // variable-length trailer such as a DMA region page array -- via the
            // work-request length; bounding the read by `msg_size` would truncate
            // that trailer. A virtual function posts the work request at exactly
            // `msg_size` bytes, so the two are equivalent for it.
            let req_len = MemoryRead::len(&read);
            if req_len as u64 > PAGE_SIZE64 {
                anyhow::bail!("request message length {req_len} exceeds page size {PAGE_SIZE64}");
            }
            if hdr.resp.msg_size as u64 > PAGE_SIZE64 {
                anyhow::bail!(
                    "response message size {} exceeds page size {PAGE_SIZE64}",
                    hdr.resp.msg_size
                );
            }

            let mut read = MemoryRead::limit(read, req_len);
            read.skip(size_of_val(&hdr))
                .context("message size too small")?;

            let mut write = MemoryWrite::limit(rqe.access(&queues.gm), hdr.resp.msg_size as usize);
            let mut header_write = write.clone();
            write
                .skip(size_of::<GdmaRespHdr>())
                .context("response message too small")?;

            let r = match hdr.req.msg_type >> 16 {
                0 => self.handle_req(&hdr, read, write),
                _ => {
                    // Device-specific (BNIC/MANA) command. The MANA client is
                    // provisioned by the host as part of hardware-channel
                    // bring-up: completing HWC setup delivers an init EQE that
                    // carries the client's pdid and resource limits, after which
                    // the client is addressable. `GDMA_REGISTER_DEVICE` is an
                    // optional, redundant confirmation -- some drivers send it
                    // (the in-tree mana_driver and the Linux driver) and others
                    // skip it, issuing MANA commands directly after HWC init (the
                    // Windows VF driver, and a physical function). Requiring an
                    // explicit register here would wrongly reject the latter.
                    // Reaching this dispatch means the HWC is live, so accept any
                    // command addressed to the MANA client.
                    if hdr.dev_id == BNIC_DEV_ID {
                        devices
                            .bnic
                            .handle_req(&mut self.state, &hdr, read, write)
                            .await
                    } else {
                        Err(anyhow!("unknown device {:?}", hdr.dev_id))
                    }
                }
            };

            let (status, response_len) = match r {
                Ok(response_len) => (0, response_len),
                Err(err) => {
                    // BNIC client messages carry device-specific status codes:
                    // surface the code a handler tagged onto the error, else the
                    // device's generic "not set by handler" default. Core GDMA
                    // requests keep the generic non-zero failure code.
                    let status = err.downcast_ref::<BnicStatusError>().map_or(
                        if hdr.req.msg_type >> 16 != 0 && hdr.dev_id == BNIC_DEV_ID {
                            bnic_status::NOT_SET_BY_HANDLER
                        } else {
                            1
                        },
                        |e| e.status,
                    );
                    tracing::warn!(
                        msg_type = hdr.req.msg_type,
                        dev_id = ?hdr.dev_id,
                        status,
                        error = err.as_ref() as &dyn std::error::Error,
                        "req error"
                    );
                    (status, 0)
                }
            };

            self.state.queues.post_cq(self.cq_id, &[], self.sq_id, true);

            let resp = GdmaRespHdr {
                response: hdr.resp,
                dev_id: hdr.dev_id,
                activity_id: hdr.activity_id,
                status,
                reserved: 0,
            };

            header_write
                .write(resp.as_bytes())
                .context("writing response message header")?;

            let rx_oob = HwcRxOob {
                wqe_addr_low_or_offset: rqe_offset,
                tx_oob_data_size: (size_of_val(&resp) + response_len) as u32,
                ..FromZeros::new_zeroed()
            };

            self.state
                .queues
                .post_cq(self.cq_id, rx_oob.as_bytes(), self.rq_id, false);
        }
    }

    fn handle_req(
        &mut self,
        hdr: &GdmaReqHdr,
        mut read: Limit<WqeAccess<'_>>,
        mut write: Limit<WqeAccess<'_>>,
    ) -> anyhow::Result<usize> {
        tracing::debug!(msg_type = ?GdmaRequestType(hdr.req.msg_type), "hwc request");

        let response_len = match GdmaRequestType(hdr.req.msg_type) {
            GdmaRequestType::GDMA_GENERATE_TEST_EQE => {
                let req: GdmaGenerateTestEventReq =
                    read.read_plain().context("reading test eqe request")?;
                self.state
                    .queues
                    .post_eq(req.queue_index, GDMA_EQE_TEST_EVENT, &[]);

                0
            }
            GdmaRequestType::GDMA_GENERATE_RESET_REQUEST_EQE => {
                let req: GdmaGenerateResetEventReq =
                    read.read_plain().context("reading reset request EQE")?;
                self.state.queues.post_eq(
                    req.queue_index,
                    GDMA_EQE_HWC_RESET_REQUEST,
                    req.data.as_bytes(),
                );
                0
            }
            GdmaRequestType::GDMA_VERIFY_VF_DRIVER_VERSION => {
                let req: GdmaVerifyVerReq = read
                    .read_plain()
                    .context("reading verify vf driver request")?;

                let drv_name = core::ffi::CStr::from_bytes_until_nul(&req.os_ver_str1)
                    .ok()
                    .and_then(|c| c.to_str().ok())
                    .unwrap_or("<invalid>");
                let drv_commit = core::ffi::CStr::from_bytes_until_nul(&req.os_ver_str2)
                    .ok()
                    .and_then(|c| c.to_str().ok())
                    .unwrap_or("<invalid>");
                tracing::info!(
                    drv_name,
                    drv_commit,
                    os_type = format_args!("{:#x}", req.os_type),
                    os_ver_major = req.os_ver_major,
                    os_ver_minor = req.os_ver_minor,
                    os_ver_build = req.os_ver_build,
                    os_ver_platform = req.os_ver_platform,
                    cap_flags1 = format_args!("{:#x}", req.gd_drv_cap_flags1),
                    protocol_ver_min = req.protocol_ver_min,
                    protocol_ver_max = req.protocol_ver_max,
                    "vf driver version",
                );

                let resp = GdmaVerifyVerResp {
                    gdma_protocol_ver: req.protocol_ver_min,
                    pf_cap_flags1: 0,
                    pf_cap_flags2: 0,
                    pf_cap_flags3: 0,
                    pf_cap_flags4: 0,
                };

                write
                    .write(resp.as_bytes())
                    .context("writing verify vf driver response")?;
                size_of_val(&resp)
            }
            GdmaRequestType::GDMA_QUERY_MAX_RESOURCES => {
                let resp = GdmaQueryMaxResourcesResp {
                    status: 0,
                    max_sq: self.state.queues.max_sqs(),
                    max_rq: self.state.queues.max_rqs(),
                    max_cq: self.state.queues.max_cqs(),
                    max_eq: self.state.queues.max_eqs(),
                    max_db: 1,
                    max_mst: 1,
                    max_cq_mod_ctx: 0,
                    max_mod_cq: 0,
                    max_msix: 64,
                };

                write
                    .write(resp.as_bytes())
                    .context("writing query max response")?;
                size_of_val(&resp)
            }
            GdmaRequestType::GDMA_LIST_DEVICES => {
                let mut resp = GdmaListDevicesResp {
                    num_of_devs: 2,
                    ..FromZeros::new_zeroed()
                };
                resp.devs[0] = HWC_DEV_ID;
                resp.devs[1] = BNIC_DEV_ID;

                write
                    .write(resp.as_bytes())
                    .context("writing gdma list response")?;
                size_of_val(&resp)
            }
            GdmaRequestType::GDMA_REGISTER_DEVICE => {
                if hdr.dev_id != BNIC_DEV_ID {
                    anyhow::bail!("invalid device id: {:?}", hdr.dev_id);
                }

                if self.bnic_enabled {
                    anyhow::bail!("bnic already enabled");
                }

                self.bnic_enabled = true;

                let resp = GdmaRegisterDeviceResp {
                    pdid: 0,
                    gpa_mkey: 0,
                    db_id: 0,
                };

                write
                    .write(resp.as_bytes())
                    .context("writing register device response")?;
                size_of_val(&resp)
            }
            GdmaRequestType::GDMA_CREATE_DMA_REGION => {
                let req: GdmaCreateDmaRegionReq =
                    read.read_plain().context("reading dma region request")?;
                let pages: Vec<u64> = read
                    .read_n(req.page_addr_list_len as usize)
                    .context("reading dma region pages")?;

                // The guest may deliver the page list across multiple messages:
                // when `page_addr_list_len` is short of `page_count`, the rest
                // arrive via GDMA_DMA_REGION_ADD_PAGES. Hold the region as
                // `Building` until it is whole, then finalize it.
                let builder =
                    DmaRegionBuilder::new(pages, req.offset_in_page, req.length, req.page_count)
                        .context("failed to parse dma region input")?;
                let state = if builder.is_complete() {
                    DmaRegionState::Ready(
                        builder
                            .build()
                            .context("failed to parse dma region input")?,
                    )
                } else {
                    DmaRegionState::Building(builder)
                };
                let gdma_region = self.state.dma_regions.insert(state) as u64 + 1;

                let resp = GdmaCreateDmaRegionResp { gdma_region };
                write
                    .write(resp.as_bytes())
                    .context("writing dma region response")?;
                size_of_val(&resp)
            }
            GdmaRequestType::GDMA_DMA_REGION_ADD_PAGES => {
                let req: GdmaDmaRegionAddPagesReq =
                    read.read_plain().context("reading add pages request")?;
                let pages: Vec<u64> = read
                    .read_n(req.page_addr_list_len as usize)
                    .context("reading add pages list")?;

                let slot = self
                    .state
                    .dma_regions
                    .get_mut(req.gdma_region.wrapping_sub(1) as usize)
                    .context("dma region not found")?;
                let DmaRegionState::Building(builder) = slot else {
                    anyhow::bail!("dma region is not awaiting more pages");
                };
                builder
                    .add_pages(&pages)
                    .context("adding pages to dma region")?;
                if builder.is_complete() {
                    let region = builder.build().context("finalizing dma region")?;
                    *slot = DmaRegionState::Ready(region);
                }
                0
            }
            GdmaRequestType::GDMA_DESTROY_DMA_REGION => {
                let req: GdmaDestroyDmaRegionReq = read
                    .read_plain()
                    .context("reading destroy dma region request")?;
                self.state
                    .remove_dma_region(req.gdma_region)
                    .context("destroying dma region")?;
                0
            }
            GdmaRequestType::GDMA_CREATE_QUEUE => {
                let req: GdmaCreateQueueReq = read.read_plain().context("reading queue request")?;
                if req.queue_type != GdmaQueueType::GDMA_EQ {
                    anyhow::bail!("unsupported queue type: {:?}", req.queue_type);
                }

                let region = self.state.get_dma_region(req.gdma_region, req.queue_size)?;

                let eq_id = self
                    .state
                    .queues
                    .alloc_eq(region.clone(), req.eq_pci_msix_index)
                    .context("failed to allocate queue")?;

                let resp = GdmaCreateQueueResp { queue_index: eq_id };
                write
                    .write(resp.as_bytes())
                    .context("writing queue response")?;

                // Take ownership of the DMA region.
                self.state.remove_dma_region(req.gdma_region).unwrap();
                size_of_val(&resp)
            }
            GdmaRequestType::GDMA_DISABLE_QUEUE => {
                let req: GdmaDisableQueueReq = read
                    .read_plain()
                    .context("failed to read disable queue request")?;
                if req.queue_type != GdmaQueueType::GDMA_EQ {
                    anyhow::bail!("unsupported queue type: {:?}", req.queue_type);
                }
                if req.alloc_res_id_on_creation != 1 {
                    tracing::warn!(
                        value = req.alloc_res_id_on_creation,
                        "mystery value not set to 1"
                    );
                }
                self.state.queues.free_eq(req.queue_index)?;
                0
            }
            GdmaRequestType::GDMA_CHANGE_MSIX_FOR_EQ => {
                let req: GdmaChangeMsixVectorIndexForEq = read
                    .read_plain()
                    .context("failed to read change eq msix request")?;
                self.state
                    .queues
                    .update_eq_msix(req.queue_index, req.msix)?;
                0
            }
            GdmaRequestType::GDMA_DEREGISTER_DEVICE => {
                if hdr.dev_id != BNIC_DEV_ID {
                    anyhow::bail!("invalid device id: {:?}", hdr.dev_id);
                }

                if !self.bnic_enabled {
                    anyhow::bail!("bnic not enabled");
                }

                self.bnic_enabled = false;
                0
            }
            GdmaRequestType::GDMA_CREATE_PD => {
                // A protection domain is a handle namespace for memory regions.
                // The emulated data path addresses guest memory by GPA and never
                // resolves a memory key, so a domain needs no backing state
                // beyond a live handle: allocate one and report it, with `pd_id`
                // mirroring the handle. The Windows VF driver creates a global
                // domain while starting the device to bring up its RDMA/NDK
                // capability; the Linux NIC driver never issues this.
                let _req: GdmaCreatePdReq =
                    read.read_plain().context("reading create pd request")?;
                let key = self.state.pds.insert(());
                let resp = GdmaCreatePdResp {
                    pd_handle: key as u64 + 1,
                    pd_id: key as u32 + 1,
                    reserved: 0,
                };
                write
                    .write(resp.as_bytes())
                    .context("writing create pd response")?;
                size_of_val(&resp)
            }
            GdmaRequestType::GDMA_DESTROY_PD => {
                let req: GdmaDestroyPdReq =
                    read.read_plain().context("reading destroy pd request")?;
                self.state
                    .pds
                    .try_remove(req.pd_handle.wrapping_sub(1) as usize)
                    .context("destroying unknown pd handle")?;
                0
            }
            GdmaRequestType::GDMA_CREATE_MR => {
                // A memory region is registered within a protection domain. As
                // with GDMA_CREATE_PD, only the handle matters to the emulator:
                // the data path never resolves the returned keys, so report an
                // opaque handle and usable, non-zero keys. Validate that the
                // referenced domain is live.
                let req: GdmaCreateMrReq =
                    read.read_plain().context("reading create mr request")?;
                if !self
                    .state
                    .pds
                    .contains(req.pd_handle.wrapping_sub(1) as usize)
                {
                    anyhow::bail!(
                        "create mr references unknown pd handle {:#x}",
                        req.pd_handle
                    );
                }
                let key = self.state.mrs.insert(());
                let mem_key = key as u32 + 1;
                let resp = GdmaCreateMrResp {
                    mr_handle: key as u64 + 1,
                    lkey: mem_key,
                    rkey: mem_key,
                };
                write
                    .write(resp.as_bytes())
                    .context("writing create mr response")?;
                size_of_val(&resp)
            }
            GdmaRequestType::GDMA_DESTROY_MR => {
                let req: GdmaDestroyMrReq =
                    read.read_plain().context("reading destroy mr request")?;
                self.state
                    .mrs
                    .try_remove(req.mr_handle.wrapping_sub(1) as usize)
                    .context("destroying unknown mr handle")?;
                0
            }
            ty => {
                anyhow::bail!("unsupported message type: {:x?}", ty);
            }
        };
        Ok(response_len)
    }
}

impl AsyncRun<HwControl> for Devices {
    async fn run(
        &mut self,
        stop: &mut StopTask<'_>,
        hwc: &mut HwControl,
    ) -> Result<(), task_control::Cancelled> {
        stop.until_stopped(async {
            if let Err(err) = hwc.process(self).await {
                tracing::error!(
                    error = err.as_ref() as &dyn std::error::Error,
                    "hwc failure"
                )
            }
        })
        .await
    }
}
