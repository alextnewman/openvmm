// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! This module drives the MANA emuulator with the MANA driver to test the
//! end-to-end flow.

use crate::bnic_driver::BnicDriver;
use crate::bnic_driver::RxConfig;
use crate::bnic_driver::WqConfig;
use crate::gdma_driver::GdmaDriver;
use crate::mana::ResourceArena;
use crate::queues::Cq;
use crate::queues::DoorbellPage;
use async_trait::async_trait;
use chipset_device::mmio::ExternallyManagedMmioIntercepts;
use chipset_device::pci::PciConfigSpace;
use chipset_device::poll_device::PollDevice;
use gdma::VportConfig;
use gdma_defs::GDMA_MESSAGE_V1;
use gdma_defs::GDMA_PAGE_TYPE_4K;
use gdma_defs::GDMA_STATUS_CMD_UNSUPPORTED;
use gdma_defs::GdmaCreateDmaRegionReq;
use gdma_defs::GdmaCreateDmaRegionResp;
use gdma_defs::GdmaCreateMrReq;
use gdma_defs::GdmaCreateMrResp;
use gdma_defs::GdmaCreatePdReq;
use gdma_defs::GdmaCreatePdResp;
use gdma_defs::GdmaDestroyMrReq;
use gdma_defs::GdmaDestroyPdReq;
use gdma_defs::GdmaDevId;
use gdma_defs::GdmaDevType;
use gdma_defs::GdmaDmaRegionAddPagesReq;
use gdma_defs::GdmaQueueType;
use gdma_defs::GdmaReqHdr;
use gdma_defs::GdmaRequestType;
use gdma_defs::PAGE_SIZE64;
use gdma_defs::RegMap;
use gdma_defs::SMC_MSG_TYPE_DESTROY_HWC_VERSION;
use gdma_defs::SmcMessageType;
use gdma_defs::SmcProtoHdr;
use gdma_defs::bnic::CQE_RX_OBJECT_FENCE;
use gdma_defs::bnic::MANA_DEFAULT_LINK_SPEED_MBPS;
use gdma_defs::bnic::ManaCfgRxSteerReq;
use gdma_defs::bnic::ManaCommandCode;
use gdma_defs::bnic::ManaConfigVportReq;
use gdma_defs::bnic::ManaConfigVportResp;
use gdma_defs::bnic::ManaCqeHeader;
use gdma_defs::bnic::ManaCreateWqobjReq;
use gdma_defs::bnic::ManaFenceRqReq;
use gdma_defs::bnic::ManaPfCreateFilterReq;
use gdma_defs::bnic::ManaPfCreateFilterResp;
use gdma_defs::bnic::ManaPfCreateVportReq;
use gdma_defs::bnic::ManaPfCreateVportResp;
use gdma_defs::bnic::ManaQueryFilterCapResponse;
use gdma_defs::bnic::ManaQueryLinkConfigReq;
use gdma_defs::bnic::ManaQueryLinkConfigResp;
use gdma_defs::bnic::STATISTICS_FLAGS_ALL;
use gdma_defs::bnic::Tristate;
use gdma_defs::bnic::bnic_status;
use inspect::InspectMut;
use net_backend::Endpoint;
use net_backend::MultiQueueSupport;
use net_backend::Queue;
use net_backend::QueueConfig;
use net_backend::RssConfig;
use net_backend::null::NullEndpoint;
use pal_async::DefaultDriver;
use pal_async::async_test;
use parking_lot::Mutex;
use pci_core::bus_range::AssignedBusRange;
use pci_core::msi::MsiConnection;
use pci_core::spec::cfg_space::Command;
use std::future::poll_fn;
use std::sync::Arc;
use std::task::Poll;
use test_with_tracing::test;
use user_driver::DeviceBacking;
use user_driver::DeviceRegisterIo;
use user_driver::memory::MemoryBlock;
use user_driver::memory::PAGE_SIZE;
use user_driver_emulated_mock::DeviceTestMemory;
use user_driver_emulated_mock::EmulatedDevice;
use vmcore::device_state::ChangeDeviceState;
use vmcore::vm_task::SingleDriverBackend;
use vmcore::vm_task::VmTaskDriverSource;
use zerocopy::FromBytes;
use zerocopy::FromZeros;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

#[async_test]
async fn test_gdma(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let dma_client = mem.dma_client();
    let device = EmulatedDevice::new(device, msi_conn, dma_client);
    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();
    gdma.test_eq().await.unwrap();
    gdma.verify_vf_driver_version().await.unwrap();
    let dev_id = gdma
        .list_devices()
        .await
        .unwrap()
        .iter()
        .copied()
        .find(|dev_id| dev_id.ty == GdmaDevType::GDMA_DEVICE_MANA)
        .unwrap();

    // The MANA device must be reported at instance 0. Some drivers read this
    // 16-bit field as a secondary client-instance index and drop any network
    // client with a non-zero value, so a regression here would silently prevent
    // the network child device from being enumerated -- even though drivers that
    // treat it as an opaque device-id instance are indifferent to the value.
    assert_eq!(dev_id.instance, 0);

    let device_props = gdma.register_device(dev_id).await.unwrap();
    let mut bnic = BnicDriver::new(&mut gdma, dev_id);
    let _dev_config = bnic.query_dev_config().await.unwrap();
    let port_config = bnic.query_vport_config(0).await.unwrap();
    let vport = port_config.vport;
    let buffer = Arc::new(
        gdma.device()
            .dma_client()
            .allocate_dma_buffer(0x5000)
            .unwrap(),
    );
    let mut arena = ResourceArena::new();
    let eq_gdma_region = gdma
        .create_dma_region(&mut arena, dev_id, buffer.subblock(0, PAGE_SIZE))
        .await
        .unwrap();
    let rq_gdma_region = gdma
        .create_dma_region(&mut arena, dev_id, buffer.subblock(PAGE_SIZE, PAGE_SIZE))
        .await
        .unwrap();
    let rq_cq_gdma_region = gdma
        .create_dma_region(
            &mut arena,
            dev_id,
            buffer.subblock(2 * PAGE_SIZE, PAGE_SIZE),
        )
        .await
        .unwrap();
    let sq_gdma_region = gdma
        .create_dma_region(
            &mut arena,
            dev_id,
            buffer.subblock(3 * PAGE_SIZE, PAGE_SIZE),
        )
        .await
        .unwrap();
    let sq_cq_gdma_region = gdma
        .create_dma_region(
            &mut arena,
            dev_id,
            buffer.subblock(4 * PAGE_SIZE, PAGE_SIZE),
        )
        .await
        .unwrap();
    let (eq_id, _) = gdma
        .create_eq(
            &mut arena,
            dev_id,
            eq_gdma_region,
            PAGE_SIZE as u32,
            device_props.pdid,
            device_props.db_id,
            0,
        )
        .await
        .unwrap();
    let mut bnic = BnicDriver::new(&mut gdma, dev_id);
    let _rq_cfg = bnic
        .create_wq_obj(
            &mut arena,
            vport,
            GdmaQueueType::GDMA_RQ,
            &WqConfig {
                wq_gdma_region: rq_gdma_region,
                cq_gdma_region: rq_cq_gdma_region,
                wq_size: PAGE_SIZE as u32,
                cq_size: PAGE_SIZE as u32,
                cq_moderation_ctx_id: 0,
                eq_id,
            },
        )
        .await
        .unwrap();
    let _sq_cfg = bnic
        .create_wq_obj(
            &mut arena,
            vport,
            GdmaQueueType::GDMA_SQ,
            &WqConfig {
                wq_gdma_region: sq_gdma_region,
                cq_gdma_region: sq_cq_gdma_region,
                wq_size: PAGE_SIZE as u32,
                cq_size: PAGE_SIZE as u32,
                cq_moderation_ctx_id: 0,
                eq_id,
            },
        )
        .await
        .unwrap();
    bnic.config_vport_tx(vport, 0, 0).await.unwrap();
    bnic.config_vport_rx(
        vport,
        &RxConfig {
            rx_enable: Some(true),
            rss_enable: Some(false),
            hash_key: None,
            default_rxobj: None,
            indirection_table: None,
            cqe_coalescing: false,
        },
    )
    .await
    .unwrap();
    arena.destroy(&mut gdma).await;
}

/// A virtual-function driver may issue MANA device commands as soon as the
/// hardware channel is up, without first sending `GDMA_REGISTER_DEVICE`. The
/// MANA client is provisioned by the HWC init handshake -- the init EQE carries
/// its pdid and resource limits -- so it is addressable immediately. The
/// Windows VF driver relies on this ordering: it queries the device
/// configuration directly after HWC bring-up. (The in-tree driver and the Linux
/// driver instead send a redundant `GDMA_REGISTER_DEVICE` first, as `test_gdma`
/// exercises; both orderings must work.) Regression test for a VF start failure
/// where the device rejected the un-preceded `MANA_QUERY_DEV_CONFIG` as an
/// "unknown device".
#[async_test]
async fn test_gdma_mana_command_without_register(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma_mana_command_without_register");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let dma_client = mem.dma_client();
    let device = EmulatedDevice::new(device, msi_conn, dma_client);
    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();
    gdma.test_eq().await.unwrap();
    gdma.verify_vf_driver_version().await.unwrap();
    let dev_id = gdma
        .list_devices()
        .await
        .unwrap()
        .iter()
        .copied()
        .find(|dev_id| dev_id.ty == GdmaDevType::GDMA_DEVICE_MANA)
        .unwrap();

    // Deliberately skip `gdma.register_device(dev_id)` and issue a MANA command
    // directly, exactly as the Windows VF driver does after HWC init. This must
    // succeed: the client is already provisioned by the HWC bring-up.
    let mut bnic = BnicDriver::new(&mut gdma, dev_id);
    bnic.query_dev_config().await.unwrap();
}

/// The Windows VF driver is a combined NIC + RDMA driver: while starting the
/// device it creates a global protection domain and registers a memory region
/// to bring up its RDMA/NDK capability, issuing `GDMA_CREATE_PD` and
/// `GDMA_CREATE_MR` on the core-GDMA device (the null device id) directly after
/// HWC init. The Linux NIC driver never issues these. The emulator services them
/// as handle allocators -- its data path addresses guest memory by GPA and never
/// resolves a memory key -- so create returns a live handle (and usable, non-zero
/// keys for a memory region) and destroy releases it. Regression test for a VF
/// start failure where the device rejected `GDMA_CREATE_PD` as an "unsupported
/// message type", aborting device start with `STATUS_UNSUCCESSFUL`.
#[async_test]
async fn test_gdma_create_pd_mr(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma_create_pd_mr");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let dma_client = mem.dma_client();
    let device = EmulatedDevice::new(device, msi_conn, dma_client);
    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();
    gdma.test_eq().await.unwrap();
    gdma.verify_vf_driver_version().await.unwrap();

    // Core-GDMA resource ops are addressed to the null device, exactly as the
    // Windows VF driver issues them after HWC init.
    let none = GdmaDevId {
        ty: GdmaDevType::GDMA_DEVICE_NONE,
        instance: 0,
    };

    let pd: GdmaCreatePdResp = gdma
        .request(
            GdmaRequestType::GDMA_CREATE_PD.0,
            none,
            GdmaCreatePdReq {
                flags: 0,
                reserved: 0,
            },
        )
        .await
        .unwrap();
    assert_ne!(pd.pd_handle, 0);
    assert_ne!(pd.pd_id, 0);

    let mr: GdmaCreateMrResp = gdma
        .request(
            GdmaRequestType::GDMA_CREATE_MR.0,
            none,
            GdmaCreateMrReq {
                pd_handle: pd.pd_handle,
                mr_type: 1,
                reserved: 0,
            },
        )
        .await
        .unwrap();
    assert_ne!(mr.mr_handle, 0);
    assert_ne!(mr.lkey, 0);
    assert_eq!(mr.lkey, mr.rkey);

    // Release in reverse order; both must succeed so the channel drops cleanly.
    gdma.request::<_, ()>(
        GdmaRequestType::GDMA_DESTROY_MR.0,
        none,
        GdmaDestroyMrReq {
            mr_handle: mr.mr_handle,
        },
    )
    .await
    .unwrap();
    gdma.request::<_, ()>(
        GdmaRequestType::GDMA_DESTROY_PD.0,
        none,
        GdmaDestroyPdReq {
            pd_handle: pd.pd_handle,
        },
    )
    .await
    .unwrap();
}

/// In bare-metal-host mode the device presents itself as a physical function
/// rather than an SR-IOV VF, so the guest exercises the Linux driver's
/// bare-metal-host code paths. Three facts are observable: (1) the PCI device id
/// is `1414:00b9` (the PF id `mana_is_pf` keys on); (2) BAR0 exposes the PF
/// register window `mana_gd_init_pf_regs` reads, resolving to the same
/// shared-memory/doorbell regions the VF map exposes; and (3) the
/// device-config response reports `bm_hostmode=1`. The VF register map stays in
/// place, so the HW channel still establishes. Without the feature a VF device
/// reports id `00ba`, leaves the PF window unmapped (reads return `!0`), and
/// reports `bm_hostmode=0`.
#[async_test]
async fn test_gdma_bm_hostmode_pf(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma_bm_hostmode_pf");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let mut device = gdma::GdmaDevice::new_with_config(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
        gdma::BnicConfig {
            bm_hostmode: true,
            ..Default::default()
        },
    );

    // (1) The function advertises the PF PCI id so the guest's `mana_is_pf`
    // takes the bare-metal-host path.
    let mut vendor_device = 0;
    device.pci_cfg_read(0, &mut vendor_device).unwrap();
    assert_eq!(
        vendor_device,
        (gdma_defs::PF_DEVICE_ID as u32) << 16 | gdma_defs::VENDOR_ID as u32
    );

    // bm_hostmode does not expose a PCI SR-IOV extended capability (that is
    // specific to the pf_caps client); extended config space reads back empty.
    let mut sriov_header = 0;
    device.pci_cfg_read(0x100, &mut sriov_header).unwrap();
    assert_eq!(sriov_header, 0);

    let dma_client = mem.dma_client();
    let device = EmulatedDevice::new(device, msi_conn, dma_client);

    // (2) Read the PF BAR0 register window the driver consumes. The driver
    // computes `db_page_base = bar0 + db_page_off` and
    // `shm_base = bar0 + sriov_base_off + sriov_shm_off`, so these resolve to
    // the doorbell page (4096) and the shared-memory window (40) respectively.
    let mut regs = device.clone();
    let bar0 = regs.map_bar(0).unwrap();
    assert_eq!(bar0.read_u32(0xD0), 4096); // GDMA_PF_REG_DB_PAGE_SIZE
    assert_eq!(bar0.read_u64(0xC8), 4096); // GDMA_PF_REG_DB_PAGE_OFF
    assert_eq!(bar0.read_u64(0x108), 0); // GDMA_SRIOV_REG_CFG_BASE_OFF
    assert_eq!(bar0.read_u64(0x70), 40); // sriov base + GDMA_PF_REG_SHM_OFF

    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();
    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();
    gdma.test_eq().await.unwrap();
    gdma.verify_vf_driver_version().await.unwrap();
    let dev_id = gdma
        .list_devices()
        .await
        .unwrap()
        .iter()
        .copied()
        .find(|dev_id| dev_id.ty == GdmaDevType::GDMA_DEVICE_MANA)
        .unwrap();

    // (3) The device-config response carries `bm_hostmode=1`.
    gdma.register_device(dev_id).await.unwrap();
    let mut bnic = BnicDriver::new(&mut gdma, dev_id);
    let dev_config = bnic.query_dev_config().await.unwrap();
    assert_eq!(dev_config.bm_hostmode, 1);
}

/// With `pf_caps` set, the device presents the PF PCI id, an SR-IOV extended
/// capability, and a true-PF BAR0 register surface: a region-descriptor table at
/// the base of BAR0 that locates the capability, doorbell, and SR-IOV regions. A
/// true-PF client validates that every advertised region resolves inside BAR0
/// (`base_offset + size <= bar_len`) and follows the SR-IOV zone's shared-memory
/// descriptor to the SMC window. This walks that structure: it asserts the
/// version, that each populated region is in-bounds, that the SMC window is
/// reachable and correctly sized, that the capability zone reports the queue
/// maxima and fixed limits, and that unimplemented regions advertise size 0.
///
/// Unlike the VF tests, this does NOT bring up the HW channel through the
/// in-tree (VF) `GdmaDriver`: the descriptor table shadows the VF register map,
/// so the true-PF surface is validated structurally. HW-channel bring-up
/// coverage lives in the VF (`test_gdma`) and `bm_hostmode` tests.
#[async_test]
async fn test_gdma_pf_caps_registers(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma_pf_caps_registers");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let mut device = gdma::GdmaDevice::new_with_config(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
        gdma::BnicConfig {
            pf_caps: true,
            ..Default::default()
        },
    );

    // (1) pf_caps presents the PF PCI id so a PF bus driver binds.
    let mut vendor_device = 0;
    device.pci_cfg_read(0, &mut vendor_device).unwrap();
    assert_eq!(
        vendor_device,
        (gdma_defs::PF_DEVICE_ID as u32) << 16 | gdma_defs::VENDOR_ID as u32
    );

    // (1b) pf_caps exposes an SR-IOV extended capability advertising zero virtual
    // functions, which a PF client requires before it will start.
    let mut sriov_header = 0;
    device.pci_cfg_read(0x100, &mut sriov_header).unwrap();
    assert_eq!(sriov_header & 0xffff, 0x0010); // SR-IOV extended capability id
    assert_eq!((sriov_header >> 16) & 0xf, 1); // capability version
    let mut sriov_vfs = 0;
    device.pci_cfg_read(0x10c, &mut sriov_vfs).unwrap();
    assert_eq!(sriov_vfs, 0); // initial + total VFs both zero

    let dma_client = mem.dma_client();
    let device = EmulatedDevice::new(device, msi_conn, dma_client);
    let mut regs = device.clone();
    let bar0 = regs.map_bar(0).unwrap();

    const BAR0_LEN: u64 = 8192;
    // A region descriptor is a { u64 base_offset, u32 size } pair; the client
    // requires base_offset + size <= bar_len for every advertised region.
    let in_bounds = |off: u64, size: u64| off + size <= BAR0_LEN;
    let region = |off_at: usize, sz_at: usize| {
        let off = bar0.read_u64(off_at);
        let size = bar0.read_u32(sz_at) as u64;
        (off, size)
    };

    // (2) Version: the major version (high byte) must be a supported value.
    let version = bar0.read_u32(0x00);
    assert_eq!((version >> 24) & 0xff, 2); // major version (emulated generation)

    // (3) The capability, doorbell, and SR-IOV regions resolve inside BAR0.
    let (cap_off, cap_size) = region(0x48, 0x50);
    assert!(in_bounds(cap_off, cap_size));
    assert_eq!(cap_size, 0x68); // capability zone size
    let (db_off, db_size) = region(0xC8, 0xD0);
    assert!(in_bounds(db_off, db_size));
    assert_eq!(db_off, 4096); // doorbell zone offset
    assert_eq!(db_size, 4096); // doorbell zone size
    let (sriov_off, sriov_size) = region(0x108, 0x110);
    assert!(in_bounds(sriov_off, sriov_size));

    // (4) The SMC window is reachable: the SR-IOV zone's shared-memory descriptor
    // (relative to the zone base) resolves in-bounds and is sized for the header.
    let shmem_rel = bar0.read_u64((sriov_off + 0x70) as usize);
    let shmem_size = bar0.read_u32((sriov_off + 0x78) as usize) as u64;
    let shmem_abs = sriov_off + shmem_rel;
    assert!(in_bounds(shmem_abs, shmem_size));
    assert_eq!(shmem_size, 32); // shared-memory window size

    // (5) The capability zone reports the device's queue maxima (sourced from the
    // live queue allocation) and fixed limits. Field offsets are relative to the
    // discovered capability-zone base.
    let cap = |field: u64| bar0.read_u32((cap_off + field) as usize);
    assert_eq!(cap(0x00), 0); // hw_capabilities
    assert_eq!(cap(0x04), 0); // feature_flags
    assert_eq!(cap(0x08), 64); // max_send_queues
    assert_eq!(cap(0x10), 64); // max_receive_queues
    assert_eq!(cap(0x18), 128); // max_completion_queues
    assert_eq!(cap(0x20), 64); // max_event_queues
    assert_eq!(cap(0x28), 0); // max_cq_moderation_contexts
    assert_eq!(cap(0x30), 0); // num_virtual_functions
    assert_eq!(cap(0x38), 1); // max_doorbell_pages
    assert_eq!(cap(0x40), 0); // max_moderated_completion_queues
    assert_eq!(cap(0x48), 1514); // max_tx_payload_len
    assert_eq!(cap(0x50), 1); // num_physical_functions
    assert_eq!(cap(0x58), 64); // max_msix_entries
    assert_eq!(cap(0x60), 64); // pf_max_msix_entries

    // (6) Unimplemented regions advertise size 0 ("absent").
    assert_eq!(bar0.read_u32(0x70), 0); // send wq context size
    assert_eq!(bar0.read_u32(0xA0), 0); // event queue context size
    assert_eq!(bar0.read_u32(0x100), 0); // address-translation context size
}

/// Before it establishes the HW channel, the host-management client polls the
/// device for readiness over the shared-memory channel: it writes a single
/// header word -- message type "host management ready", request direction --
/// to the last word of the SMC aperture, takes possession, and waits for the
/// device to answer. The device must acknowledge: echo the message type, mark
/// the word a successful response, and hand possession back. A device that
/// rejects this query as an unknown request strands the client before bring-up
/// (the symptom that motivated handling it). This drives that handshake end to
/// end over the relocated (`pf_caps`) shared-memory window.
#[async_test]
async fn test_gdma_pf_caps_host_mgmt_ready(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma_pf_caps_host_mgmt_ready");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new_with_config(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
        gdma::BnicConfig {
            pf_caps: true,
            ..Default::default()
        },
    );

    let dma_client = mem.dma_client();
    let device = EmulatedDevice::new(device, msi_conn, dma_client);
    let mut regs = device.clone();
    let bar0 = regs.map_bar(0).unwrap();

    // Discover the shared-memory window through the descriptor table: the
    // SR-IOV region descriptor, then its shared-memory sub-descriptor.
    let sriov_off = bar0.read_u64(0x108);
    let shmem_rel = bar0.read_u64((sriov_off + 0x70) as usize);
    let shmem_size = bar0.read_u32((sriov_off + 0x78) as usize) as u64;
    let shmem_abs = (sriov_off + shmem_rel) as usize;
    // The protocol header occupies the last word of the SMC aperture.
    let header_off = shmem_abs + shmem_size as usize - 4;

    // Issue the readiness query. Writing the header word is what hands the
    // device possession and triggers it to service the request.
    let request = SmcProtoHdr::new()
        .with_msg_type(SmcMessageType::SMC_MSG_TYPE_HOST_MGMT_READY.0)
        .with_msg_version(gdma_defs::SMC_MSG_TYPE_HOST_MGMT_READY_VERSION);
    assert!(!request.is_response()); // sanity: a request, not a response
    bar0.write_u32(header_off, u32::from(request));

    // The device must answer in place: same message type, marked a response,
    // success status, with a version no newer than requested and possession
    // handed back to the guest.
    let response = SmcProtoHdr::from(bar0.read_u32(header_off));
    assert_eq!(
        response.msg_type(),
        SmcMessageType::SMC_MSG_TYPE_HOST_MGMT_READY.0
    );
    assert!(response.is_response());
    assert_eq!(
        response.msg_version(),
        gdma_defs::SMC_MSG_TYPE_HOST_MGMT_READY_VERSION
    );
    assert_eq!(response.status(), 0); // success
    assert!(!response.owner_is_pf()); // possession returned to the guest
}

/// A vport must support more than one receive work-queue object so the guest
/// can build an RSS indirection table that steers traffic across multiple
/// queues. Each object must be addressed by a distinct `wq_obj` handle so it
/// can be referenced and destroyed independently. This exercises creating two
/// RX objects on one vport and destroying both by handle.
#[async_test]
async fn test_gdma_multiple_wq_objs(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma_multiple_wq_objs");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let dma_client = mem.dma_client();
    let device = EmulatedDevice::new(device, msi_conn, dma_client);
    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();
    gdma.test_eq().await.unwrap();
    gdma.verify_vf_driver_version().await.unwrap();
    let dev_id = gdma
        .list_devices()
        .await
        .unwrap()
        .iter()
        .copied()
        .find(|dev_id| dev_id.ty == GdmaDevType::GDMA_DEVICE_MANA)
        .unwrap();

    let device_props = gdma.register_device(dev_id).await.unwrap();
    let mut bnic = BnicDriver::new(&mut gdma, dev_id);
    let port_config = bnic.query_vport_config(0).await.unwrap();
    let vport = port_config.vport;

    let buffer = Arc::new(
        gdma.device()
            .dma_client()
            .allocate_dma_buffer(0x6000)
            .unwrap(),
    );
    let mut arena = ResourceArena::new();
    let eq_gdma_region = gdma
        .create_dma_region(&mut arena, dev_id, buffer.subblock(0, PAGE_SIZE))
        .await
        .unwrap();
    let (eq_id, _) = gdma
        .create_eq(
            &mut arena,
            dev_id,
            eq_gdma_region,
            PAGE_SIZE as u32,
            device_props.pdid,
            device_props.db_id,
            0,
        )
        .await
        .unwrap();

    // Create two receive work-queue objects on the same vport.
    let mut wq_objs = Vec::new();
    for i in 0..2 {
        let wq_region = gdma
            .create_dma_region(
                &mut arena,
                dev_id,
                buffer.subblock((1 + i * 2) * PAGE_SIZE, PAGE_SIZE),
            )
            .await
            .unwrap();
        let cq_region = gdma
            .create_dma_region(
                &mut arena,
                dev_id,
                buffer.subblock((2 + i * 2) * PAGE_SIZE, PAGE_SIZE),
            )
            .await
            .unwrap();
        let mut bnic = BnicDriver::new(&mut gdma, dev_id);
        let resp = bnic
            .create_wq_obj(
                &mut arena,
                vport,
                GdmaQueueType::GDMA_RQ,
                &WqConfig {
                    wq_gdma_region: wq_region,
                    cq_gdma_region: cq_region,
                    wq_size: PAGE_SIZE as u32,
                    cq_size: PAGE_SIZE as u32,
                    cq_moderation_ctx_id: 0,
                    eq_id,
                },
            )
            .await
            .unwrap();
        wq_objs.push(resp.wq_obj);
    }

    // The two receive objects must have distinct handles.
    assert_ne!(
        wq_objs[0], wq_objs[1],
        "receive work-queue objects must have distinct handles"
    );

    // Tearing the arena down destroys both objects by handle, which only
    // succeeds if each handle resolves to its own queue.
    arena.destroy(&mut gdma).await;
}

/// The Linux driver fences each receive queue during RSS (re)configuration and
/// on vport teardown: it sends `MANA_FENCE_RQ` and then blocks until a
/// `CQE_RX_OBJECT_FENCE` completion lands on that queue's CQ (`rxq->fence_event`
/// in mana_en.c). The device must both acknowledge the command and post the
/// fence completion; otherwise the driver stalls for its full timeout and falls
/// back to a blind sleep. This creates one receive object, fences it, and
/// asserts the fence CQE appears on its completion queue.
#[async_test]
async fn test_gdma_fence_rq(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma_fence_rq");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let dma_client = mem.dma_client();
    let device = EmulatedDevice::new(device, msi_conn, dma_client);
    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();
    gdma.test_eq().await.unwrap();
    gdma.verify_vf_driver_version().await.unwrap();
    let dev_id = gdma
        .list_devices()
        .await
        .unwrap()
        .iter()
        .copied()
        .find(|dev_id| dev_id.ty == GdmaDevType::GDMA_DEVICE_MANA)
        .unwrap();

    let device_props = gdma.register_device(dev_id).await.unwrap();
    let mut bnic = BnicDriver::new(&mut gdma, dev_id);
    let port_config = bnic.query_vport_config(0).await.unwrap();
    let vport = port_config.vport;

    let buffer = Arc::new(
        gdma.device()
            .dma_client()
            .allocate_dma_buffer(0x3000)
            .unwrap(),
    );
    let mut arena = ResourceArena::new();
    let eq_gdma_region = gdma
        .create_dma_region(&mut arena, dev_id, buffer.subblock(0, PAGE_SIZE))
        .await
        .unwrap();
    let (eq_id, _) = gdma
        .create_eq(
            &mut arena,
            dev_id,
            eq_gdma_region,
            PAGE_SIZE as u32,
            device_props.pdid,
            device_props.db_id,
            0,
        )
        .await
        .unwrap();

    let wq_region = gdma
        .create_dma_region(&mut arena, dev_id, buffer.subblock(PAGE_SIZE, PAGE_SIZE))
        .await
        .unwrap();
    let cq_region = gdma
        .create_dma_region(&mut arena, dev_id, buffer.subblock(2 * PAGE_SIZE, PAGE_SIZE))
        .await
        .unwrap();
    let mut bnic = BnicDriver::new(&mut gdma, dev_id);
    let resp = bnic
        .create_wq_obj(
            &mut arena,
            vport,
            GdmaQueueType::GDMA_RQ,
            &WqConfig {
                wq_gdma_region: wq_region,
                cq_gdma_region: cq_region,
                wq_size: PAGE_SIZE as u32,
                cq_size: PAGE_SIZE as u32,
                cq_moderation_ctx_id: 0,
                eq_id,
            },
        )
        .await
        .unwrap();

    // Fence the receive queue. The command itself must be accepted...
    bnic.fence_rq(resp.wq_obj).await.unwrap();

    // ...and a CQE_RX_OBJECT_FENCE must be posted on the object's CQ so the
    // driver's fence_event completes instead of timing out. Reading it through a
    // real Cq honors the owner bit, so a missing post yields no CQE at all.
    let mut cq = Cq::new_cq(
        buffer.subblock(2 * PAGE_SIZE, PAGE_SIZE),
        DoorbellPage::null(),
        resp.cq_id,
    );
    let cqe = cq.pop().expect("fence CQE must be posted on the rq's cq");
    let hdr = ManaCqeHeader::read_from_prefix(&cqe.data).unwrap().0;
    assert_eq!(
        hdr.cqe_type(),
        CQE_RX_OBJECT_FENCE,
        "fence completion must carry CQE_RX_OBJECT_FENCE"
    );

    arena.destroy(&mut gdma).await;
}

#[async_test]
async fn test_gdma_save_restore(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let dma_client = mem.dma_client();

    let device = EmulatedDevice::new(device, msi_conn, dma_client);
    let cloned_device = device.clone();

    let dma_client = device.dma_client();
    let gdma_buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let saved_state = {
        let mut gdma = GdmaDriver::new(&driver, device, 1, Some(gdma_buffer.clone()))
            .await
            .unwrap();

        gdma.test_eq().await.unwrap();
        gdma.verify_vf_driver_version().await.unwrap();
        gdma.save().await.unwrap()
    };

    let mut new_gdma = GdmaDriver::restore(saved_state, cloned_device, gdma_buffer)
        .await
        .unwrap();

    // Validate that the new driver still works after restoration.
    new_gdma.test_eq().await.unwrap();
}

#[async_test]
async fn test_adapter_link_speed_default(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_adapter_link_speed_default");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let dma_client = mem.dma_client();
    let device = EmulatedDevice::new(device, msi_conn, dma_client);
    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();

    // Register the MANA device so we can issue BNIC requests.
    gdma.verify_vf_driver_version().await.unwrap();
    let dev_id = gdma
        .list_devices()
        .await
        .unwrap()
        .iter()
        .copied()
        .find(|dev_id| dev_id.ty == GdmaDevType::GDMA_DEVICE_MANA)
        .unwrap();
    gdma.register_device(dev_id).await.unwrap();

    // The default BnicConfig has adapter_link_speed_mbps = 0, so
    // query_dev_config should return 0.
    let mut bnic = BnicDriver::new(&mut gdma, dev_id);
    let dev_config = bnic.query_dev_config().await.unwrap();

    assert_eq!(
        dev_config.adapter_link_speed_mbps, 0,
        "adapter_link_speed_mbps should be 0 with default BnicConfig"
    );
}

/// Configures the emulated GDMA device with a specific non-zero link speed
/// via `BnicConfig`, then verifies that `query_dev_config` returns that speed
/// and `link_speed_bps()` converts it correctly.
async fn verify_adapter_link_speed_expected(driver: DefaultDriver, link_speed_mbps: u32) {
    let mem = DeviceTestMemory::new(128, false, "test_adapter_link_speed_expected");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new_with_config(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
        gdma::BnicConfig {
            adapter_link_speed_mbps: link_speed_mbps,
            ..Default::default()
        },
    );
    let dma_client = mem.dma_client();
    let device = EmulatedDevice::new(device, msi_conn, dma_client);
    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();

    gdma.verify_vf_driver_version().await.unwrap();
    let dev_id = gdma
        .list_devices()
        .await
        .unwrap()
        .iter()
        .copied()
        .find(|dev_id| dev_id.ty == GdmaDevType::GDMA_DEVICE_MANA)
        .unwrap();
    gdma.register_device(dev_id).await.unwrap();

    // The emulator now returns the configured link speed directly.
    let mut bnic = BnicDriver::new(&mut gdma, dev_id);
    let dev_config = bnic.query_dev_config().await.unwrap();

    assert_eq!(
        dev_config.adapter_link_speed_mbps, link_speed_mbps,
        "adapter_link_speed_mbps should match the configured value"
    );
    assert_eq!(
        dev_config.link_speed_bps(),
        link_speed_mbps as u64 * 1000 * 1000,
        "link_speed_bps() should reflect the configured adapter_link_speed_mbps"
    );
}

/// Verifies that configuring the emulated GDMA device with
/// `adapter_link_speed_mbps = 400,000` (400 Gbps) yields 400 Gbps from
/// `link_speed_bps()` — not zero and not the 200 Gbps fallback.
#[async_test]
async fn test_adapter_link_speed_expected(driver: DefaultDriver) {
    verify_adapter_link_speed_expected(driver, 400 * 1000).await;
}

#[async_test]
async fn test_gdma_reset_request(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let dma_client = mem.dma_client();
    let device = EmulatedDevice::new(device, msi_conn, dma_client);
    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();

    assert_eq!(
        gdma.get_reset_request_pending(),
        None,
        "reset_request_pending should be unset before reset request"
    );

    // Get the device ID while HWC is still alive (needed for deregister later).
    let dev_id = gdma
        .list_devices()
        .await
        .unwrap()
        .iter()
        .copied()
        .find(|dev_id| dev_id.ty == GdmaDevType::GDMA_DEVICE_MANA)
        .unwrap();

    // Trigger the reset event (EQE 135).
    gdma.generate_reset_request_eqe(false).await.unwrap();

    assert_eq!(
        gdma.get_reset_request_pending(),
        Some(false),
        "reset_request_pending should capture revoke_vtl0_vf=false"
    );

    // Deregister should fail immediately because reset_request_pending is set.
    let deregister_result = gdma.deregister_device(dev_id).await;
    let err = deregister_result.expect_err("deregister_device should fail after EQE 135");
    let err_msg = format!("{err:#}");
    assert!(
        err_msg.contains("HWC reset request pending"),
        "unexpected error: {err_msg}"
    );
    assert_eq!(
        gdma.get_reset_request_pending(),
        Some(false),
        "reset_request_pending should remain revoke_vtl0_vf=false after deregister_device"
    );
}

#[async_test]
async fn test_gdma_reset_request_with_revoke(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let dma_client = mem.dma_client();
    let device = EmulatedDevice::new(device, msi_conn, dma_client);
    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();

    assert_eq!(
        gdma.get_reset_request_pending(),
        None,
        "reset_request_pending should be unset before reset request"
    );

    // Get the device ID while HWC is still alive (needed for deregister later).
    let dev_id = gdma
        .list_devices()
        .await
        .unwrap()
        .iter()
        .copied()
        .find(|dev_id| dev_id.ty == GdmaDevType::GDMA_DEVICE_MANA)
        .unwrap();

    // Trigger the reset event (EQE 135) with vtl0 VF revoke.
    gdma.generate_reset_request_eqe(true).await.unwrap();

    assert_eq!(
        gdma.get_reset_request_pending(),
        Some(true),
        "reset_request_pending should capture revoke_vtl0_vf=true"
    );

    // Deregister should fail immediately because reset_request_pending is set.
    let deregister_result = gdma.deregister_device(dev_id).await;
    let err = deregister_result.expect_err("deregister_device should fail after EQE 135");
    let err_msg = format!("{err:#}");
    assert!(
        err_msg.contains("HWC reset request pending"),
        "unexpected error: {err_msg}"
    );
    assert_eq!(
        gdma.get_reset_request_pending(),
        Some(true),
        "reset_request_pending should remain revoke_vtl0_vf=true after deregister_device"
    );
}

/// Resets the emulated device through its [`ChangeDeviceState`] implementation,
/// modelling the reset the host performs on a VM reset or function-level reset.
#[expect(
    clippy::await_holding_lock,
    reason = "the test executor is single-threaded and GdmaDevice::reset does not re-enter the device lock"
)]
async fn reset_emulated_gdma(device: &Arc<Mutex<gdma::GdmaDevice>>) {
    device.lock().reset().await;
}

/// Drops `gdma` without sending DESTROY_HWC, leaving the device's HW channel
/// established. This models a guest that went away (for example an ungraceful
/// reboot) without tearing the channel down. `save()` is used because it is the
/// supported way to suppress the DESTROY_HWC that [`GdmaDriver`]'s `Drop`
/// otherwise sends; the saved state is intentionally discarded. Dropping the
/// driver afterwards releases its handle to the shared device so the test
/// executor can still shut down.
async fn abandon_channel<T: DeviceBacking>(mut gdma: GdmaDriver<T>) {
    gdma.save()
        .await
        .expect("save suppresses DESTROY_HWC on drop");
    drop(gdma);
}

/// Establishing the HW channel a second time without an intervening teardown
/// must be rejected: the device reports that a channel is already active. This
/// is the failure a guest hits after an ungraceful reboot when the device does
/// not reset its state, and it is the precondition that
/// [`test_gdma_reset_allows_reestablish`] shows the reset path clears.
#[async_test]
async fn test_gdma_reestablish_rejected_while_active(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma_reestablish_rejected");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let device_inner = device.device().clone();
    let device_again = device.clone();

    let dma_client = device.dma_client();
    let buffer0 = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();
    let buffer1 = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let gdma = GdmaDriver::new(&driver, device, 1, Some(buffer0))
        .await
        .unwrap();

    // The guest goes away without issuing DESTROY_HWC, leaving the channel
    // established on the device.
    abandon_channel(gdma).await;

    let result = GdmaDriver::new(&driver, device_again, 1, Some(buffer1)).await;
    assert!(
        result.is_err(),
        "re-establishing the HW channel should fail while one is still active"
    );

    // Reset tears down the still-active channel so the lingering HW channel task
    // stops and the test executor can shut down cleanly.
    reset_emulated_gdma(&device_inner).await;
}

/// After the device is reset (as the host does on VM reset / FLR), the guest can
/// re-establish the HW channel even when the previous channel was never torn
/// down gracefully.
#[async_test]
async fn test_gdma_reset_allows_reestablish(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma_reset_reestablish");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let device_inner = device.device().clone();
    let device_again = device.clone();

    let dma_client = device.dma_client();
    let buffer0 = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();
    let buffer1 = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let gdma = GdmaDriver::new(&driver, device, 1, Some(buffer0))
        .await
        .unwrap();

    // The guest goes away (e.g. an ungraceful reboot) without issuing
    // DESTROY_HWC, leaving the channel established on the device.
    abandon_channel(gdma).await;

    // The host resets the device, tearing down the stale channel.
    reset_emulated_gdma(&device_inner).await;

    // The guest can now re-establish the channel cleanly.
    let mut gdma = GdmaDriver::new(&driver, device_again, 1, Some(buffer1))
        .await
        .unwrap();
    gdma.test_eq().await.unwrap();
}

/// Tearing down the HW channel must follow the SMC shared-memory possession
/// handshake. The driver writes the `DESTROY_HWC` request header *without*
/// setting the possession bit (BIT 31); the device is responsible for taking
/// possession so the guest keeps polling while the asynchronous HWC teardown
/// runs, then releasing it with a well-formed response. Before this was
/// modelled, the asynchronous `DESTROY_HWC` path left the bare request header in
/// shared memory (possession clear, direction=request), so the guest read the
/// request back as if it were the response and logged
/// `Wrong SMC response 0x2, type=2, ver=0` / `Error when tearing down HWC: -71`
/// at shutdown.
///
/// This drives the teardown through a second handle to the emulated device's
/// BAR0 (the way the guest's shared-memory writes reach the device) so the
/// response header can be inspected directly, which the driver's own `Drop`
/// only logs.
#[async_test]
async fn test_gdma_destroy_hwc_possession_handshake(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma_destroy_hwc_possession");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    // A second handle to the same emulated device (shares the inner
    // `Arc<Mutex<GdmaDevice>>`) used to drive the guest-side shared-memory
    // protocol directly while `GdmaDriver` owns the established channel.
    let mut probe = device.clone();

    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    // ESTABLISH_HWC completes synchronously, so the device hands shared-memory
    // possession back to the guest as part of bring-up.
    let gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();

    // Locate the SMC header exactly as the driver does: the final dword of the
    // shared region at `vf_gdma_sriov_shared_reg_start + 28` in BAR0.
    let bar0 = probe.map_bar(0).unwrap();
    let mut regmap = RegMap::new_zeroed();
    for i in 0..size_of_val(&regmap) / 4 {
        regmap.as_mut_bytes()[i * 4..(i + 1) * 4]
            .copy_from_slice(&bar0.read_u32(i * 4).to_ne_bytes());
    }
    let hdr_off = regmap.vf_gdma_sriov_shared_reg_start as usize + 28;

    // After ESTABLISH_HWC the guest owns shared memory (possession bit clear).
    let raw = bar0.read_u32(hdr_off);
    assert!(
        !SmcProtoHdr::from(raw).owner_is_pf(),
        "guest should own shared memory after ESTABLISH_HWC, header={raw:#010x}",
    );

    // Issue DESTROY_HWC the way the driver's teardown does: write the request
    // header without setting the possession bit.
    let req = SmcProtoHdr::new()
        .with_msg_type(SmcMessageType::SMC_MSG_TYPE_DESTROY_HWC.0)
        .with_msg_version(SMC_MSG_TYPE_DESTROY_HWC_VERSION);
    bar0.write_u32(hdr_off, u32::from(req));

    // Regression assertion: the device must take possession on the request
    // write. There is no await between the write and this read, so the
    // asynchronous HWC stop cannot have progressed yet; the header therefore
    // still reflects the in-flight request with possession held by the PF.
    // Without the possession handshake the device left the bare request header
    // (possession clear, direction=request) and the guest read it as a
    // malformed response.
    let raw = bar0.read_u32(hdr_off);
    let hdr = SmcProtoHdr::from(raw);
    assert!(
        hdr.owner_is_pf(),
        "device must take shared-memory possession on the DESTROY_HWC request, header={raw:#010x}",
    );
    assert!(
        !hdr.is_response(),
        "DESTROY_HWC is still pending; the response bit must not be set yet, header={raw:#010x}",
    );

    // Drive the asynchronous teardown to completion. Each shared-memory read
    // polls whether the HWC task has stopped; yielding lets that task run.
    let mut timer = pal_async::timer::PolledTimer::new(&driver);
    let mut raw = bar0.read_u32(hdr_off);
    for _ in 0..1000 {
        if !SmcProtoHdr::from(raw).owner_is_pf() {
            break;
        }
        timer.sleep(std::time::Duration::from_millis(1)).await;
        raw = bar0.read_u32(hdr_off);
    }

    // The completed response hands possession back with a well-formed reply the
    // guest accepts: direction=response, the original message type, status=0.
    let hdr = SmcProtoHdr::from(raw);
    assert!(
        !hdr.owner_is_pf(),
        "device never released possession after DESTROY_HWC, header={raw:#010x}",
    );
    assert!(
        hdr.is_response(),
        "DESTROY_HWC response bit not set, header={raw:#010x}",
    );
    assert_eq!(
        hdr.msg_type(),
        SmcMessageType::SMC_MSG_TYPE_DESTROY_HWC.0,
        "wrong DESTROY_HWC response message type, header={raw:#010x}",
    );
    assert_eq!(
        hdr.status(),
        0,
        "DESTROY_HWC reported failure, header={raw:#010x}",
    );

    // The HW channel is already torn down. Suppress the driver's own DESTROY_HWC
    // (it would race a redundant second teardown) and drop it so the executor
    // shuts down cleanly.
    abandon_channel(gdma).await;
}

/// The driver allocates DMA regions for queue memory and, when a region is not
/// consumed by a queue, tears it down with `GDMA_DESTROY_DMA_REGION`. The device
/// must service that command (acknowledge it and forget the region) rather than
/// rejecting it; otherwise the driver logs a teardown error on every such
/// region. This exercises the create-then-destroy round trip end to end.
#[async_test]
async fn test_gdma_destroy_dma_region(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma_destroy_dma_region");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();
    gdma.test_eq().await.unwrap();
    gdma.verify_vf_driver_version().await.unwrap();
    let dev_id = gdma
        .list_devices()
        .await
        .unwrap()
        .iter()
        .copied()
        .find(|dev_id| dev_id.ty == GdmaDevType::GDMA_DEVICE_MANA)
        .unwrap();
    gdma.register_device(dev_id).await.unwrap();

    let region_buffer = Arc::new(
        gdma.device()
            .dma_client()
            .allocate_dma_buffer(PAGE_SIZE)
            .unwrap(),
    );
    let mut arena = ResourceArena::new();
    let gdma_region = gdma
        .create_dma_region(&mut arena, dev_id, region_buffer.subblock(0, PAGE_SIZE))
        .await
        .unwrap();

    // The device must accept the teardown of a region it created.
    gdma.destroy_dma_region(dev_id, gdma_region).await.unwrap();

    // The region is now owned by neither side; tell the arena so it does not
    // attempt to destroy it again, then drop its remaining (host) resources.
    arena.take_dma_region(gdma_region);
    arena.destroy(&mut gdma).await;
}

/// A DMA region whose page list is too large for one HW channel message is
/// delivered as a `GDMA_CREATE_DMA_REGION` carrying the first page(s) plus one
/// or more `GDMA_DMA_REGION_ADD_PAGES` messages supplying the rest. The device
/// must hold the region incomplete until every page has arrived, then expose it.
/// Before ADD_PAGES was handled the create itself was rejected ("large regions
/// not supported") whenever `page_addr_list_len < page_count`, so a split page
/// list could never be assembled.
#[async_test]
async fn test_gdma_dma_region_add_pages(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma_dma_region_add_pages");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();
    gdma.test_eq().await.unwrap();
    gdma.verify_vf_driver_version().await.unwrap();
    let dev_id = gdma
        .list_devices()
        .await
        .unwrap()
        .iter()
        .copied()
        .find(|dev_id| dev_id.ty == GdmaDevType::GDMA_DEVICE_MANA)
        .unwrap();
    let device_props = gdma.register_device(dev_id).await.unwrap();

    // A two-page region whose pages are delivered across two messages.
    let region_buffer = Arc::new(
        gdma.device()
            .dma_client()
            .allocate_dma_buffer(2 * PAGE_SIZE)
            .unwrap(),
    );
    let pfns = region_buffer.pfns();
    assert_eq!(pfns.len(), 2);

    // CREATE carries only the first page (page_addr_list_len=1 < page_count=2),
    // so the device must hold the region incomplete.
    #[repr(C)]
    #[derive(IntoBytes, Immutable, KnownLayout)]
    struct CreateReq {
        req: GdmaCreateDmaRegionReq,
        pages: [u64; 1],
    }
    let create = CreateReq {
        req: GdmaCreateDmaRegionReq {
            length: (2 * PAGE_SIZE) as u64,
            offset_in_page: 0,
            gdma_page_type: GDMA_PAGE_TYPE_4K,
            page_count: 2,
            page_addr_list_len: 1,
        },
        pages: [pfns[0] * PAGE_SIZE64],
    };
    let resp: GdmaCreateDmaRegionResp = gdma
        .request(GdmaRequestType::GDMA_CREATE_DMA_REGION.0, dev_id, create)
        .await
        .unwrap();
    let gdma_region = resp.gdma_region;

    // ADD_PAGES supplies the remaining page, completing the region.
    #[repr(C)]
    #[derive(IntoBytes, Immutable, KnownLayout)]
    struct AddReq {
        req: GdmaDmaRegionAddPagesReq,
        pages: [u64; 1],
    }
    let add = AddReq {
        req: GdmaDmaRegionAddPagesReq {
            gdma_region,
            page_addr_list_len: 1,
            reserved: 0,
        },
        pages: [pfns[1] * PAGE_SIZE64],
    };
    gdma.request::<_, ()>(GdmaRequestType::GDMA_DMA_REGION_ADD_PAGES.0, dev_id, add)
        .await
        .unwrap();

    // The assembled region must now be usable. Binding it to an EQ exercises the
    // device's region lookup, which validates that the page list is complete and
    // that its length matches the queue size (two pages here).
    let mut arena = ResourceArena::new();
    arena.push(crate::resources::Resource::DmaRegion {
        dev_id,
        gdma_region,
    });
    gdma.create_eq(
        &mut arena,
        dev_id,
        gdma_region,
        (2 * PAGE_SIZE) as u32,
        device_props.pdid,
        device_props.db_id,
        0,
    )
    .await
    .unwrap();

    arena.destroy(&mut gdma).await;
}

/// A physical function frames `GDMA_CREATE_DMA_REGION` by setting the request
/// header's `msg_size` to the request's fixed base size (header plus fixed
/// fields, no page-array trailer) while the work request still carries the full
/// page array, conveying the true length through the work-request length. The
/// device must read the page list using the work-request length, not the
/// header's `msg_size`: bounding the read by `msg_size` truncates the page array
/// and the create fails ("out of range") even though every page is present. A
/// virtual function always sizes the work request to exactly `msg_size`, so the
/// undersized-header path is reachable only from a physical function -- this test
/// reproduces it with `request_version_advertising`.
#[async_test]
async fn test_gdma_create_dma_region_underreported_size(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma_create_dma_region_underreported_size");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();
    gdma.test_eq().await.unwrap();
    gdma.verify_vf_driver_version().await.unwrap();
    let dev_id = gdma
        .list_devices()
        .await
        .unwrap()
        .iter()
        .copied()
        .find(|dev_id| dev_id.ty == GdmaDevType::GDMA_DEVICE_MANA)
        .unwrap();
    let device_props = gdma.register_device(dev_id).await.unwrap();

    // A two-page region whose entire page list rides in the CREATE message, so
    // the region finalizes immediately (page_addr_list_len == page_count).
    let region_buffer = Arc::new(
        gdma.device()
            .dma_client()
            .allocate_dma_buffer(2 * PAGE_SIZE)
            .unwrap(),
    );
    let pfns = region_buffer.pfns();
    assert_eq!(pfns.len(), 2);

    #[repr(C)]
    #[derive(IntoBytes, Immutable, KnownLayout)]
    struct CreateReq {
        req: GdmaCreateDmaRegionReq,
        pages: [u64; 2],
    }
    let create = CreateReq {
        req: GdmaCreateDmaRegionReq {
            length: (2 * PAGE_SIZE) as u64,
            offset_in_page: 0,
            gdma_page_type: GDMA_PAGE_TYPE_4K,
            page_count: 2,
            page_addr_list_len: 2,
        },
        pages: [pfns[0] * PAGE_SIZE64, pfns[1] * PAGE_SIZE64],
    };

    // Advertise only the fixed base size (header + `GdmaCreateDmaRegionReq`, no
    // page array) even though the work request carries the full page list --
    // exactly how a physical function frames this command.
    let advertised_base_size =
        (size_of::<GdmaReqHdr>() + size_of::<GdmaCreateDmaRegionReq>()) as u32;
    let (resp, _): (GdmaCreateDmaRegionResp, u32) = gdma
        .request_version_advertising(
            GdmaRequestType::GDMA_CREATE_DMA_REGION.0,
            GDMA_MESSAGE_V1,
            GdmaRequestType::GDMA_CREATE_DMA_REGION.0,
            GDMA_MESSAGE_V1,
            dev_id,
            create,
            advertised_base_size,
        )
        .await
        .unwrap();
    let gdma_region = resp.gdma_region;

    // The region must be fully assembled despite the undersized header. Binding
    // it to a two-page EQ exercises the device's region lookup, which rejects an
    // incomplete page list or a length that does not match the queue size.
    let mut arena = ResourceArena::new();
    arena.push(crate::resources::Resource::DmaRegion {
        dev_id,
        gdma_region,
    });
    gdma.create_eq(
        &mut arena,
        dev_id,
        gdma_region,
        (2 * PAGE_SIZE) as u32,
        device_props.pdid,
        device_props.db_id,
        0,
    )
    .await
    .unwrap();

    arena.destroy(&mut gdma).await;
}

/// The driver splits a DMA region whose page list does not fit in one HW
/// channel message into a `GDMA_CREATE_DMA_REGION` plus follow-up
/// `GDMA_DMA_REGION_ADD_PAGES` messages, and the device reassembles them into a
/// single usable region. This drives the high-level `create_dma_region` path
/// with a 32-page region (two 16-page messages) and binds the result to an EQ,
/// which the device accepts only once every page has arrived and the region's
/// length matches the queue size. Before the split the driver could describe at
/// most one message's worth of pages.
#[async_test]
async fn test_gdma_large_dma_region_split(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma_large_dma_region_split");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();
    gdma.test_eq().await.unwrap();
    gdma.verify_vf_driver_version().await.unwrap();
    let dev_id = gdma
        .list_devices()
        .await
        .unwrap()
        .iter()
        .copied()
        .find(|dev_id| dev_id.ty == GdmaDevType::GDMA_DEVICE_MANA)
        .unwrap();
    let device_props = gdma.register_device(dev_id).await.unwrap();

    // 32 pages span two 16-page messages and form a power-of-two ring size.
    const REGION_PAGES: usize = 32;
    let region_buffer = gdma
        .device()
        .dma_client()
        .allocate_dma_buffer(REGION_PAGES * PAGE_SIZE)
        .unwrap();

    let mut arena = ResourceArena::new();
    let gdma_region = gdma
        .create_dma_region(&mut arena, dev_id, region_buffer)
        .await
        .unwrap();

    // The reassembled region must be complete and correctly sized: binding it to
    // an EQ exercises the device's region lookup end to end.
    gdma.create_eq(
        &mut arena,
        dev_id,
        gdma_region,
        (REGION_PAGES * PAGE_SIZE) as u32,
        device_props.pdid,
        device_props.db_id,
        0,
    )
    .await
    .unwrap();

    arena.destroy(&mut gdma).await;
}

/// `ethtool -S` drives `MANA_QUERY_STATS`; the device must service it and return
/// a response whose `reported_statistics` mask covers what the driver requested.
/// Before this was handled the command was rejected and stats reporting failed.
#[async_test]
async fn test_gdma_query_stats(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma_query_stats");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();
    gdma.test_eq().await.unwrap();
    gdma.verify_vf_driver_version().await.unwrap();
    let dev_id = gdma
        .list_devices()
        .await
        .unwrap()
        .iter()
        .copied()
        .find(|dev_id| dev_id.ty == GdmaDevType::GDMA_DEVICE_MANA)
        .unwrap();
    gdma.register_device(dev_id).await.unwrap();

    let mut bnic = BnicDriver::new(&mut gdma, dev_id);
    let stats = bnic.query_stats(STATISTICS_FLAGS_ALL).await.unwrap();

    // The device reported every statistic the driver asked for. The emulated
    // datapath has seen no traffic, so the counters themselves are zero.
    assert_eq!(stats.reported_statistics, STATISTICS_FLAGS_ALL);
    assert_eq!(stats.hc_in_octets, 0);
    assert_eq!(stats.hc_out_octets, 0);
}

/// `ethtool -S` also drives `MANA_QUERY_PHY_STAT` (the physical-port counters).
/// The emulated VF has no PHY, so the device must still service the command and
/// return success with zeroed counters, echoing the requested-statistics bitmap.
/// Before this was handled the command was rejected ("unsupported request"),
/// which surfaced as a benign-but-noisy device warning on every stats poll.
#[async_test]
async fn test_gdma_query_phy_stats(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma_query_phy_stats");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();
    gdma.test_eq().await.unwrap();
    gdma.verify_vf_driver_version().await.unwrap();
    let dev_id = gdma
        .list_devices()
        .await
        .unwrap()
        .iter()
        .copied()
        .find(|dev_id| dev_id.ty == GdmaDevType::GDMA_DEVICE_MANA)
        .unwrap();
    gdma.register_device(dev_id).await.unwrap();

    let mut bnic = BnicDriver::new(&mut gdma, dev_id);
    // A non-zero request bitmap proves the device read and echoed the request
    // field (the Linux driver itself sends 0 here, but the echo is the contract).
    let requested = 0x1234_5678_9abc_def0;
    let stats = bnic.query_phy_stats(requested).await.unwrap();

    assert_eq!(stats.reported_statistics, requested);
    assert_eq!(stats.rx_pkt_drop_phy, 0);
    assert_eq!(stats.tx_pkt_drop_phy, 0);
    assert_eq!(stats.pkt_tc_phy, [0; 16]);
    assert_eq!(stats.byte_tc_phy, [0; 16]);
    assert_eq!(stats.pause_tc_phy, [0; 16]);
}

/// A backend endpoint that records the RSS indirection table the device plumbs
/// to it on every `get_queues` call, so a test can prove the device re-resolved
/// and re-applied steering. Datapath behavior is delegated to a `NullEndpoint`.
struct RecordingEndpoint {
    tables: Arc<Mutex<Vec<Vec<u16>>>>,
    inner: NullEndpoint,
}

impl RecordingEndpoint {
    fn new(tables: Arc<Mutex<Vec<Vec<u16>>>>) -> Self {
        Self {
            tables,
            inner: NullEndpoint::new(),
        }
    }
}

impl InspectMut for RecordingEndpoint {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        self.inner.inspect_mut(req);
    }
}

#[async_trait]
impl Endpoint for RecordingEndpoint {
    fn endpoint_type(&self) -> &'static str {
        "resteer-recording"
    }

    async fn get_queues(
        &mut self,
        config: Vec<QueueConfig>,
        rss: Option<&RssConfig<'_>>,
        queues: &mut Vec<Box<dyn Queue>>,
    ) -> anyhow::Result<()> {
        self.tables
            .lock()
            .push(rss.map(|r| r.indirection_table.to_vec()).unwrap_or_default());
        self.inner.get_queues(config, rss, queues).await
    }

    async fn stop(&mut self) {
        self.inner.stop().await;
    }

    fn is_ordered(&self) -> bool {
        true
    }

    fn multiqueue_support(&self) -> MultiQueueSupport {
        MultiQueueSupport {
            max_queues: 16,
            indirection_table_size: 128,
        }
    }
}

/// The Linux driver reconfigures RSS on a *live* vport (ethtool -X /
/// `mana_config_rss` -> `mana_cfg_vport_steering`): it re-sends
/// `MANA_CONFIG_VPORT_RX` with `rx_enable` re-asserted TRUE and `update_indir_tab`
/// set, pushing a new indirection table without bringing the receive path down.
/// The device must re-resolve the new handle-based table and re-plumb it to the
/// backend; before this it only acted on rx_enable transitions, so a steering
/// update on an already-running vport fell through and was silently ignored (the
/// device acked success but the steering never changed). This creates four
/// receive queues, steers with one table, then live-re-steers with the reversed
/// table and asserts the backend saw both resolved tables in order.
#[async_test]
async fn test_gdma_live_rss_resteer(driver: DefaultDriver) {
    const NUM_QUEUES: usize = 4;

    let recorded = Arc::new(Mutex::new(Vec::<Vec<u16>>::new()));
    let mem = DeviceTestMemory::new(128, false, "test_gdma_live_rss_resteer");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(RecordingEndpoint::new(recorded.clone())),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();
    gdma.test_eq().await.unwrap();
    gdma.verify_vf_driver_version().await.unwrap();
    let dev_id = gdma
        .list_devices()
        .await
        .unwrap()
        .iter()
        .copied()
        .find(|dev_id| dev_id.ty == GdmaDevType::GDMA_DEVICE_MANA)
        .unwrap();
    let device_props = gdma.register_device(dev_id).await.unwrap();

    let mut bnic = BnicDriver::new(&mut gdma, dev_id);
    let port_config = bnic.query_vport_config(0).await.unwrap();
    let vport = port_config.vport;

    let buffer = Arc::new(
        gdma.device()
            .dma_client()
            .allocate_dma_buffer((NUM_QUEUES * 4 + 1) * PAGE_SIZE)
            .unwrap(),
    );
    let mut arena = ResourceArena::new();
    let eq_gdma_region = gdma
        .create_dma_region(&mut arena, dev_id, buffer.subblock(0, PAGE_SIZE))
        .await
        .unwrap();
    let (eq_id, _) = gdma
        .create_eq(
            &mut arena,
            dev_id,
            eq_gdma_region,
            PAGE_SIZE as u32,
            device_props.pdid,
            device_props.db_id,
            0,
        )
        .await
        .unwrap();

    // Create NUM_QUEUES receive objects (collecting their handles for the
    // indirection table) and NUM_QUEUES transmit objects, so the device builds
    // one datapath task per queue pair.
    let rx_handles = create_steering_queues(
        &mut gdma, dev_id, vport, eq_id, &mut arena, &buffer, NUM_QUEUES,
    )
    .await;

    // Enable the receive path with an identity-order indirection table, then
    // re-steer the *running* vport with the reversed table. The device resolves
    // each work-queue object handle to its receive queue index before handing
    // the table to the backend, so the backend should observe [0,1,2,3] then
    // [3,2,1,0].
    let table_a: Vec<u64> = rx_handles.clone();
    let table_b: Vec<u64> = rx_handles.iter().rev().copied().collect();
    let mut bnic = BnicDriver::new(&mut gdma, dev_id);
    bnic.config_vport_rx(
        vport,
        &RxConfig {
            rx_enable: Some(true),
            rss_enable: Some(true),
            hash_key: None,
            default_rxobj: None,
            indirection_table: Some(&table_a),
            cqe_coalescing: false,
        },
    )
    .await
    .unwrap();
    bnic.config_vport_rx(
        vport,
        &RxConfig {
            rx_enable: Some(true),
            rss_enable: Some(true),
            hash_key: None,
            default_rxobj: None,
            indirection_table: Some(&table_b),
            cqe_coalescing: false,
        },
    )
    .await
    .unwrap();

    let resolved = recorded.lock().clone();
    assert_eq!(
        resolved,
        vec![vec![0u16, 1, 2, 3], vec![3u16, 2, 1, 0]],
        "live RSS re-steer must re-resolve the indirection table and re-plumb it \
         to the backend (a missing second entry means the update was dropped)"
    );

    arena.destroy(&mut gdma).await;
}

/// Creates `num_queues` receive objects (returning their work-queue object
/// handles in order) followed by `num_queues` transmit objects on `vport`, each
/// backed by a one-page WQ + CQ carved out of `buffer` (page 0 is reserved for
/// the caller's EQ, so `buffer` must be at least `num_queues * 4 + 1` pages). The
/// device assigns every receive object a distinct handle, so an RSS indirection
/// table can name individual queues.
async fn create_steering_queues<T: DeviceBacking>(
    gdma: &mut GdmaDriver<T>,
    dev_id: GdmaDevId,
    vport: u64,
    eq_id: u32,
    arena: &mut ResourceArena,
    buffer: &Arc<MemoryBlock>,
    num_queues: usize,
) -> Vec<u64> {
    let mut rx_handles = Vec::new();
    for i in 0..num_queues {
        let wq_region = gdma
            .create_dma_region(
                arena,
                dev_id,
                buffer.subblock((1 + i * 2) * PAGE_SIZE, PAGE_SIZE),
            )
            .await
            .unwrap();
        let cq_region = gdma
            .create_dma_region(
                arena,
                dev_id,
                buffer.subblock((2 + i * 2) * PAGE_SIZE, PAGE_SIZE),
            )
            .await
            .unwrap();
        let mut bnic = BnicDriver::new(gdma, dev_id);
        let resp = bnic
            .create_wq_obj(
                arena,
                vport,
                GdmaQueueType::GDMA_RQ,
                &WqConfig {
                    wq_gdma_region: wq_region,
                    cq_gdma_region: cq_region,
                    wq_size: PAGE_SIZE as u32,
                    cq_size: PAGE_SIZE as u32,
                    cq_moderation_ctx_id: 0,
                    eq_id,
                },
            )
            .await
            .unwrap();
        rx_handles.push(resp.wq_obj);
    }
    let sq_base = num_queues * 2 + 1;
    for i in 0..num_queues {
        let wq_region = gdma
            .create_dma_region(
                arena,
                dev_id,
                buffer.subblock((sq_base + i * 2) * PAGE_SIZE, PAGE_SIZE),
            )
            .await
            .unwrap();
        let cq_region = gdma
            .create_dma_region(
                arena,
                dev_id,
                buffer.subblock((sq_base + 1 + i * 2) * PAGE_SIZE, PAGE_SIZE),
            )
            .await
            .unwrap();
        let mut bnic = BnicDriver::new(gdma, dev_id);
        bnic.create_wq_obj(
            arena,
            vport,
            GdmaQueueType::GDMA_SQ,
            &WqConfig {
                wq_gdma_region: wq_region,
                cq_gdma_region: cq_region,
                wq_size: PAGE_SIZE as u32,
                cq_size: PAGE_SIZE as u32,
                cq_moderation_ctx_id: 0,
                eq_id,
            },
        )
        .await
        .unwrap();
    }
    rx_handles
}

/// The real Linux driver sends the **V2** steering request
/// (`mana_cfg_rx_steer_req_v2`, GDMA_MESSAGE_V2): it inserts `cqe_coalescing_enable`
/// plus 7 reserved bytes between the fixed request fields and the indirection
/// table, and points `indir_tab_offset` past that 8-byte gap. The device must
/// honor `indir_tab_offset` when reading the table instead of assuming the table
/// is contiguous with the fixed struct; otherwise it reads the table 8 bytes
/// early, every work-queue handle fails to resolve, and `MANA_CONFIG_VPORT_RX`
/// fails with "indirection table references unknown rx queue" -- which the real
/// driver surfaces as `mana_open` failing to configure the RSS table. The Rust
/// `BnicDriver` only speaks the V1 layout (table contiguous with the struct), so
/// this crafts a raw V2 request to exercise the offset path: it builds four
/// receive queues and steers with a reversed table placed at the V2 offset,
/// asserting the backend observes the correctly resolved [3,2,1,0] table.
#[async_test]
async fn test_gdma_rss_v2_indir_offset(driver: DefaultDriver) {
    const NUM_QUEUES: usize = 4;

    let recorded = Arc::new(Mutex::new(Vec::<Vec<u16>>::new()));
    let mem = DeviceTestMemory::new(128, false, "test_gdma_rss_v2_indir_offset");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(RecordingEndpoint::new(recorded.clone())),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();
    gdma.test_eq().await.unwrap();
    gdma.verify_vf_driver_version().await.unwrap();
    let dev_id = gdma
        .list_devices()
        .await
        .unwrap()
        .iter()
        .copied()
        .find(|dev_id| dev_id.ty == GdmaDevType::GDMA_DEVICE_MANA)
        .unwrap();
    let device_props = gdma.register_device(dev_id).await.unwrap();

    let mut bnic = BnicDriver::new(&mut gdma, dev_id);
    let port_config = bnic.query_vport_config(0).await.unwrap();
    let vport = port_config.vport;

    let buffer = Arc::new(
        gdma.device()
            .dma_client()
            .allocate_dma_buffer((NUM_QUEUES * 4 + 1) * PAGE_SIZE)
            .unwrap(),
    );
    let mut arena = ResourceArena::new();
    let eq_gdma_region = gdma
        .create_dma_region(&mut arena, dev_id, buffer.subblock(0, PAGE_SIZE))
        .await
        .unwrap();
    let (eq_id, _) = gdma
        .create_eq(
            &mut arena,
            dev_id,
            eq_gdma_region,
            PAGE_SIZE as u32,
            device_props.pdid,
            device_props.db_id,
            0,
        )
        .await
        .unwrap();

    let rx_handles = create_steering_queues(
        &mut gdma, dev_id, vport, eq_id, &mut arena, &buffer, NUM_QUEUES,
    )
    .await;

    // Craft the V2 steering request by hand: `cqe_coalescing_enable` +
    // `reserved2[7]` sit between the fixed struct and the indirection table, and
    // `indir_tab_offset` points past them. A non-zero `cqe_coalescing_enable`
    // guarantees the 8-byte gap cannot be silently mistaken for a valid (zero)
    // handle were the device to (wrongly) read the table contiguously.
    #[repr(C)]
    #[derive(IntoBytes, Immutable, KnownLayout, FromBytes)]
    struct CfgRxSteerReqV2 {
        fixed: ManaCfgRxSteerReq,
        cqe_coalescing_enable: u8,
        reserved2: [u8; 7],
        indir_tab: [u64; NUM_QUEUES],
    }

    let reversed: Vec<u64> = rx_handles.iter().rev().copied().collect();
    let req = CfgRxSteerReqV2 {
        fixed: ManaCfgRxSteerReq {
            vport,
            num_indir_entries: NUM_QUEUES as u16,
            indir_tab_offset: (size_of::<GdmaReqHdr>() + size_of::<ManaCfgRxSteerReq>() + 8) as u16,
            rx_enable: Tristate::TRUE,
            rss_enable: Tristate::TRUE,
            update_default_rxobj: 0,
            update_hashkey: 0,
            update_indir_tab: 1,
            reserved: 0,
            default_rxobj: 0,
            hashkey: [0; 40],
        },
        cqe_coalescing_enable: 1,
        reserved2: [0; 7],
        indir_tab: reversed.try_into().unwrap(),
    };

    gdma.request::<_, ()>(ManaCommandCode::MANA_CONFIG_VPORT_RX.0, dev_id, req)
        .await
        .expect(
            "V2 MANA_CONFIG_VPORT_RX must succeed once the device honors \
             indir_tab_offset when reading the indirection table",
        );

    let resolved = recorded.lock().clone();
    assert_eq!(
        resolved,
        vec![vec![3u16, 2, 1, 0]],
        "device must read the indirection table at indir_tab_offset (V2 layout); \
         reading it contiguous with the fixed struct mis-resolves every handle"
    );

    arena.destroy(&mut gdma).await;
}

/// Walks the PCI capability list and returns the configuration-space offset of
/// the PCI Express capability (capability ID `0x10`), panicking if it is
/// absent. This is the same discovery the guest's `pcie_has_flr()` performs.
fn find_pci_express_cap(device: &mut gdma::GdmaDevice) -> u16 {
    const CAP_ID_PCI_EXPRESS: u32 = 0x10;
    let mut cap_ptr = 0;
    device.pci_cfg_read(0x34, &mut cap_ptr).unwrap();
    let mut offset = (cap_ptr & 0xff) as u16;
    while offset != 0 {
        let mut header = 0;
        device.pci_cfg_read(offset, &mut header).unwrap();
        if header & 0xff == CAP_ID_PCI_EXPRESS {
            return offset;
        }
        offset = ((header >> 8) & 0xff) as u16;
    }
    panic!("PCI Express capability not advertised");
}

/// A guest-initiated PCIe Function Level Reset (the real Linux driver calls
/// `pcie_flr()` to recover a wedged function in `mana_dealloc_queues`) must
/// reset the device. The emulator advertises the PCI Express capability with
/// FLR support and, when the guest writes the FLR bit in Device Control, routes
/// it to the same teardown as a host reset plus a configuration-space reset.
///
/// The teardown is asynchronous (it stops the HW channel task) but the FLR is
/// triggered from the synchronous config-write path, so it is serviced from
/// `poll_device`. This test establishes the channel, leaves it active (modeling
/// a guest that wedged), triggers FLR, pumps `poll_device` to completion, and
/// asserts the configuration space was reset (memory decode disabled), which is
/// the last step of the teardown and therefore proves the whole path ran.
/// Without the FLR wiring there is no PCI Express capability at all, so the
/// capability walk fails first.
#[async_test]
async fn test_gdma_flr_resets_device(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma_flr_resets_device");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let device_inner = device.device().clone();

    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();

    // The guest wedged with the channel still established (it never issued
    // DESTROY_HWC), like the stuck-TX recovery path that calls pcie_flr().
    abandon_channel(gdma).await;

    let mmio_enabled = Command::new().with_mmio_enabled(true).into_bits() as u32;

    // The device advertises FLR support, and the emulator has memory decode
    // enabled from enumeration.
    let cap = {
        let mut dev = device_inner.lock();
        let cap = find_pci_express_cap(&mut dev);
        let mut device_caps = 0;
        dev.pci_cfg_read(cap + 0x04, &mut device_caps).unwrap();
        assert_ne!(
            device_caps & (1 << 28),
            0,
            "the PCI Express capability must advertise Function Level Reset"
        );
        let mut command = 0;
        dev.pci_cfg_read(0x4, &mut command).unwrap();
        assert_ne!(
            command & mmio_enabled,
            0,
            "memory decode should be enabled before the reset"
        );
        cap
    };

    // The guest initiates FLR by writing the FLR bit (bit 15) in Device Control,
    // at offset 0x08 within the PCI Express capability.
    device_inner
        .lock()
        .pci_cfg_write(cap + 0x08, 1 << 15)
        .unwrap();

    // Drive the asynchronous teardown that the FLR kicked off. The final step
    // resets configuration space, so memory decode going low signals that the
    // whole teardown (HW channel stop, datapath shutdown, config reset) ran.
    poll_fn(|cx| {
        let mut dev = device_inner.lock();
        dev.poll_device(cx);
        let mut command = 0;
        dev.pci_cfg_read(0x4, &mut command).unwrap();
        if command & mmio_enabled == 0 {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
}

/// The device returns a *specific* BNIC command status code on each negative
/// path (the host's `_BNIC_COMMAND_STATUS`), not a single generic failure code.
/// The Linux driver only tests status != 0, but the host's canonical test suite
/// and command traces observe the exact code, so the emulator must report the
/// code real hardware uses for each rejection.
///
/// Fencing a receive queue whose work-queue-object handle was never created is
/// rejected with `BasicNicInvalidWQHandle` (29) -- the code the host returns
/// when the handle lookup fails. (This is deliberately distinct from
/// `BasicNicFenceRQFailed` (5), which the host uses only after a *successful*
/// lookup when the fence operation itself fails -- a path the emulator does not
/// produce.) The driver surfaces the device's status code in its error message,
/// so assert on it.
///
/// A failed command latches the driver into `hwc_failure`, so each negative path
/// is exercised by its own freshly established driver; see the companion
/// `test_gdma_create_wqobj_bad_type_status` for a different command reporting a
/// different, command-appropriate code (proving the codes are per-path rather
/// than a single constant).
#[async_test]
async fn test_gdma_fence_unknown_handle_status(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma_fence_unknown_handle_status");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();
    gdma.test_eq().await.unwrap();
    gdma.verify_vf_driver_version().await.unwrap();
    let dev_id = gdma
        .list_devices()
        .await
        .unwrap()
        .iter()
        .copied()
        .find(|dev_id| dev_id.ty == GdmaDevType::GDMA_DEVICE_MANA)
        .unwrap();
    gdma.register_device(dev_id).await.unwrap();

    // Fence a work-queue-object handle that was never created: the handle lookup
    // fails, so the device must reject the command with InvalidWQHandle (29).
    let err = gdma
        .request::<_, ()>(
            ManaCommandCode::MANA_FENCE_RQ.0,
            dev_id,
            ManaFenceRqReq {
                wq_obj_handle: 0xdead_beef,
            },
        )
        .await
        .expect_err("fencing an unknown rq handle must be rejected");
    assert!(
        err.to_string().contains(&format!(
            "failed with {:#x}",
            bnic_status::INVALID_WQ_HANDLE
        )),
        "fence of an unknown handle must report BasicNicInvalidWQHandle ({:#x}); \
         driver error was: {err:#}",
        bnic_status::INVALID_WQ_HANDLE,
    );
}

/// Companion to `test_gdma_fence_unknown_handle_status`: a *different* negative
/// path reports a *different*, command-appropriate BNIC status code, proving the
/// codes are per-path rather than a single constant. Creating a work-queue
/// object with an unsupported queue type (a completion queue is not a valid work
/// queue) is rejected with `BasicNicStatusUnsupportQueueType` (36).
#[async_test]
async fn test_gdma_create_wqobj_bad_type_status(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma_create_wqobj_bad_type_status");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();
    gdma.test_eq().await.unwrap();
    gdma.verify_vf_driver_version().await.unwrap();
    let dev_id = gdma
        .list_devices()
        .await
        .unwrap()
        .iter()
        .copied()
        .find(|dev_id| dev_id.ty == GdmaDevType::GDMA_DEVICE_MANA)
        .unwrap();
    gdma.register_device(dev_id).await.unwrap();

    let err = gdma
        .request::<_, ()>(
            ManaCommandCode::MANA_CREATE_WQ_OBJ.0,
            dev_id,
            ManaCreateWqobjReq {
                wq_type: GdmaQueueType::GDMA_CQ,
                ..FromZeros::new_zeroed()
            },
        )
        .await
        .expect_err("creating a wq object with an unsupported queue type must be rejected");
    assert!(
        err.to_string().contains(&format!(
            "failed with {:#x}",
            bnic_status::UNSUPPORTED_QUEUE_TYPE
        )),
        "create-wq with an unsupported queue type must report \
         BasicNicStatusUnsupportQueueType ({:#x}); driver error was: {err:#}",
        bnic_status::UNSUPPORTED_QUEUE_TYPE,
    );
}

/// A BNIC command the device does not implement is rejected with the GDMA core
/// `CMD_UNSUPPORTED` status (0xffffffff), NOT a generic non-zero failure code.
/// The distinction is load-bearing: the guest's GDMA client (`hw_channel.c`)
/// maps 0xffffffff to `-EOPNOTSUPP` and tolerates it (logging at most once),
/// whereas any other non-zero status is a hard `-EPROTO` it logs on every
/// occurrence -- the noisy "Command 0x... failed with status: 0x1f" spam an
/// unimplemented command (e.g. an `ethtool` link-config query before this was
/// fixed) would otherwise produce. `MANA_SET_BW_CLAMP` (0x2000B) is a real MANA
/// command this device does not implement, so it exercises the catch-all.
#[async_test]
async fn test_gdma_unsupported_command_status(driver: DefaultDriver) {
    const MANA_SET_BW_CLAMP: u32 = 0x2000B;

    let mem = DeviceTestMemory::new(128, false, "test_gdma_unsupported_command_status");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();
    gdma.test_eq().await.unwrap();
    gdma.verify_vf_driver_version().await.unwrap();
    let dev_id = gdma
        .list_devices()
        .await
        .unwrap()
        .iter()
        .copied()
        .find(|dev_id| dev_id.ty == GdmaDevType::GDMA_DEVICE_MANA)
        .unwrap();
    gdma.register_device(dev_id).await.unwrap();

    // Send a command the device does not implement; the body is irrelevant
    // because the catch-all does not read it.
    let err = gdma
        .request::<_, ()>(
            MANA_SET_BW_CLAMP,
            dev_id,
            ManaFenceRqReq { wq_obj_handle: 0 },
        )
        .await
        .expect_err("an unimplemented command must be rejected");
    assert!(
        err.to_string()
            .contains(&format!("failed with {GDMA_STATUS_CMD_UNSUPPORTED:#x}")),
        "an unimplemented command must report GDMA_STATUS_CMD_UNSUPPORTED ({GDMA_STATUS_CMD_UNSUPPORTED:#x}); \
         driver error was: {err:#}",
    );
}

/// `MANA_QUERY_FILTER_CAP` (0x28007) is a privileged command that a
/// physical-function client managing the NIC issues to learn the device's
/// receive-filter and receive-object capacity; a virtual function never sends
/// it. The host miniport requires a successful response to finish bringing up
/// the NIC. Before this it fell through the catch-all and was rejected as
/// `GDMA_STATUS_CMD_UNSUPPORTED`, leaving the device unconfigured. Verify the
/// device reports the basic-NIC limits (one MAC filter, 64 receive objects). The
/// request carries no body beyond the header, so an empty request is sent.
#[async_test]
async fn test_gdma_query_filter_cap(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma_query_filter_cap");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();
    gdma.test_eq().await.unwrap();
    gdma.verify_vf_driver_version().await.unwrap();
    let dev_id = gdma
        .list_devices()
        .await
        .unwrap()
        .iter()
        .copied()
        .find(|dev_id| dev_id.ty == GdmaDevType::GDMA_DEVICE_MANA)
        .unwrap();
    gdma.register_device(dev_id).await.unwrap();

    let resp: ManaQueryFilterCapResponse = gdma
        .request(ManaCommandCode::MANA_QUERY_FILTER_CAP.0, dev_id, ())
        .await
        .expect("query filter cap must succeed");

    assert_eq!(
        resp.max_num_filters, 1,
        "device must report one MAC filter for a basic NIC"
    );
    assert_eq!(
        resp.max_num_rx_objects, 64,
        "device must report 64 receive objects for a basic NIC"
    );
}

/// `MANA_PF_CREATE_VPORT` (0x28003) is a privileged command a physical-function
/// client issues to create the vport it manages, obtaining the opaque handle it
/// then passes to the shared vport commands (config-vport-tx, create-wq-obj,
/// config-vport-rx). A virtual function never sends it -- it learns its vport
/// handle from `MANA_QUERY_VPORT_CONFIG` instead. Before this the command fell
/// through the catch-all and the host miniport looped in
/// `CM_PROB_NOT_CONFIGURED`. The emulator addresses its single vport by index
/// and returns that index (0) as the handle; verify both that the handle is 0
/// and -- the whole point of the handle -- that it resolves through a shared
/// command (`MANA_CONFIG_VPORT_TX`).
#[async_test]
async fn test_gdma_pf_create_vport(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma_pf_create_vport");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();
    gdma.test_eq().await.unwrap();
    gdma.verify_vf_driver_version().await.unwrap();
    let dev_id = gdma
        .list_devices()
        .await
        .unwrap()
        .iter()
        .copied()
        .find(|dev_id| dev_id.ty == GdmaDevType::GDMA_DEVICE_MANA)
        .unwrap();
    gdma.register_device(dev_id).await.unwrap();

    let resp: ManaPfCreateVportResp = gdma
        .request(
            ManaCommandCode::MANA_PF_CREATE_VPORT.0,
            dev_id,
            ManaPfCreateVportReq {
                attached_gf_id: 0,
                is_pvf_default_vport: 0,
                allow_vlan_tagging: 1,
                allow_all_ethertypes: 1,
                allow_src_mac_spoofing: 0,
                mask_vlan_tag: 0,
                strip_vlan_tag: 0,
                msix_table_size_hint: 0,
                mac_address_set: 1,
                enable_tx_vport: 1,
                mac_address: [1, 2, 3, 4, 5, 6],
            },
        )
        .await
        .expect("pf create vport must succeed");

    assert_eq!(
        resp.vport_handle, 0,
        "the single vport's handle is its index (0)"
    );

    // The returned handle must resolve through the shared vport commands the
    // privileged client issues next; configuring the vport TX path with the
    // handle proves it.
    let cfg: ManaConfigVportResp = gdma
        .request(
            ManaCommandCode::MANA_CONFIG_VPORT_TX.0,
            dev_id,
            ManaConfigVportReq {
                vport: resp.vport_handle,
                pdid: 0,
                doorbell_pageid: 0,
            },
        )
        .await
        .expect("config vport with the created vport handle must succeed");
    assert_eq!(cfg.short_form_allowed, 1);
}

/// `MANA_PF_CREATE_FILTER` (0x28000) is a privileged command a physical-function
/// client issues to create a receive filter (typically the default MAC filter)
/// on a vport, receiving an opaque filter handle to track. A virtual function
/// never sends it. The emulator keeps no filter table (its single vport receives
/// all backend traffic) but must return a distinct, non-invalid handle for the
/// privileged bring-up to proceed, and must reject a filter referencing an
/// unknown vport handle. Verify both.
#[async_test]
async fn test_gdma_pf_create_filter(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma_pf_create_filter");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();
    gdma.test_eq().await.unwrap();
    gdma.verify_vf_driver_version().await.unwrap();
    let dev_id = gdma
        .list_devices()
        .await
        .unwrap()
        .iter()
        .copied()
        .find(|dev_id| dev_id.ty == GdmaDevType::GDMA_DEVICE_MANA)
        .unwrap();
    gdma.register_device(dev_id).await.unwrap();

    let make_req = |vport_handle: u64| ManaPfCreateFilterReq {
        vport_handle,
        mac_address: [1, 2, 3, 4, 5, 6],
        allow_any_vlan_tag: 1,
        match_inner_mac_tni: 0,
        require_vlan_tag: 0,
        is_exception_filter: 0,
        vlan: 0,
        tni: 0,
        reserved2: 0,
        reserved3: 0,
    };

    // The single vport's handle is its index (0); creating a filter on it must
    // succeed and yield a non-invalid (not all-ones) handle.
    let resp: ManaPfCreateFilterResp = gdma
        .request(
            ManaCommandCode::MANA_PF_CREATE_FILTER.0,
            dev_id,
            make_req(0),
        )
        .await
        .expect("pf create filter must succeed");
    assert_ne!(
        resp.filter_handle,
        u64::MAX,
        "the filter handle must not be the invalid sentinel"
    );

    // A filter referencing a vport handle that does not resolve must be
    // rejected with the invalid-vport-handle status.
    let err = gdma
        .request::<_, ()>(
            ManaCommandCode::MANA_PF_CREATE_FILTER.0,
            dev_id,
            make_req(99),
        )
        .await
        .expect_err("a filter against an unknown vport handle must be rejected");
    assert!(
        err.to_string().contains(&format!(
            "failed with {:#x}",
            bnic_status::INVALID_VPORT_HANDLE
        )),
        "an unknown vport handle must report INVALID_VPORT_HANDLE ({:#x}); driver error was: {err:#}",
        bnic_status::INVALID_VPORT_HANDLE,
    );
}

/// `MANA_QUERY_LINK_CONFIG` (0x2000A) reports the adapter's link speed. ethtool
/// link queries and the QoS shaper issue it; the host (oracle) implements it, so
/// the emulator must too. Before this it fell through the catch-all and the
/// driver's `mana_query_link_cfg` logged a query failure on every poll. Verify
/// the configured link speed is echoed in both `link_speed_mbps` and
/// `qos_speed_mbps`, and that `qos_unconfigured` is 0 (a non-zero value makes
/// the driver reject the response with `-EINVAL`).
#[async_test]
async fn test_gdma_query_link_config(driver: DefaultDriver) {
    const LINK_SPEED_MBPS: u32 = 200_000;

    let mem = DeviceTestMemory::new(128, false, "test_gdma_query_link_config");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new_with_config(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
        gdma::BnicConfig {
            adapter_link_speed_mbps: LINK_SPEED_MBPS,
            ..Default::default()
        },
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();
    gdma.test_eq().await.unwrap();
    gdma.verify_vf_driver_version().await.unwrap();
    let dev_id = gdma
        .list_devices()
        .await
        .unwrap()
        .iter()
        .copied()
        .find(|dev_id| dev_id.ty == GdmaDevType::GDMA_DEVICE_MANA)
        .unwrap();
    gdma.register_device(dev_id).await.unwrap();

    let resp: ManaQueryLinkConfigResp = gdma
        .request(
            ManaCommandCode::MANA_QUERY_LINK_CONFIG.0,
            dev_id,
            ManaQueryLinkConfigReq { vport: 0 },
        )
        .await
        .expect("query link config must succeed");

    assert_eq!(
        resp.link_speed_mbps, LINK_SPEED_MBPS,
        "link_speed_mbps must report the configured adapter link speed"
    );
    assert_eq!(
        resp.qos_speed_mbps, LINK_SPEED_MBPS,
        "qos_speed_mbps must report the configured adapter link speed"
    );
    assert_eq!(
        resp.qos_unconfigured, 0,
        "qos_unconfigured must be 0 or the driver rejects the response with -EINVAL"
    );
}

/// With the default `BnicConfig` (no configured link speed) the device must
/// still report a concrete, non-zero speed for `MANA_QUERY_LINK_CONFIG`. The
/// guest's `mana_get_link_ksettings` copies `qos_speed_mbps` verbatim into
/// `ethtool`, which renders 0 as "Unknown!"; a PF that implements this command
/// always knows its speed, so the emulator reports its nominal line rate
/// (`MANA_DEFAULT_LINK_SPEED_MBPS`) instead. This mirrors the production path,
/// which constructs the device via `GdmaDevice::new` (default config).
#[async_test]
async fn test_gdma_query_link_config_default_speed(driver: DefaultDriver) {
    let mem = DeviceTestMemory::new(128, false, "test_gdma_query_link_config_default");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(NullEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let dma_client = device.dma_client();
    let buffer = dma_client.allocate_dma_buffer(6 * PAGE_SIZE).unwrap();

    let mut gdma = GdmaDriver::new(&driver, device, 1, Some(buffer))
        .await
        .unwrap();
    gdma.test_eq().await.unwrap();
    gdma.verify_vf_driver_version().await.unwrap();
    let dev_id = gdma
        .list_devices()
        .await
        .unwrap()
        .iter()
        .copied()
        .find(|dev_id| dev_id.ty == GdmaDevType::GDMA_DEVICE_MANA)
        .unwrap();
    gdma.register_device(dev_id).await.unwrap();

    let resp: ManaQueryLinkConfigResp = gdma
        .request(
            ManaCommandCode::MANA_QUERY_LINK_CONFIG.0,
            dev_id,
            ManaQueryLinkConfigReq { vport: 0 },
        )
        .await
        .expect("query link config must succeed");

    assert_eq!(
        resp.link_speed_mbps, MANA_DEFAULT_LINK_SPEED_MBPS,
        "an unconfigured adapter must report the nominal line rate, not 0"
    );
    assert_eq!(
        resp.qos_speed_mbps, MANA_DEFAULT_LINK_SPEED_MBPS,
        "qos_speed_mbps (ethtool speed) must be the nominal line rate, not 0"
    );
    assert_eq!(
        resp.qos_unconfigured, 0,
        "qos_unconfigured must be 0 or the driver rejects the response with -EINVAL"
    );
}
