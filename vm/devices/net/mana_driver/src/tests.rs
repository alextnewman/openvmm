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
use gdma::VportConfig;
use gdma_defs::GdmaDevId;
use gdma_defs::GdmaDevType;
use gdma_defs::GdmaQueueType;
use gdma_defs::GdmaReqHdr;
use gdma_defs::bnic::CQE_RX_OBJECT_FENCE;
use gdma_defs::bnic::ManaCfgRxSteerReq;
use gdma_defs::bnic::ManaCommandCode;
use gdma_defs::bnic::ManaCqeHeader;
use gdma_defs::bnic::STATISTICS_FLAGS_ALL;
use gdma_defs::bnic::Tristate;
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
use std::sync::Arc;
use test_with_tracing::test;
use user_driver::DeviceBacking;
use user_driver::memory::MemoryBlock;
use user_driver::memory::PAGE_SIZE;
use user_driver_emulated_mock::DeviceTestMemory;
use user_driver_emulated_mock::EmulatedDevice;
use vmcore::device_state::ChangeDeviceState;
use vmcore::vm_task::SingleDriverBackend;
use vmcore::vm_task::VmTaskDriverSource;
use zerocopy::FromBytes;
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
