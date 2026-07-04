// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(test)]

use crate::GuestDmaMode;
use crate::ManaEndpoint;
use crate::ManaTestConfiguration;
use crate::QueueStats;
use async_trait::async_trait;
use chipset_device::mmio::ExternallyManagedMmioIntercepts;
use gdma::VportConfig;
use gdma_defs::bnic::ManaQueryDeviceCfgResp;
use inspect::InspectMut;
use inspect_counters::Counter;
use mana_driver::mana::ManaDevice;
use mana_driver::mana::RxConfig;
use mesh::CancelContext;
use mesh::CancelReason;
use net_backend::BufferAccess;
use net_backend::Endpoint;
use net_backend::MultiQueueSupport;
use net_backend::Queue;
use net_backend::QueueConfig;
use net_backend::RssConfig;
use net_backend::RxId;
use net_backend::TxId;
use net_backend::TxSegment;
use net_backend::VlanMetadata;
use net_backend::linearize;
use net_backend::loopback::LoopbackEndpoint;
use net_backend::next_packet;
use pal_async::DefaultDriver;
use pal_async::async_test;
use parking_lot::Mutex;
use pci_core::bus_range::AssignedBusRange;
use pci_core::msi::MsiConnection;
use std::collections::VecDeque;
use std::future::poll_fn;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;
use std::time::Duration;
use test_with_tracing::test;
use user_driver_emulated_mock::DeviceTestMemory;
use user_driver_emulated_mock::EmulatedDevice;
use vmcore::vm_task::SingleDriverBackend;
use vmcore::vm_task::VmTaskDriverSource;

const IPV4_HEADER_LENGTH: usize = 54;
const IPV4_VLAN_HEADER_LENGTH: usize = 58;
const MAX_GDMA_SGE_PER_TX_PACKET: usize = 31;

struct TxPacketBuilder {
    /// Tracks segments for all the packets
    segments: Vec<TxSegment>,
    /// Total length of all the segments
    total_len: u64,
    /// Tracks the length of each packet. The length of this vector is the number of packets.
    pkt_len: Vec<u64>,
}

impl TxPacketBuilder {
    fn new() -> Self {
        Self {
            segments: Vec::new(),
            total_len: 0,
            pkt_len: Vec::new(),
        }
    }

    fn push(&mut self, segment: TxSegment) {
        self.total_len += segment.len as u64;
        if let net_backend::TxSegmentType::Head(metadata) = &segment.ty {
            self.pkt_len.push(metadata.len as u64);
        }
        self.segments.push(segment);
    }

    fn packet_data(&self) -> Vec<u8> {
        (0..self.total_len).map(|v| v as u8).collect::<Vec<u8>>()
    }

    fn data_len(&self) -> u64 {
        self.total_len
    }

    fn segments(&self) -> &[TxSegment] {
        &self.segments
    }
}

/// Constructs a mana emulator backed by the loopback endpoint, then hooks a
/// mana driver up to it, puts the net_mana endpoint on top of that, and
/// ensures that packets can be sent and received.
#[async_test]
async fn test_endpoint_direct_dma(driver: DefaultDriver) {
    // 1 segment of 1138 bytes
    send_test_packet(
        driver.clone(),
        GuestDmaMode::DirectDma,
        1138,
        1,
        false, // LSO?
        None,  // Test config
        None,  // Default expected stats
    )
    .await;

    // 10 segments of 113 bytes each == 1130
    send_test_packet(
        driver.clone(),
        GuestDmaMode::DirectDma,
        1130,
        10,
        false, // LSO?
        None,  // Test config
        None,  // Default expected stats
    )
    .await;
}

#[async_test]
async fn test_endpoint_bounce_buffer(driver: DefaultDriver) {
    // 1 segment of 1138 bytes
    send_test_packet(
        driver,
        GuestDmaMode::BounceBuffer,
        1138,
        1,
        false, // LSO?
        None,  // Test config
        None,  // Default expected stats
    )
    .await;
}

#[async_test]
async fn test_segment_coalescing(driver: DefaultDriver) {
    // 34 segments of 60 bytes each == 2040
    send_test_packet(
        driver,
        GuestDmaMode::DirectDma,
        2040,
        34,
        false, // LSO?
        None,  // Test config
        None,  // Default expected stats
    )
    .await;
}

#[async_test]
async fn test_segment_coalescing_many(driver: DefaultDriver) {
    // 128 segments of 16 bytes each == 2048
    send_test_packet(
        driver.clone(),
        GuestDmaMode::DirectDma,
        2048,
        128,
        false, // LSO?
        None,  // Test config
        None,  // Default expected stats
    )
    .await;
}

#[async_test]
async fn test_packet_header_gt_head(driver: DefaultDriver) {
    let num_segments = 32;
    let packet_len = num_segments * (IPV4_HEADER_LENGTH - 10);
    send_test_packet(
        driver.clone(),
        GuestDmaMode::DirectDma,
        packet_len,
        num_segments,
        false, // LSO?
        None,  // Test config
        None,  // Default expected stats
    )
    .await;
}

#[async_test]
async fn test_lso_header_eq_head(driver: DefaultDriver) {
    // For the header (i.e. protocol) length to be equal to the head segment, make
    // the segment length equal to the protocol header length.
    let segment_len = IPV4_HEADER_LENGTH;
    let num_segments = MAX_GDMA_SGE_PER_TX_PACKET - 10;
    let packet_len = num_segments * segment_len;
    send_test_packet(
        driver.clone(),
        GuestDmaMode::DirectDma,
        packet_len,
        num_segments,
        true, // LSO?
        None, // Test config
        None, // Default expected stats
    )
    .await;

    // Caolescing test
    let num_segments = MAX_GDMA_SGE_PER_TX_PACKET + 1;
    let packet_len = num_segments * segment_len;
    send_test_packet(
        driver.clone(),
        GuestDmaMode::DirectDma,
        packet_len,
        num_segments,
        true, // LSO?
        None, // Test config
        None, // Default expected stats
    )
    .await;
}

#[async_test]
async fn test_lso_header_lt_head(driver: DefaultDriver) {
    // For the header (i.e. protocol) length to be less than the head segment, make
    // the segment length greater than the protocol header length to force the header
    // to fit in the first segment.
    let segment_len = IPV4_HEADER_LENGTH + 6;
    let num_segments = MAX_GDMA_SGE_PER_TX_PACKET - 10;
    let packet_len = num_segments * segment_len;
    send_test_packet(
        driver.clone(),
        GuestDmaMode::DirectDma,
        packet_len,
        num_segments,
        true, // LSO?
        None, // Test config
        None, // Default expected stats
    )
    .await;

    // Coalescing test
    let num_segments = MAX_GDMA_SGE_PER_TX_PACKET + 1;
    let packet_len = num_segments * segment_len;
    send_test_packet(
        driver.clone(),
        GuestDmaMode::DirectDma,
        packet_len,
        num_segments,
        true, // LSO?
        None, // Test config
        None, // Default expected stats
    )
    .await;
}

#[async_test]
async fn test_lso_header_gt_head(driver: DefaultDriver) {
    // For the header (i.e. protocol) length to be greater than the head segment, make
    // the segment length smaller than the protocol header length to force the header
    // to not fit in the first segment.
    let segment_len = IPV4_HEADER_LENGTH - 5;
    let num_segments = MAX_GDMA_SGE_PER_TX_PACKET - 10;
    let packet_len = num_segments * segment_len;
    send_test_packet(
        driver.clone(),
        GuestDmaMode::DirectDma,
        packet_len,
        num_segments,
        true, // LSO?
        None, // Test config
        None, // Default expected stats
    )
    .await;

    // Coalescing test
    let num_segments = MAX_GDMA_SGE_PER_TX_PACKET + 1;
    let packet_len = num_segments * segment_len;
    send_test_packet(
        driver.clone(),
        GuestDmaMode::DirectDma,
        packet_len,
        num_segments,
        true, // LSO?
        None, // Test config
        None, // Default expected stats
    )
    .await;
}

#[async_test]
async fn test_lso_split_header(driver: DefaultDriver) {
    // Invalid split header with header missing bytes (packet should get dropped).
    // Keep the total packet length less than the protocol header length.
    let segment_len = 1;
    let num_segments = IPV4_HEADER_LENGTH - 10;
    let packet_len = num_segments * segment_len;
    let expected_stats = Some(QueueStats {
        tx_packets: Counter::new(),
        rx_packets: Counter::new(),
        tx_errors: Counter::new(),
        rx_errors: Counter::new(),
        ..Default::default()
    });
    send_test_packet(
        driver.clone(),
        GuestDmaMode::DirectDma,
        packet_len,
        num_segments,
        true, // LSO?
        None, // Test config
        expected_stats,
    )
    .await;

    // Excessive splitting of the header, but keep the total packet length
    // the same as the protocol header length. The header should get coalesced
    // correctly back to one segment. With LSO, packet with one segment is
    // invalid and the expected result is that the packet gets dropped.
    let segment_len = 1;
    let num_segments = IPV4_HEADER_LENGTH;
    let packet_len = num_segments * segment_len;
    let expected_stats = Some(QueueStats {
        tx_packets: Counter::new(),
        rx_packets: Counter::new(),
        tx_errors: Counter::new(),
        rx_errors: Counter::new(),
        ..Default::default()
    });
    send_test_packet(
        driver.clone(),
        GuestDmaMode::DirectDma,
        packet_len,
        num_segments,
        true, // LSO?
        None, // Test config
        expected_stats,
    )
    .await;

    // Excessive splitting of the header, but total segment will be more than
    // one after coalescing. The packet should be accepted.
    let segment_len = 1;
    let num_segments = IPV4_HEADER_LENGTH + 10;
    let packet_len = num_segments * segment_len;
    send_test_packet(
        driver.clone(),
        GuestDmaMode::DirectDma,
        packet_len,
        num_segments,
        true, // LSO?
        None, // Test config
        None, // Default expected stats
    )
    .await;

    // Split headers such that the last header has both header and payload bytes.
    // i.e. The header should not evenly split into segments.
    let segment_len = 5;
    assert!(!IPV4_HEADER_LENGTH.is_multiple_of(segment_len));
    let num_segments = IPV4_HEADER_LENGTH + 10;
    let packet_len = num_segments * segment_len;
    send_test_packet(
        driver.clone(),
        GuestDmaMode::DirectDma,
        packet_len,
        num_segments,
        true, // LSO?
        None, // Test config
        None, // Default expected stats
    )
    .await;
}

#[async_test]
async fn test_lso_segment_coalescing_only_header(driver: DefaultDriver) {
    let segment_len = IPV4_HEADER_LENGTH;
    let num_segments = 1;
    let packet_len = num_segments * segment_len;
    // An LSO packet without any payload is considered bad packet and should be dropped.
    let expected_stats = Some(QueueStats {
        tx_packets: Counter::new(),
        rx_packets: Counter::new(),
        tx_errors: Counter::new(),
        rx_errors: Counter::new(),
        ..Default::default()
    });
    send_test_packet(
        driver.clone(),
        GuestDmaMode::DirectDma,
        packet_len,
        num_segments,
        true, // LSO?
        None, // Test config
        expected_stats,
    )
    .await;

    // Allow LSO with only header segment for test coverage and check that it
    // results in error stats incremented.
    let mut expected_stats = Some(QueueStats {
        tx_packets: Counter::new(),
        rx_packets: Counter::new(),
        tx_errors: Counter::new(),
        rx_errors: Counter::new(),
        ..Default::default()
    });

    expected_stats.as_mut().unwrap().tx_errors.add(1);
    let test_config = Some(ManaTestConfiguration {
        allow_lso_pkt_with_one_sge: true,
    });
    send_test_packet(
        driver.clone(),
        GuestDmaMode::DirectDma,
        packet_len,
        num_segments,
        true, // LSO?
        test_config,
        expected_stats,
    )
    .await;
}

// Tests for multiple packets in a single Tx call.
#[async_test]
async fn test_multi_packet(driver: DefaultDriver) {
    let mut num_packets = 0;
    let mut pkt_builder = TxPacketBuilder::new();
    let packet_len = 550;
    let num_segments = 1;
    let enable_lso = false;
    build_tx_segments(packet_len, num_segments, enable_lso, &mut pkt_builder);
    num_packets += 1;

    // Coalescing
    let packet_len = 2040;
    let num_segments = MAX_GDMA_SGE_PER_TX_PACKET + 3;
    build_tx_segments(packet_len, num_segments, enable_lso, &mut pkt_builder);
    num_packets += 1;

    // Split headers
    let segment_len = 1;
    let num_segments = IPV4_HEADER_LENGTH - 10;
    let packet_len = num_segments * segment_len;
    build_tx_segments(packet_len, num_segments, enable_lso, &mut pkt_builder);
    num_packets += 1;

    let packet_len = 650;
    let num_segments = 10;
    build_tx_segments(packet_len, num_segments, enable_lso, &mut pkt_builder);
    num_packets += 1;

    let mut expected_stats = QueueStats {
        ..Default::default()
    };
    expected_stats.tx_packets.add(num_packets);
    expected_stats.rx_packets.add(num_packets);

    send_test_packet_multi(
        driver.clone(),
        GuestDmaMode::DirectDma,
        &mut pkt_builder,
        None,                 // Test config
        Some(expected_stats), // Default expected stats
    )
    .await;
}

// Tests for multiple LSO packets in a single Tx call.
#[async_test]
async fn test_multi_lso_packet(driver: DefaultDriver) {
    let mut num_packets = 0;
    let enable_lso = true;
    let mut pkt_builder = TxPacketBuilder::new();
    // Header equals head segment.
    let segment_len = IPV4_HEADER_LENGTH;
    let num_segments = MAX_GDMA_SGE_PER_TX_PACKET - 10;
    let packet_len = segment_len * num_segments;
    build_tx_segments(packet_len, num_segments, enable_lso, &mut pkt_builder);
    num_packets += 1;

    // Coalescing
    let num_segments = MAX_GDMA_SGE_PER_TX_PACKET + 1;
    let packet_len = num_segments * segment_len;
    build_tx_segments(packet_len, num_segments, enable_lso, &mut pkt_builder);
    num_packets += 1;

    // Excessive splitting of split headers
    let segment_len = 1;
    let num_segments = IPV4_HEADER_LENGTH + 10;
    let packet_len = num_segments * segment_len;
    build_tx_segments(packet_len, num_segments, enable_lso, &mut pkt_builder);
    num_packets += 1;

    // Header greater than head segment.
    let segment_len = IPV4_HEADER_LENGTH - 5;
    let num_segments = MAX_GDMA_SGE_PER_TX_PACKET - 10;
    let packet_len = num_segments * segment_len;
    build_tx_segments(packet_len, num_segments, enable_lso, &mut pkt_builder);
    num_packets += 1;

    let mut expected_stats = QueueStats {
        ..Default::default()
    };
    expected_stats.tx_packets.add(num_packets);
    expected_stats.rx_packets.add(num_packets);

    send_test_packet_multi(
        driver.clone(),
        GuestDmaMode::DirectDma,
        &mut pkt_builder,
        None,                 // Test config
        Some(expected_stats), // Default expected stats
    )
    .await;
}

// Tests for multiple mixed (LSO and non-LSO) packets in a single Tx call.
#[async_test]
async fn test_multi_mixed_packet(driver: DefaultDriver) {
    let mut num_packets = 0;
    let mut pkt_builder = TxPacketBuilder::new();

    // Simple non-LSO packet
    let packet_len = 550;
    let num_segments = 1;
    build_tx_segments(packet_len, num_segments, false, &mut pkt_builder);
    num_packets += 1;

    // Excessive splitting of split headers for LSO packet
    let segment_len = 1;
    let num_segments = IPV4_HEADER_LENGTH + 10;
    let packet_len = num_segments * segment_len;
    build_tx_segments(packet_len, num_segments, true, &mut pkt_builder);
    num_packets += 1;

    // Coalescing for non-LSO packet
    let packet_len = 2040;
    let num_segments = MAX_GDMA_SGE_PER_TX_PACKET + 3;
    build_tx_segments(packet_len, num_segments, false, &mut pkt_builder);
    num_packets += 1;

    // Finish with a LSO packet.
    let segment_len = IPV4_HEADER_LENGTH - 5;
    let num_segments = MAX_GDMA_SGE_PER_TX_PACKET - 10;
    let packet_len = num_segments * segment_len;
    build_tx_segments(packet_len, num_segments, true, &mut pkt_builder);
    num_packets += 1;

    let mut expected_stats = QueueStats {
        ..Default::default()
    };
    expected_stats.tx_packets.add(num_packets);
    expected_stats.rx_packets.add(num_packets);

    send_test_packet_multi(
        driver.clone(),
        GuestDmaMode::DirectDma,
        &mut pkt_builder,
        None,                 // Test config
        Some(expected_stats), // Default expected stats
    )
    .await;
}

#[async_test]
async fn test_vport_with_query_filter_state(driver: DefaultDriver) {
    let pages = 512; // 2MB
    let mem = DeviceTestMemory::new(pages, false, "test_vport_with_query_filter_state");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(LoopbackEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let dma_client = mem.dma_client();
    let device = EmulatedDevice::new(device, msi_conn, dma_client);
    let cap_flags1 = gdma_defs::bnic::BasicNicDriverFlags::new().with_query_filter_state(1);
    let dev_config = ManaQueryDeviceCfgResp {
        pf_cap_flags1: cap_flags1,
        pf_cap_flags2: 0,
        pf_cap_flags3: 0,
        pf_cap_flags4: 0,
        max_num_vports: 1,
        bm_hostmode: 0,
        reserved: 0,
        max_num_eqs: 64,
        adapter_mtu: 0,
        reserved2: 0,
        adapter_link_speed_mbps: 0,
    };
    let thing = ManaDevice::new(&driver, device, 1, 1, None).await.unwrap();
    let _ = thing.new_vport(0, None, &dev_config).await.unwrap();
}

/// Verifies that the link speed queried from the adapter via the full driver
/// stack is reported correctly through `dev_config().link_speed_bps()`,
/// `vport.link_speed_bps()`, and `endpoint.link_speed()`.
///
/// The emulated GDMA device returns `adapter_link_speed_mbps = 0`, so the
/// driver-stack path exercises the 200 Gbps fallback.
#[async_test]
async fn test_link_speed_default(driver: DefaultDriver) {
    // Verify that a non-zero adapter_link_speed_mbps is converted to bps
    // correctly, without going through the driver stack.
    let dev_config_nonzero = ManaQueryDeviceCfgResp {
        pf_cap_flags1: 0.into(),
        pf_cap_flags2: 0,
        pf_cap_flags3: 0,
        pf_cap_flags4: 0,
        max_num_vports: 1,
        bm_hostmode: 0,
        reserved: 0,
        max_num_eqs: 64,
        adapter_mtu: 0,
        reserved2: 0,
        adapter_link_speed_mbps: 100 * 1000, // 100 Gbps
    };
    assert_eq!(
        dev_config_nonzero.link_speed_bps(),
        100 * 1000 * 1000 * 1000
    );

    // Now exercise the full driver stack. The emulated GDMA device returns
    // adapter_link_speed_mbps = 0, so the 200 Gbps fallback is expected
    // throughout.
    const FALLBACK_LINK_SPEED_BPS: u64 = 200 * 1000 * 1000 * 1000;

    let pages = 512; // 2MB
    let mem = DeviceTestMemory::new(pages, false, "test_link_speed_default");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(LoopbackEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());

    let mana_device = ManaDevice::new(&driver, device, 1, 1, None).await.unwrap();

    // Verify the link speed as seen in the device config populated by
    // query_dev_config() during ManaDevice::new().
    assert_eq!(
        mana_device.dev_config().link_speed_bps(),
        FALLBACK_LINK_SPEED_BPS
    );

    let vport = mana_device
        .new_vport(
            0,
            None,
            &ManaQueryDeviceCfgResp {
                pf_cap_flags1: 0.into(),
                pf_cap_flags2: 0,
                pf_cap_flags3: 0,
                pf_cap_flags4: 0,
                max_num_vports: 1,
                bm_hostmode: 0,
                reserved: 0,
                max_num_eqs: 64,
                adapter_mtu: 0,
                reserved2: 0,
                adapter_link_speed_mbps: 0,
            },
        )
        .await
        .unwrap();

    // The vport inherits the link speed from the ManaDevice (emulator value).
    assert_eq!(vport.link_speed_bps(), FALLBACK_LINK_SPEED_BPS);

    // Verify it is also surfaced correctly through the Endpoint trait.
    let mut endpoint = ManaEndpoint::new(driver.clone(), vport, GuestDmaMode::DirectDma).await;
    assert_eq!(endpoint.link_speed(), FALLBACK_LINK_SPEED_BPS);
    endpoint.stop().await;
}

/// Verifies that a link speed configured on the emulated GDMA device propagates
/// through the full net_mana driver stack: `dev_config().link_speed_bps()`,
/// `vport.link_speed_bps()`, and `endpoint.link_speed()`.
#[async_test]
async fn test_link_speed_expected(driver: DefaultDriver) {
    verify_link_speed_expected(driver, 400 * 1000).await; // 400 Gbps
}

async fn verify_link_speed_expected(driver: DefaultDriver, link_speed_mbps: u32) {
    let link_speed_bps = link_speed_mbps as u64 * 1000 * 1000;

    let pages = 512;
    let mem = DeviceTestMemory::new(pages, false, "test_link_speed_expected");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new_with_config(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(LoopbackEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
        gdma::BnicConfig {
            adapter_link_speed_mbps: link_speed_mbps,
            ..Default::default()
        },
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());

    let thing = ManaDevice::new(&driver, device, 1, 1, None).await.unwrap();

    // Layer 1: dev_config stored on ManaDevice.
    assert_eq!(
        thing.dev_config().link_speed_bps(),
        link_speed_bps,
        "dev_config().link_speed_bps() should reflect the configured link speed"
    );

    let vport_dev_config = ManaQueryDeviceCfgResp {
        pf_cap_flags1: 0.into(),
        pf_cap_flags2: 0,
        pf_cap_flags3: 0,
        pf_cap_flags4: 0,
        max_num_vports: 1,
        bm_hostmode: 0,
        reserved: 0,
        max_num_eqs: 64,
        adapter_mtu: 0,
        reserved2: 0,
        adapter_link_speed_mbps: 0,
    };
    let vport = thing.new_vport(0, None, &vport_dev_config).await.unwrap();

    // Layer 2: vport derives its link speed from the stored dev_config,
    // not from the per-call vport_dev_config.
    assert_eq!(
        vport.link_speed_bps(),
        link_speed_bps,
        "vport.link_speed_bps() should reflect the configured link speed"
    );

    // Layer 3: ManaEndpoint surfaces it via the Endpoint trait.
    let mut endpoint = ManaEndpoint::new(driver.clone(), vport, GuestDmaMode::DirectDma).await;
    assert_eq!(
        endpoint.link_speed(),
        link_speed_bps,
        "endpoint.link_speed() should reflect the configured link speed"
    );
    endpoint.stop().await;
}

#[async_test]
async fn test_rx_error_handling(driver: DefaultDriver) {
    // Send a packet larger than the 2048-byte RX buffer, causing the GDMA BNIC emulator
    // to return CQE_RX_TRUNCATED, exercising the rx_poll error path.
    let expected_num_tx_packets = 1;
    let expected_num_rx_packets = 0;
    let num_segments = 1;
    let packet_len = 4096; // Exceeds the 2048-byte RX buffer

    let mut pkt_builder = TxPacketBuilder::new();
    build_tx_segments(packet_len, num_segments, false, &mut pkt_builder);

    let (stats, _) = test_endpoint(
        driver,
        GuestDmaMode::DirectDma,
        &pkt_builder,
        expected_num_tx_packets,
        expected_num_rx_packets,
        ManaTestConfiguration::default(),
    )
    .await;

    assert_eq!(stats.rx_errors.get(), 1, "rx_errors should increase");
    assert_eq!(stats.rx_packets.get(), 0, "rx_packets should stay the same");
    assert_eq!(stats.tx_packets.get(), 1, "tx_packets should increase");
}

async fn send_test_packet(
    driver: DefaultDriver,
    dma_mode: GuestDmaMode,
    packet_len: usize,
    num_segments: usize,
    enable_lso: bool,
    test_config: Option<ManaTestConfiguration>,
    expected_stats: Option<QueueStats>,
) {
    let mut pkt_builder = TxPacketBuilder::new();
    build_tx_segments(packet_len, num_segments, enable_lso, &mut pkt_builder);
    send_test_packet_multi(
        driver,
        dma_mode,
        &mut pkt_builder,
        test_config,
        expected_stats,
    )
    .await;
}

async fn send_test_packet_multi(
    driver: DefaultDriver,
    dma_mode: GuestDmaMode,
    pkt_builder: &mut TxPacketBuilder,
    test_config: Option<ManaTestConfiguration>,
    expected_stats: Option<QueueStats>,
) {
    let test_config = test_config.unwrap_or_default();
    let expected_stats = expected_stats.unwrap_or_else(|| {
        let mut tx_packets = Counter::new();
        tx_packets.add(1);
        let mut rx_packets = Counter::new();
        rx_packets.add(1);
        QueueStats {
            tx_packets,
            rx_packets,
            tx_errors: Counter::new(),
            rx_errors: Counter::new(),
            ..Default::default()
        }
    });

    let (stats, _) = test_endpoint(
        driver,
        dma_mode,
        pkt_builder,
        expected_stats.tx_packets.get() as usize,
        expected_stats.rx_packets.get() as usize,
        test_config,
    )
    .await;

    assert_eq!(
        stats.tx_packets.get(),
        expected_stats.tx_packets.get(),
        "tx_packets mismatch"
    );
    assert_eq!(
        stats.rx_packets.get(),
        expected_stats.rx_packets.get(),
        "rx_packets mismatch"
    );
    assert_eq!(
        stats.tx_errors.get(),
        expected_stats.tx_errors.get(),
        "tx_errors mismatch"
    );
    assert_eq!(
        stats.rx_errors.get(),
        expected_stats.rx_errors.get(),
        "rx_errors mismatch"
    );
}

fn build_tx_segments_internal(
    packet_len: usize,
    num_segments: usize,
    enable_lso: bool,
    vlan: Option<VlanMetadata>,
    pkt_builder: &mut TxPacketBuilder,
) {
    assert_eq!(packet_len % num_segments, 0);
    let tx_id = 1;
    let segment_len = packet_len / num_segments;
    let mut tx_metadata = net_backend::TxMetadata {
        id: TxId(tx_id),
        segment_count: num_segments as u8,
        len: packet_len as u32,
        l2_len: if vlan.is_some() {
            18 // Ethernet header with 802.1q
        } else {
            14 // Ethernet header
        },
        l3_len: 20,             // IPv4 header
        l4_len: 20,             // TCP header
        max_segment_size: 1460, // Typical MSS for Ethernet
        vlan,
        ..Default::default()
    };

    tx_metadata.flags.set_offload_tcp_segmentation(enable_lso);

    if tx_metadata.vlan.is_some() {
        assert_eq!(
            tx_metadata.l2_len as usize + tx_metadata.l3_len as usize + tx_metadata.l4_len as usize,
            IPV4_VLAN_HEADER_LENGTH
        );
    } else {
        assert_eq!(
            tx_metadata.l2_len as usize + tx_metadata.l3_len as usize + tx_metadata.l4_len as usize,
            IPV4_HEADER_LENGTH
        );
    }

    assert_eq!(packet_len % num_segments, 0);

    let mut gpa = pkt_builder.data_len();
    pkt_builder.push(TxSegment {
        ty: net_backend::TxSegmentType::Head(tx_metadata.clone()),
        gpa,
        len: segment_len as u32,
    });

    for _ in 0..(num_segments - 1) {
        gpa += segment_len as u64;
        pkt_builder.push(TxSegment {
            ty: net_backend::TxSegmentType::Tail,
            gpa,
            len: segment_len as u32,
        });
    }
}

fn build_tx_segments(
    packet_len: usize,
    num_segments: usize,
    enable_lso: bool,
    pkt_builder: &mut TxPacketBuilder,
) {
    build_tx_segments_internal(packet_len, num_segments, enable_lso, None, pkt_builder);
}

fn build_tx_segments_vlan(
    packet_len: usize,
    num_segments: usize,
    vlan_id: u16,
    vlan_priority: u8,
    vlan_dei: bool,
    pkt_builder: &mut TxPacketBuilder,
) {
    build_tx_segments_internal(
        packet_len,
        num_segments,
        false, // LSO doesn't make sense for VLAN-tagged packets in these tests.
        Some(
            VlanMetadata::new()
                .with_priority(vlan_priority)
                .with_drop_eligible_indicator(vlan_dei)
                .with_vlan_id(vlan_id),
        ),
        pkt_builder,
    );
}

async fn test_endpoint(
    driver: DefaultDriver,
    dma_mode: GuestDmaMode,
    pkt_builder: &TxPacketBuilder,
    expected_num_send_packets: usize,
    expected_num_received_packets: usize,
    test_configuration: ManaTestConfiguration,
) -> (QueueStats, Vec<Option<net_backend::RxMetadata>>) {
    let pages = 256; // 1MB
    let allow_dma = dma_mode == GuestDmaMode::DirectDma;
    let mem: DeviceTestMemory = DeviceTestMemory::new(pages * 2, allow_dma, "test_endpoint");
    let payload_mem = mem.payload_mem();
    let data_to_send = pkt_builder.packet_data();
    let tx_segments = pkt_builder.segments();

    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(LoopbackEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let dev_config = ManaQueryDeviceCfgResp {
        pf_cap_flags1: 0.into(),
        pf_cap_flags2: 0,
        pf_cap_flags3: 0,
        pf_cap_flags4: 0,
        max_num_vports: 1,
        bm_hostmode: 0,
        reserved: 0,
        max_num_eqs: 64,
        adapter_mtu: 0,
        reserved2: 0,
        adapter_link_speed_mbps: 0,
    };
    let thing = ManaDevice::new(&driver, device, 1, 1, None).await.unwrap();
    let vport = thing.new_vport(0, None, &dev_config).await.unwrap();
    let mut endpoint = ManaEndpoint::new(driver.clone(), vport, dma_mode).await;
    endpoint.set_test_configuration(test_configuration);
    let mut queues = Vec::new();
    let mut pool = net_backend::tests::Bufs::new(payload_mem.clone());
    endpoint
        .get_queues(
            vec![QueueConfig {
                driver: Box::new(driver.clone()),
            }],
            None,
            &mut queues,
        )
        .await
        .unwrap();

    // Post initial RX buffers.
    queues[0].rx_avail(&mut pool, &(1..128u32).map(RxId).collect::<Vec<_>>());

    payload_mem.write_at(0, &data_to_send).unwrap();

    queues[0].tx_avail(&mut pool, tx_segments).unwrap();

    // Poll for completion
    // Keep at least couple of elements in the Rx and Tx done vectors to
    // allow for zero packet tests.
    let mut rx_packets = (0..expected_num_received_packets.max(2))
        .map(|i| RxId(i as u32))
        .collect::<Vec<_>>();
    let mut rx_packets_n = 0;
    let mut tx_done = vec![TxId(0); expected_num_send_packets.max(2)];
    let mut tx_done_n = 0;

    // Wait until both expected RX and TX completions are satisfied.
    // When an expected count is 0, its condition is immediately true.
    let done = |rx_n: usize, tx_n: usize| -> bool {
        rx_n >= expected_num_received_packets && tx_n >= expected_num_send_packets
    };

    loop {
        let mut context = CancelContext::new().with_timeout(Duration::from_secs(1));
        match context
            .until_cancelled(poll_fn(|cx| queues[0].poll_ready(cx, &mut pool)))
            .await
        {
            Err(CancelReason::DeadlineExceeded) => break,
            Err(e) => {
                tracing::error!(error = ?e, "Failed to poll queue ready");
                break;
            }
            _ => {}
        }
        rx_packets_n += queues[0]
            .rx_poll(&mut pool, &mut rx_packets[rx_packets_n..])
            .unwrap();
        // GDMA Errors generate a TryReturn error, ignored here.
        tx_done_n += queues[0]
            .tx_poll(&mut pool, &mut tx_done[tx_done_n..])
            .unwrap_or(0);
        if done(rx_packets_n, tx_done_n) {
            break;
        }
    }
    assert_eq!(rx_packets_n, expected_num_received_packets);
    assert_eq!(tx_done_n, expected_num_send_packets);

    if expected_num_received_packets == 0 {
        // If no packets were received, exit.
        let stats = get_queue_stats(queues[0].queue_stats());
        drop(queues);
        endpoint.stop().await;
        return (stats, Vec::new());
    }

    // GDMA emulator always returns TxId(1) for completed packets.
    for done in tx_done.iter().take(expected_num_send_packets) {
        assert_eq!(done.0, 1);
    }

    // Check rx
    let mut offset = 0;
    for (i, rx_id) in rx_packets
        .iter()
        .enumerate()
        .take(expected_num_received_packets)
    {
        let this_pkt_len = pkt_builder.pkt_len[i] as usize;
        let mut received_data = vec![0; this_pkt_len];
        assert_eq!(rx_id.0, (i + 1) as u32);
        let buffer_size = pool.capacity(*rx_id) as u64;
        payload_mem
            .read_at(buffer_size * rx_id.0 as u64, &mut received_data)
            .unwrap();
        assert_eq!(received_data.len(), this_pkt_len);
        assert_eq!(
            &received_data,
            &data_to_send[offset..offset + this_pkt_len],
            "{:?}",
            rx_id
        );
        offset += this_pkt_len;
    }

    // Gather per-buffer RX metadata written by net_mana.
    let rx_meta: Vec<Option<net_backend::RxMetadata>> = rx_packets[..rx_packets_n]
        .iter()
        .map(|id| pool.rx_metadata(*id))
        .collect();

    let stats = get_queue_stats(queues[0].queue_stats());
    drop(queues);
    endpoint.stop().await;
    (stats, rx_meta)
}

fn get_queue_stats(queue_stats: Option<&dyn net_backend::BackendQueueStats>) -> QueueStats {
    let queue_stats = queue_stats.unwrap();
    QueueStats {
        rx_errors: queue_stats.rx_errors(),
        tx_errors: queue_stats.tx_errors(),
        rx_packets: queue_stats.rx_packets(),
        tx_packets: queue_stats.tx_packets(),
        tx_vlan_packets: queue_stats.tx_vlan_packets(),
        rx_vlan_packets: queue_stats.rx_vlan_packets(),
        ..Default::default()
    }
}

use crate::ManaQueue;
use gdma_defs::CqeParams;
use gdma_defs::bnic::ManaTxCompOob;
use mana_driver::mana::ResourceArena;
use page_pool_alloc::PagePoolAllocator;
use zerocopy::FromZeros;

type TestEmulatedDevice = EmulatedDevice<gdma::GdmaDevice, PagePoolAllocator>;

/// Sets up the full device stack and returns a [`ManaQueue`] ready for
/// direct `handle_tx_cqe` testing along with the resources needed for
/// teardown.
async fn new_test_queue(
    driver: &DefaultDriver,
) -> (
    ManaQueue<TestEmulatedDevice>,
    ResourceArena,
    ManaEndpoint<TestEmulatedDevice>,
) {
    let pages = 256;
    let mem = DeviceTestMemory::new(pages * 2, true, "test queue");
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(LoopbackEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let dev_config = ManaQueryDeviceCfgResp {
        pf_cap_flags1: 0.into(),
        pf_cap_flags2: 0,
        pf_cap_flags3: 0,
        pf_cap_flags4: 0,
        max_num_vports: 1,
        bm_hostmode: 0,
        reserved: 0,
        max_num_eqs: 64,
        adapter_mtu: 0,
        reserved2: 0,
        adapter_link_speed_mbps: 0,
    };
    let thing = ManaDevice::new(driver, device, 1, 1, None).await.unwrap();
    let vport = thing.new_vport(0, None, &dev_config).await.unwrap();
    let mut endpoint = ManaEndpoint::new(driver.clone(), vport, GuestDmaMode::DirectDma).await;
    let tx_config = endpoint.vport.config_tx().await.unwrap();

    let mut arena = ResourceArena::new();
    let (queue, _resources) = endpoint.new_queue(&tx_config, &mut arena, 0).await.unwrap();

    (queue, arena, endpoint)
}

#[async_test]
#[should_panic(expected = "TX CQE arrived with no matching posted TX")]
async fn tx_spurious_cqe_panics(driver: DefaultDriver) {
    use gdma_defs::bnic::CQE_TX_OKAY;

    let (mut queue, _arena, _endpoint) = new_test_queue(&driver).await;

    assert!(queue.posted_tx.is_empty());
    let mut oob = ManaTxCompOob::new_zeroed();
    oob.cqe_hdr.set_cqe_type(CQE_TX_OKAY);

    let _ = queue.handle_tx_cqe(&oob, CqeParams::new(), 8);
}

#[async_test]
async fn tx_cqe_gdma_err_returns_try_restart(driver: DefaultDriver) {
    use crate::PostedTx;
    use gdma_defs::bnic::CQE_TX_GDMA_ERR;
    use net_backend::TxError;

    let (mut queue, arena, mut endpoint) = new_test_queue(&driver).await;

    queue.posted_tx.push_back(PostedTx {
        id: TxId(42),
        wqe_len: 0,
        bounced_len_with_padding: 0,
    });

    let mut oob = ManaTxCompOob::new_zeroed();
    oob.cqe_hdr.set_cqe_type(CQE_TX_GDMA_ERR);

    // CQE_TX_GDMA_ERR returns TryRestart without popping posted_tx.
    let result = queue.handle_tx_cqe(&oob, CqeParams::new(), 8);
    assert!(
        matches!(result, Err(TxError::TryRestart(_))),
        "expected TryRestart, got {result:?}"
    );
    assert_eq!(queue.stats.tx_errors.get(), 1);
    assert_eq!(queue.stats.tx_stuck.get(), 1);
    assert_eq!(queue.posted_tx.len(), 1);

    drop(queue);
    endpoint.vport.destroy(arena).await;
    endpoint.stop().await;
}

#[async_test]
async fn tx_cqe_invalid_oob_completes_packet(driver: DefaultDriver) {
    use crate::PostedTx;
    use gdma_defs::bnic::CQE_TX_INVALID_OOB;

    let (mut queue, arena, mut endpoint) = new_test_queue(&driver).await;

    queue.posted_tx.push_back(PostedTx {
        id: TxId(7),
        wqe_len: 0,
        bounced_len_with_padding: 0,
    });

    let mut oob = ManaTxCompOob::new_zeroed();
    oob.cqe_hdr.set_cqe_type(CQE_TX_INVALID_OOB);

    // CQE_TX_INVALID_OOB logs an error but still pops posted_tx.
    let result = queue.handle_tx_cqe(&oob, CqeParams::new(), 8);
    assert_eq!(result.unwrap().0, 7);
    assert_eq!(queue.stats.tx_errors.get(), 1);
    assert!(queue.posted_tx.is_empty());

    drop(queue);
    endpoint.vport.destroy(arena).await;
    endpoint.stop().await;
}

#[async_test]
async fn tx_cqe_okay_completes_packet(driver: DefaultDriver) {
    use crate::PostedTx;
    use gdma_defs::bnic::CQE_TX_OKAY;

    let (mut queue, arena, mut endpoint) = new_test_queue(&driver).await;

    queue.posted_tx.push_back(PostedTx {
        id: TxId(99),
        wqe_len: 0,
        bounced_len_with_padding: 0,
    });

    let mut oob = ManaTxCompOob::new_zeroed();
    oob.cqe_hdr.set_cqe_type(CQE_TX_OKAY);

    let result = queue.handle_tx_cqe(&oob, CqeParams::new(), 8);
    assert_eq!(result.unwrap().0, 99);
    assert_eq!(queue.stats.tx_packets.get(), 1);
    assert!(queue.posted_tx.is_empty());

    drop(queue);
    endpoint.vport.destroy(arena).await;
    endpoint.stop().await;
}

// ---------------------------------------------------------------------------
// VLAN tests
// ---------------------------------------------------------------------------

/// Verify that a single VLAN-tagged packet round-trips through the MANA TX and
/// RX paths with the VLAN ID preserved.
#[async_test]
async fn test_vlan_tx_rx_roundtrip_direct_dma(driver: DefaultDriver) {
    let mut pkt_builder = TxPacketBuilder::new();
    build_tx_segments_vlan(1138, 1, 42, 0, false, &mut pkt_builder);

    let (stats, rx_meta) = test_endpoint(
        driver,
        GuestDmaMode::DirectDma,
        &pkt_builder,
        1, // expected TX
        1, // expected RX
        ManaTestConfiguration::default(),
    )
    .await;

    assert_eq!(stats.tx_packets.get(), 1);
    assert_eq!(stats.rx_packets.get(), 1);
    assert_eq!(stats.tx_vlan_packets.get(), 1);
    assert_eq!(stats.rx_vlan_packets.get(), 1);

    let rx_vlan = rx_meta[0]
        .expect("RX metadata should be present")
        .vlan
        .expect("RX metadata should carry VLAN");
    assert_eq!(rx_vlan.vlan_id(), 42);
    assert_eq!(rx_vlan.priority(), 0);
    assert_eq!(rx_vlan.drop_eligible_indicator(), false);
}

/// Same round-trip but with bounce-buffer DMA mode.
#[async_test]
async fn test_vlan_tx_rx_roundtrip_bounce_buffer(driver: DefaultDriver) {
    let mut pkt_builder = TxPacketBuilder::new();
    build_tx_segments_vlan(1138, 1, 99, 0, false, &mut pkt_builder);

    let (stats, rx_meta) = test_endpoint(
        driver,
        GuestDmaMode::BounceBuffer,
        &pkt_builder,
        1,
        1,
        ManaTestConfiguration::default(),
    )
    .await;

    assert_eq!(stats.tx_packets.get(), 1);
    assert_eq!(stats.rx_packets.get(), 1);
    assert_eq!(stats.tx_vlan_packets.get(), 1);
    assert_eq!(stats.rx_vlan_packets.get(), 1);

    let rx_vlan = rx_meta[0]
        .expect("RX metadata should be present")
        .vlan
        .expect("RX metadata should carry VLAN");
    assert_eq!(rx_vlan.vlan_id(), 99);
    assert_eq!(rx_vlan.priority(), 0);
    assert_eq!(rx_vlan.drop_eligible_indicator(), false);
}

/// Verify that a non-VLAN packet does NOT produce VLAN metadata.
#[async_test]
async fn test_no_vlan_rx_metadata_when_untagged(driver: DefaultDriver) {
    let mut pkt_builder = TxPacketBuilder::new();
    build_tx_segments(1138, 1, false, &mut pkt_builder);

    let (stats, rx_meta) = test_endpoint(
        driver,
        GuestDmaMode::DirectDma,
        &pkt_builder,
        1,
        1,
        ManaTestConfiguration::default(),
    )
    .await;

    assert_eq!(stats.tx_vlan_packets.get(), 0);
    assert_eq!(stats.rx_vlan_packets.get(), 0);

    let rx = rx_meta[0].expect("RX metadata should be present");
    assert!(
        rx.vlan.is_none(),
        "RX metadata must not carry VLAN for an untagged packet"
    );
}

/// Mix of VLAN-tagged and untagged packets in a single TX batch.
#[async_test]
async fn test_vlan_mixed_batch(driver: DefaultDriver) {
    let mut pkt_builder = TxPacketBuilder::new();

    // Packet 0: no VLAN
    build_tx_segments(550, 1, false, &mut pkt_builder);
    // Packet 1: VLAN 100
    build_tx_segments_vlan(550, 1, 100, 0, false, &mut pkt_builder);
    // Packet 2: no VLAN, multi-segment
    build_tx_segments(1130, 10, false, &mut pkt_builder);
    // Packet 3: VLAN 4094 (max 12-bit value)
    build_tx_segments_vlan(550, 1, 4094, 0, false, &mut pkt_builder);

    let (stats, rx_meta) = test_endpoint(
        driver,
        GuestDmaMode::DirectDma,
        &pkt_builder,
        4,
        4,
        ManaTestConfiguration::default(),
    )
    .await;

    assert_eq!(stats.tx_packets.get(), 4);
    assert_eq!(stats.rx_packets.get(), 4);
    assert_eq!(stats.tx_vlan_packets.get(), 2);
    assert_eq!(stats.rx_vlan_packets.get(), 2);

    // Packet 0: no VLAN
    assert!(
        rx_meta[0]
            .expect("RX metadata should be present")
            .vlan
            .is_none()
    );

    // Packet 1: VLAN 100
    assert_eq!(
        rx_meta[1]
            .expect("RX metadata should be present")
            .vlan
            .expect("RX should carry VLAN")
            .vlan_id(),
        100
    );
    assert_eq!(
        rx_meta[1]
            .expect("RX metadata should be present")
            .vlan
            .expect("RX should carry VLAN")
            .priority(),
        0
    );
    assert_eq!(
        rx_meta[1]
            .expect("RX metadata should be present")
            .vlan
            .expect("RX should carry VLAN")
            .drop_eligible_indicator(),
        false
    );

    // Packet 2: no VLAN
    assert!(
        rx_meta[2]
            .expect("RX metadata should be present")
            .vlan
            .is_none()
    );

    // Packet 3: VLAN 4094
    assert_eq!(
        rx_meta[3]
            .expect("RX metadata should be present")
            .vlan
            .expect("RX should carry VLAN")
            .vlan_id(),
        4094
    );
    assert_eq!(
        rx_meta[3]
            .expect("RX metadata should be present")
            .vlan
            .expect("RX should carry VLAN")
            .priority(),
        0
    );
    assert_eq!(
        rx_meta[3]
            .expect("RX metadata should be present")
            .vlan
            .expect("RX should carry VLAN")
            .drop_eligible_indicator(),
        false
    );
}

/// RX CQE coalescing: when the driver opts in (the `GDMA_MESSAGE_V2`
/// `MANA_CONFIG_VPORT_RX` request with `cqe_coalescing_enable` set) the emulator
/// packs up to `MANA_RXCOMP_OOB_NUM_PPI` receive completions that share
/// identical OOB metadata into a single `CQE_RX_COALESCED_4`, and net_mana's
/// `rx_poll` expands that one CQE back into the individual packets.
///
/// This drives four identical loopback packets through the real datapath and
/// asserts that all four are delivered AND that the coalesced-packet counter
/// advanced -- which is only possible if at least one CQE carried more than one
/// packet. Without the coalescing emitter (one CQE per packet) the counter
/// stays zero, so the `>= 2` assertion is a true regression guard.
#[async_test]
async fn rx_coalesced_cqe_delivers_batch(driver: DefaultDriver) {
    const PACKET_LEN: usize = 500;
    const NUM_PACKETS: usize = 4;

    // Build the full device stack directly (rather than via `new_test_queue`)
    // so we can capture the payload memory and drive a concrete `ManaQueue`.
    let pages = 256;
    let mem = DeviceTestMemory::new(pages * 2, true, "rx_coalesce");
    let payload_mem = mem.payload_mem();
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(LoopbackEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let dev_config = ManaQueryDeviceCfgResp {
        pf_cap_flags1: 0.into(),
        pf_cap_flags2: 0,
        pf_cap_flags3: 0,
        pf_cap_flags4: 0,
        max_num_vports: 1,
        bm_hostmode: 0,
        reserved: 0,
        max_num_eqs: 64,
        adapter_mtu: 0,
        reserved2: 0,
        adapter_link_speed_mbps: 0,
    };
    let thing = ManaDevice::new(&driver, device, 1, 1, None).await.unwrap();
    let vport = thing.new_vport(0, None, &dev_config).await.unwrap();
    let mut endpoint = ManaEndpoint::new(driver.clone(), vport, GuestDmaMode::DirectDma).await;
    let tx_config = endpoint.vport.config_tx().await.unwrap();

    let mut arena = ResourceArena::new();
    let (mut queue, resources) = endpoint.new_queue(&tx_config, &mut arena, 0).await.unwrap();

    // Opt into coalescing. This issues the V2 MANA_CONFIG_VPORT_RX request
    // (cqe_coalescing_enable = 1) and starts the receive datapath to our single
    // receive queue with coalescing armed.
    endpoint
        .vport
        .config_rx(&RxConfig {
            rx_enable: Some(true),
            rss_enable: Some(false),
            hash_key: None,
            default_rxobj: Some(resources.rxq.wq_obj()),
            indirection_table: None,
            cqe_coalescing: true,
        })
        .await
        .unwrap();

    let mut pool = net_backend::tests::Bufs::new(payload_mem.clone());

    // Post receive buffers, then send all four packets in a single batch so the
    // device reflects them through loopback before producing completions -- the
    // condition under which the emulator coalesces.
    queue.rx_avail(&mut pool, &(1..=16u32).map(RxId).collect::<Vec<_>>());

    let mut pkt_builder = TxPacketBuilder::new();
    for _ in 0..NUM_PACKETS {
        build_tx_segments(PACKET_LEN, 1, false, &mut pkt_builder);
    }
    let data_to_send = pkt_builder.packet_data();
    payload_mem.write_at(0, &data_to_send).unwrap();
    queue.tx_avail(&mut pool, pkt_builder.segments()).unwrap();

    // Poll until all four packets are received (or the deadline trips).
    let mut rx_ids = [RxId(0); NUM_PACKETS];
    let mut rx_n = 0;
    let mut tx_done = [TxId(0); NUM_PACKETS];
    let mut tx_n = 0;
    loop {
        let mut context = CancelContext::new().with_timeout(Duration::from_secs(5));
        match context
            .until_cancelled(poll_fn(|cx| queue.poll_ready(cx, &mut pool)))
            .await
        {
            Err(CancelReason::DeadlineExceeded) => break,
            Err(e) => {
                tracing::error!(error = ?e, "failed to poll queue ready");
                break;
            }
            _ => {}
        }
        rx_n += queue.rx_poll(&mut pool, &mut rx_ids[rx_n..]).unwrap();
        // GDMA errors surface as a TryRestart error here; ignore for polling.
        tx_n += queue.tx_poll(&mut pool, &mut tx_done[tx_n..]).unwrap_or(0);
        if rx_n >= NUM_PACKETS {
            break;
        }
    }

    assert_eq!(rx_n, NUM_PACKETS, "all four packets must be delivered");
    assert_eq!(
        queue.stats.rx_packets.get(),
        NUM_PACKETS as u64,
        "rx_packets counts every delivered packet"
    );
    assert!(
        queue.stats.rx_packets_coalesced.get() >= 2,
        "coalescing must pack at least two packets into one CQE (got {})",
        queue.stats.rx_packets_coalesced.get()
    );

    // Every delivered buffer must hold the exact bytes that were sent. Packets
    // are consumed in receive-buffer post order, so packet i lands in RxId(i+1).
    let mut offset = 0;
    for (i, rx_id) in rx_ids.iter().take(rx_n).enumerate() {
        assert_eq!(rx_id.0, (i + 1) as u32);
        let buffer_size = pool.capacity(*rx_id) as u64;
        let mut received = vec![0u8; PACKET_LEN];
        payload_mem
            .read_at(buffer_size * rx_id.0 as u64, &mut received)
            .unwrap();
        assert_eq!(
            received,
            data_to_send[offset..offset + PACKET_LEN],
            "payload mismatch for {rx_id:?}"
        );
        offset += PACKET_LEN;
    }

    drop(queue);
    endpoint.vport.destroy(arena).await;
    endpoint.stop().await;
}

/// Builds a minimal Ethernet + IPv4 + TCP frame for the published RSS test flow
/// (66.9.149.187:2794 -> 161.142.100.80:1766), padded to `len` bytes.
fn tcp_ipv4_frame(len: usize) -> Vec<u8> {
    let mut frame = vec![
        // Ethernet: dst MAC, src MAC, ethertype 0x0800.
        0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x08, 0x00,
        // IPv4 header (IHL=5, protocol 6 = TCP), src then dst address.
        0x45, 0x00, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 66, 9, 149, 187, 161, 142, 100, 80,
        // TCP source port 2794, destination port 1766.
        0x0a, 0xea, 0x06, 0xe6,
    ];
    frame.resize(len, 0);
    frame
}

/// RSS receive hashing (offload): when the driver enables RSS with a hash key,
/// the device computes the Toeplitz hash over each received packet's flow tuple
/// and reports it in the completion OOB. This drives a real TCP/IPv4 frame
/// through the loopback datapath with RSS enabled end to end -- exercising the
/// config_rx -> `rss_key` -> `write_data` hash wiring -- and asserts the device
/// hashed it (the `rx_packets_hashed` counter advances). Without the device-side
/// hash emitter the OOB hash type stays zero and the counter never moves, so the
/// assertion is a true regression guard. The exact hash type/value is covered by
/// the gdma-crate unit tests (`bnic::tests`, `rss::tests`).
#[async_test]
async fn rx_rss_hash_reported(driver: DefaultDriver) {
    const FRAME_LEN: usize = 60;

    // The Microsoft-standard RSS hash key (matches the published Toeplitz
    // verification vectors).
    const HASH_KEY: [u8; 40] = [
        0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f,
        0xb0, 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30,
        0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
    ];

    let pages = 256;
    let mem = DeviceTestMemory::new(pages * 2, true, "rx_rss_hash");
    let payload_mem = mem.payload_mem();
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(LoopbackEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let dev_config = ManaQueryDeviceCfgResp {
        pf_cap_flags1: 0.into(),
        pf_cap_flags2: 0,
        pf_cap_flags3: 0,
        pf_cap_flags4: 0,
        max_num_vports: 1,
        bm_hostmode: 0,
        reserved: 0,
        max_num_eqs: 64,
        adapter_mtu: 0,
        reserved2: 0,
        adapter_link_speed_mbps: 0,
    };
    let thing = ManaDevice::new(&driver, device, 1, 1, None).await.unwrap();
    let vport = thing.new_vport(0, None, &dev_config).await.unwrap();
    let mut endpoint = ManaEndpoint::new(driver.clone(), vport, GuestDmaMode::DirectDma).await;
    let tx_config = endpoint.vport.config_tx().await.unwrap();

    let mut arena = ResourceArena::new();
    let (mut queue, resources) = endpoint.new_queue(&tx_config, &mut arena, 0).await.unwrap();

    // Enable RSS with the standard hash key. This issues MANA_CONFIG_VPORT_RX
    // with rss_enable=TRUE plus the key, so the device arms receive-side hashing
    // on the datapath to our single receive queue (no custom indirection table).
    endpoint
        .vport
        .config_rx(&RxConfig {
            rx_enable: Some(true),
            rss_enable: Some(true),
            hash_key: Some(&HASH_KEY),
            default_rxobj: Some(resources.rxq.wq_obj()),
            indirection_table: None,
            cqe_coalescing: false,
        })
        .await
        .unwrap();

    let mut pool = net_backend::tests::Bufs::new(payload_mem.clone());

    // Post a receive buffer, then transmit one real TCP/IPv4 frame; loopback
    // reflects it into the receive path where the device hashes it.
    queue.rx_avail(&mut pool, &[RxId(1)]);

    let frame = tcp_ipv4_frame(FRAME_LEN);
    payload_mem.write_at(0, &frame).unwrap();
    let tx_metadata = net_backend::TxMetadata {
        id: TxId(1),
        segment_count: 1,
        len: FRAME_LEN as u32,
        l2_len: 14,
        l3_len: 20,
        l4_len: 20,
        max_segment_size: 1460,
        ..Default::default()
    };
    queue
        .tx_avail(
            &mut pool,
            &[TxSegment {
                ty: net_backend::TxSegmentType::Head(tx_metadata),
                gpa: 0,
                len: FRAME_LEN as u32,
            }],
        )
        .unwrap();

    // Poll until the frame is received (or the deadline trips).
    let mut rx_ids = [RxId(0); 1];
    let mut rx_n = 0;
    loop {
        let mut context = CancelContext::new().with_timeout(Duration::from_secs(5));
        match context
            .until_cancelled(poll_fn(|cx| queue.poll_ready(cx, &mut pool)))
            .await
        {
            Err(CancelReason::DeadlineExceeded) => break,
            Err(e) => {
                tracing::error!(error = ?e, "failed to poll queue ready");
                break;
            }
            _ => {}
        }
        rx_n += queue.rx_poll(&mut pool, &mut rx_ids[rx_n..]).unwrap();
        let mut tx_done = [TxId(0); 1];
        let _ = queue.tx_poll(&mut pool, &mut tx_done).unwrap_or(0);
        if rx_n >= 1 {
            break;
        }
    }

    assert_eq!(rx_n, 1, "the frame must be delivered");
    assert_eq!(
        queue.stats.rx_packets_hashed.get(),
        1,
        "the device must report an RSS hash for the received TCP/IPv4 frame"
    );

    drop(queue);
    endpoint.vport.destroy(arena).await;
    endpoint.stop().await;
}

/// RX CQE coalescing live toggle: enabling coalescing on an already-running
/// vport must take effect on the live datapath WITHOUT cycling it.
///
/// This models the `ethtool -C eth0 rx-frames 4` path. On a running port the
/// driver re-issues `MANA_CONFIG_VPORT_RX` (`rx_enable=TRUE`) with
/// `cqe_coalescing_enable=1` but `update_indir_tab=0` / `update_hashkey=0`, so
/// the device must not rebuild the datapath (that would drop the live RSS
/// table) -- it instead flips the coalescing flag the running receive tasks
/// share. The test starts the datapath with coalescing OFF, toggles it ON via a
/// second `config_rx` that carries no indirection table, then drives a batch and
/// asserts it was coalesced. If the running task did not observe the toggle it
/// would deliver one CQE per packet (coalesced counter stays zero), so the
/// `>= 2` assertion is a true regression guard for the shared-flag behavior.
#[async_test]
async fn rx_coalescing_live_toggle_engages_without_rebuild(driver: DefaultDriver) {
    const PACKET_LEN: usize = 500;
    const NUM_PACKETS: usize = 4;

    let pages = 256;
    let mem = DeviceTestMemory::new(pages * 2, true, "rx_coalesce_toggle");
    let payload_mem = mem.payload_mem();
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(LoopbackEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let dev_config = ManaQueryDeviceCfgResp {
        pf_cap_flags1: 0.into(),
        pf_cap_flags2: 0,
        pf_cap_flags3: 0,
        pf_cap_flags4: 0,
        max_num_vports: 1,
        bm_hostmode: 0,
        reserved: 0,
        max_num_eqs: 64,
        adapter_mtu: 0,
        reserved2: 0,
        adapter_link_speed_mbps: 0,
    };
    let thing = ManaDevice::new(&driver, device, 1, 1, None).await.unwrap();
    let vport = thing.new_vport(0, None, &dev_config).await.unwrap();
    let mut endpoint = ManaEndpoint::new(driver.clone(), vport, GuestDmaMode::DirectDma).await;
    let tx_config = endpoint.vport.config_tx().await.unwrap();

    let mut arena = ResourceArena::new();
    let (mut queue, resources) = endpoint.new_queue(&tx_config, &mut arena, 0).await.unwrap();

    // Start the receive datapath with coalescing OFF (the V1 request form). The
    // device builds its receive task capturing the disabled flag.
    endpoint
        .vport
        .config_rx(&RxConfig {
            rx_enable: Some(true),
            rss_enable: Some(false),
            hash_key: None,
            default_rxobj: Some(resources.rxq.wq_obj()),
            indirection_table: None,
            cqe_coalescing: false,
        })
        .await
        .unwrap();

    // Live toggle: re-issue config on the already-running vport with coalescing
    // ON and no indirection table. This sends update_indir_tab=0 /
    // update_hashkey=0, so the device must NOT rebuild the datapath -- it must
    // flip the flag the running task already shares.
    endpoint
        .vport
        .config_rx(&RxConfig {
            rx_enable: Some(true),
            rss_enable: Some(false),
            hash_key: None,
            default_rxobj: Some(resources.rxq.wq_obj()),
            indirection_table: None,
            cqe_coalescing: true,
        })
        .await
        .unwrap();

    let mut pool = net_backend::tests::Bufs::new(payload_mem.clone());

    // Post receive buffers, then send all four packets in a single batch so the
    // device reflects them through loopback before producing completions -- the
    // condition under which the emulator coalesces.
    queue.rx_avail(&mut pool, &(1..=16u32).map(RxId).collect::<Vec<_>>());

    let mut pkt_builder = TxPacketBuilder::new();
    for _ in 0..NUM_PACKETS {
        build_tx_segments(PACKET_LEN, 1, false, &mut pkt_builder);
    }
    let data_to_send = pkt_builder.packet_data();
    payload_mem.write_at(0, &data_to_send).unwrap();
    queue.tx_avail(&mut pool, pkt_builder.segments()).unwrap();

    // Poll until all four packets are received (or the deadline trips).
    let mut rx_ids = [RxId(0); NUM_PACKETS];
    let mut rx_n = 0;
    let mut tx_done = [TxId(0); NUM_PACKETS];
    let mut tx_n = 0;
    loop {
        let mut context = CancelContext::new().with_timeout(Duration::from_secs(5));
        match context
            .until_cancelled(poll_fn(|cx| queue.poll_ready(cx, &mut pool)))
            .await
        {
            Err(CancelReason::DeadlineExceeded) => break,
            Err(e) => {
                tracing::error!(error = ?e, "failed to poll queue ready");
                break;
            }
            _ => {}
        }
        rx_n += queue.rx_poll(&mut pool, &mut rx_ids[rx_n..]).unwrap();
        tx_n += queue.tx_poll(&mut pool, &mut tx_done[tx_n..]).unwrap_or(0);
        if rx_n >= NUM_PACKETS {
            break;
        }
    }

    assert_eq!(rx_n, NUM_PACKETS, "all four packets must be delivered");
    assert!(
        queue.stats.rx_packets_coalesced.get() >= 2,
        "the live coalescing toggle must engage on the running datapath \
         (coalesced packets: {})",
        queue.stats.rx_packets_coalesced.get()
    );

    drop(queue);
    endpoint.vport.destroy(arena).await;
    endpoint.stop().await;
}

/// Per-queue state inside the [`SteeringSwitch`].
#[derive(Default)]
struct SteeringQueueState {
    /// Receive buffers the device has made available on this queue.
    rx_avail: VecDeque<RxId>,
    /// Packets steered to this queue, waiting for a receive buffer.
    pending: VecDeque<(Vec<u8>, Option<VlanMetadata>)>,
    /// Waker for the datapath task servicing this queue.
    waker: Option<Waker>,
}

/// Shared state for the [`SteeringEndpoint`] test backend.
///
/// Models the PF / physical wire: it owns the resolved RSS indirection table
/// and steers each transmitted frame onto a receive queue accordingly.
struct SteeringSwitch {
    /// Indirection table as resolved by the device: bucket -> receive queue
    /// index. Recorded from the [`RssConfig`] handed to `get_queues`.
    indir: Vec<u16>,
    queues: Vec<SteeringQueueState>,
}

/// A test backend that steers transmitted frames to a receive queue chosen by
/// the RSS indirection table, using the first packet byte as the hash bucket.
#[derive(InspectMut)]
#[inspect(skip)]
struct SteeringEndpoint {
    switch: Arc<Mutex<SteeringSwitch>>,
}

impl SteeringEndpoint {
    fn new(switch: Arc<Mutex<SteeringSwitch>>) -> Self {
        Self { switch }
    }
}

#[async_trait]
impl Endpoint for SteeringEndpoint {
    fn endpoint_type(&self) -> &'static str {
        "steering-test"
    }

    async fn get_queues(
        &mut self,
        config: Vec<QueueConfig>,
        rss: Option<&RssConfig<'_>>,
        queues: &mut Vec<Box<dyn Queue>>,
    ) -> anyhow::Result<()> {
        {
            let mut switch = self.switch.lock();
            switch.indir = rss
                .map(|r| r.indirection_table.to_vec())
                .unwrap_or_default();
            switch.queues.clear();
            switch.queues.resize_with(config.len(), Default::default);
        }
        for index in 0..config.len() {
            queues.push(Box::new(SteeringQueue {
                switch: self.switch.clone(),
                index,
            }));
        }
        Ok(())
    }

    async fn stop(&mut self) {}

    fn is_ordered(&self) -> bool {
        true
    }

    fn multiqueue_support(&self) -> MultiQueueSupport {
        MultiQueueSupport {
            max_queues: 8,
            indirection_table_size: 128,
        }
    }
}

#[derive(InspectMut)]
#[inspect(skip)]
struct SteeringQueue {
    switch: Arc<Mutex<SteeringSwitch>>,
    index: usize,
}

impl Queue for SteeringQueue {
    fn poll_ready(&mut self, cx: &mut Context<'_>, _pool: &mut dyn BufferAccess) -> Poll<()> {
        let mut switch = self.switch.lock();
        let q = &mut switch.queues[self.index];
        if !q.pending.is_empty() && !q.rx_avail.is_empty() {
            Poll::Ready(())
        } else {
            q.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    fn rx_avail(&mut self, _pool: &mut dyn BufferAccess, done: &[RxId]) {
        let mut switch = self.switch.lock();
        switch.queues[self.index]
            .rx_avail
            .extend(done.iter().copied());
    }

    fn rx_poll(
        &mut self,
        pool: &mut dyn BufferAccess,
        packets: &mut [RxId],
    ) -> anyhow::Result<usize> {
        let mut switch = self.switch.lock();
        let mut n = 0;
        while n < packets.len() {
            let q = &mut switch.queues[self.index];
            if q.pending.is_empty() || q.rx_avail.is_empty() {
                break;
            }
            let rx_id = q.rx_avail.pop_front().unwrap();
            let (data, vlan) = q.pending.pop_front().unwrap();
            pool.write_packet(
                rx_id,
                &net_backend::RxMetadata {
                    offset: 0,
                    len: data.len(),
                    vlan,
                    ..Default::default()
                },
                &data,
            );
            packets[n] = rx_id;
            n += 1;
        }
        Ok(n)
    }

    fn tx_avail(
        &mut self,
        pool: &mut dyn BufferAccess,
        mut segments: &[TxSegment],
    ) -> anyhow::Result<(bool, usize)> {
        let mut sent = 0;
        while !segments.is_empty() {
            let (meta, _, _) = next_packet(segments);
            let vlan = meta.vlan;
            let before = segments.len();
            let data = linearize(pool, &mut segments)?;
            sent += before - segments.len();

            let mut switch = self.switch.lock();
            // Use the first packet byte as the hash bucket so tests can steer
            // deterministically. With no indirection table, fall back to the
            // transmitting queue (loopback).
            let target = if switch.indir.is_empty() {
                self.index
            } else {
                let bucket = data.first().copied().unwrap_or(0) as usize;
                switch.indir[bucket % switch.indir.len()] as usize
            };
            let q = &mut switch.queues[target];
            q.pending.push_back((data, vlan));
            if let Some(waker) = q.waker.take() {
                waker.wake();
            }
        }
        Ok((true, sent))
    }

    fn tx_poll(
        &mut self,
        _pool: &mut dyn BufferAccess,
        _done: &mut [TxId],
    ) -> Result<usize, net_backend::TxError> {
        Ok(0)
    }
}

/// Drives every queue until a single steered receive lands, returning the index
/// of the queue that received it. Panics on timeout.
async fn poll_for_steered_rx(
    queues: &mut [Box<dyn Queue>],
    pool: &mut net_backend::tests::Bufs,
) -> usize {
    loop {
        let mut context = CancelContext::new().with_timeout(Duration::from_secs(5));
        if context
            .until_cancelled(poll_fn(|cx| {
                let mut ready = Poll::Pending;
                for q in queues.iter_mut() {
                    if q.poll_ready(cx, &mut *pool).is_ready() {
                        ready = Poll::Ready(());
                    }
                }
                ready
            }))
            .await
            .is_err()
        {
            panic!("timed out waiting for steered receive");
        }

        for q in queues.iter_mut() {
            let mut tx_done = [TxId(0); 4];
            let _ = q.tx_poll(&mut *pool, &mut tx_done);
        }

        for (k, q) in queues.iter_mut().enumerate() {
            let mut rx = [RxId(0)];
            if q.rx_poll(&mut *pool, &mut rx).unwrap() > 0 {
                return k;
            }
        }
    }
}

/// Verifies that the device advertises multiple receive queues, translates the
/// guest's RSS indirection table (work-queue object handles) back into receive
/// queue indices, and steers each frame to the queue named by the table.
#[async_test]
async fn test_rss_steering_distributes_across_queues(driver: DefaultDriver) {
    const NUM_QUEUES: usize = 4;
    // Non-identity table so a mistranslation (e.g. identity) is caught:
    // bucket b is steered to queue INDIR[b].
    const INDIR: [u16; NUM_QUEUES] = [3, 2, 1, 0];

    let pages = 256; // 1MB
    let mem = DeviceTestMemory::new(pages * 2, true, "test_rss_steering");
    let payload_mem = mem.payload_mem();

    let switch = Arc::new(Mutex::new(SteeringSwitch {
        indir: Vec::new(),
        queues: Vec::new(),
    }));

    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(SteeringEndpoint::new(switch.clone())),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let dev_config = ManaQueryDeviceCfgResp {
        pf_cap_flags1: 0.into(),
        pf_cap_flags2: 0,
        pf_cap_flags3: 0,
        pf_cap_flags4: 0,
        max_num_vports: 1,
        bm_hostmode: 0,
        reserved: 0,
        max_num_eqs: 64,
        adapter_mtu: 0,
        reserved2: 0,
        adapter_link_speed_mbps: 0,
    };
    let thing = ManaDevice::new(&driver, device, 1, NUM_QUEUES as u16, None)
        .await
        .unwrap();
    let vport = thing.new_vport(0, None, &dev_config).await.unwrap();
    let mut endpoint = ManaEndpoint::new(driver.clone(), vport, GuestDmaMode::DirectDma).await;

    let mut queues = Vec::new();
    let mut pool = net_backend::tests::Bufs::new(payload_mem.clone());
    let key = [0u8; 40];
    endpoint
        .get_queues(
            (0..NUM_QUEUES)
                .map(|_| QueueConfig {
                    driver: Box::new(driver.clone()),
                })
                .collect(),
            Some(&RssConfig {
                key: &key,
                indirection_table: &INDIR,
                flags: 0,
            }),
            &mut queues,
        )
        .await
        .unwrap();
    assert_eq!(queues.len(), NUM_QUEUES);

    // The device must resolve the guest's handle-based indirection table back
    // into receive queue indices before handing it to the backend.
    assert_eq!(switch.lock().indir, INDIR.to_vec());

    // Give each queue a disjoint range of receive buffer ids so the buffer that
    // receives a frame identifies the queue it landed on. `Bufs` maps id ->
    // payload offset id*2048; offset 0 is reserved as transmit scratch.
    const BUFS_PER_QUEUE: u32 = 8;
    for (q, queue) in queues.iter_mut().enumerate() {
        let base = q as u32 * BUFS_PER_QUEUE + 1;
        let ids: Vec<RxId> = (base..base + BUFS_PER_QUEUE).map(RxId).collect();
        queue.rx_avail(&mut pool, &ids);
    }

    // For each bucket, transmit a one-segment frame whose first byte selects the
    // bucket, always from queue 0, and confirm the device steers it onto the
    // queue named by the indirection table.
    for (bucket, &target_queue) in INDIR.iter().enumerate() {
        let mut packet = vec![0u8; 64];
        packet[0] = bucket as u8;
        payload_mem.write_at(0, &packet).unwrap();

        let seg = TxSegment {
            ty: net_backend::TxSegmentType::Head(net_backend::TxMetadata {
                id: TxId(1),
                segment_count: 1,
                len: packet.len() as u32,
                ..Default::default()
            }),
            gpa: 0,
            len: packet.len() as u32,
        };
        queues[0].tx_avail(&mut pool, &[seg]).unwrap();

        let received_on = poll_for_steered_rx(&mut queues, &mut pool).await;
        assert_eq!(
            received_on, target_queue as usize,
            "bucket {bucket} should steer to queue {target_queue}",
        );
    }

    drop(queues);
    endpoint.stop().await;
}

/// A single-queue loopback backend that completes transmits **asynchronously**
/// and echoes the transmit id, modelling the `consomme` NAT backend whose state
/// is single-owner (`tx_avail` returns `(false, ..)` and the completion, with
/// the echoed transmit id, is reported later via `tx_poll`). `get_queues`
/// returns an error if asked for more than one queue -- the real consomme
/// backend asserts, which would panic the device's datapath thread; an error is
/// used here so the failure is deterministic in a test.
#[derive(InspectMut)]
#[inspect(skip)]
struct SingleQueueLoopbackEndpoint;

#[async_trait]
impl Endpoint for SingleQueueLoopbackEndpoint {
    fn endpoint_type(&self) -> &'static str {
        "single-queue-loopback-test"
    }

    async fn get_queues(
        &mut self,
        config: Vec<QueueConfig>,
        _rss: Option<&RssConfig<'_>>,
        queues: &mut Vec<Box<dyn Queue>>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            config.len() == 1,
            "single-queue backend asked for {} queues",
            config.len()
        );
        queues.push(Box::new(AsyncLoopbackQueue::default()));
        Ok(())
    }

    async fn stop(&mut self) {}

    fn is_ordered(&self) -> bool {
        true
    }

    fn multiqueue_support(&self) -> MultiQueueSupport {
        MultiQueueSupport {
            max_queues: 1,
            indirection_table_size: 64,
        }
    }
}

/// Loopback queue that defers transmit completion to `tx_poll` and echoes the
/// transmit id, exactly as the consomme backend does. This exercises the
/// device's asynchronous transmit-completion path (`process_backend`), where the
/// funnel must route the completion back to the send queue named by the echoed
/// transmit id.
#[derive(InspectMut, Default)]
#[inspect(skip)]
struct AsyncLoopbackQueue {
    rx_avail: VecDeque<RxId>,
    rx_done: VecDeque<RxId>,
    tx_done: VecDeque<TxId>,
}

impl Queue for AsyncLoopbackQueue {
    fn poll_ready(&mut self, _cx: &mut Context<'_>, _pool: &mut dyn BufferAccess) -> Poll<()> {
        if self.rx_done.is_empty() && self.tx_done.is_empty() {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }

    fn rx_avail(&mut self, _pool: &mut dyn BufferAccess, done: &[RxId]) {
        self.rx_avail.extend(done);
    }

    fn rx_poll(
        &mut self,
        _pool: &mut dyn BufferAccess,
        packets: &mut [RxId],
    ) -> anyhow::Result<usize> {
        let n = packets.len().min(self.rx_done.len());
        for (d, s) in packets.iter_mut().zip(self.rx_done.drain(..n)) {
            *d = s;
        }
        Ok(n)
    }

    fn tx_avail(
        &mut self,
        pool: &mut dyn BufferAccess,
        mut segments: &[TxSegment],
    ) -> anyhow::Result<(bool, usize)> {
        let mut sent = 0;
        while !segments.is_empty() {
            let (meta, _, _) = next_packet(segments);
            let tx_id = meta.id;
            let vlan = meta.vlan;
            let before = segments.len();
            let packet = linearize(pool, &mut segments)?;
            sent += before - segments.len();
            if let Some(rx_id) = self.rx_avail.pop_front() {
                pool.write_packet(
                    rx_id,
                    &net_backend::RxMetadata {
                        offset: 0,
                        len: packet.len(),
                        vlan,
                        ..Default::default()
                    },
                    &packet,
                );
                self.rx_done.push_back(rx_id);
            }
            // Report the completion asynchronously (via `tx_poll`), echoing the
            // transmit id, as consomme does.
            self.tx_done.push_back(tx_id);
        }
        Ok((false, sent))
    }

    fn tx_poll(
        &mut self,
        _pool: &mut dyn BufferAccess,
        done: &mut [TxId],
    ) -> Result<usize, net_backend::TxError> {
        let n = done.len().min(self.tx_done.len());
        for (d, s) in done.iter_mut().zip(self.tx_done.drain(..n)) {
            *d = s;
        }
        Ok(n)
    }
}

/// The Windows VF driver creates one queue pair per CPU regardless of the
/// per-vport `max_num_sq`/`max_num_rq` the device advertises, so it can create
/// more queue pairs than a single-queue backend (like the `consomme` NAT
/// backend) can service. Rather than requesting one backend queue per guest
/// queue pair -- which a single-queue backend rejects (the real consomme
/// backend panics its datapath thread) -- the device must funnel the guest's
/// surplus queue pairs onto the backend's available queues.
///
/// This drives that funnel: two guest queue pairs against a single-queue
/// loopback backend. It transmits from the *non-primary* send queue (queue 1)
/// and asserts (a) the transmit completes on queue 1's own completion queue --
/// proving the transmit was funneled onto the single backend queue and its
/// completion routed back by the source send queue -- and (b) the looped-back
/// packet is received on the primary receive queue (queue 0), where a
/// single-backend-queue funnel delivers all receives.
///
/// Without the funnel the device requests two backend queues from the
/// single-queue endpoint, `get_queues` fails, and `MANA_CONFIG_VPORT_RX` (hence
/// `get_queues` below) errors -- a genuine regression guard.
#[async_test]
async fn funnel_multi_queue_onto_single_queue_backend(driver: DefaultDriver) {
    let pages = 256; // 1MB
    let mem = DeviceTestMemory::new(pages * 2, true, "funnel_multi_queue");
    let payload_mem = mem.payload_mem();

    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(SingleQueueLoopbackEndpoint),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let dev_config = ManaQueryDeviceCfgResp {
        pf_cap_flags1: 0.into(),
        pf_cap_flags2: 0,
        pf_cap_flags3: 0,
        pf_cap_flags4: 0,
        max_num_vports: 1,
        bm_hostmode: 0,
        reserved: 0,
        max_num_eqs: 64,
        adapter_mtu: 0,
        reserved2: 0,
        adapter_link_speed_mbps: 0,
    };
    let thing = ManaDevice::new(&driver, device, 1, 2, None).await.unwrap();
    let vport = thing.new_vport(0, None, &dev_config).await.unwrap();
    let mut endpoint = ManaEndpoint::new(driver.clone(), vport, GuestDmaMode::DirectDma).await;

    // Create *two* queue pairs even though the backend advertises a single
    // queue -- exactly what the Windows VF driver does. Without the funnel the
    // device would ask the single-queue backend for two queues and this fails.
    let mut queues = Vec::new();
    let mut pool = net_backend::tests::Bufs::new(payload_mem.clone());
    endpoint
        .get_queues(
            (0..2)
                .map(|_| QueueConfig {
                    driver: Box::new(driver.clone()),
                })
                .collect(),
            None,
            &mut queues,
        )
        .await
        .unwrap();
    assert_eq!(queues.len(), 2);

    // Post receive buffers on the *primary* receive queue (queue 0). With a
    // single backend queue the funnel delivers every received packet there; the
    // surplus queue's posted buffers stay idle.
    queues[0].rx_avail(&mut pool, &(1..8u32).map(RxId).collect::<Vec<_>>());

    // Transmit a one-segment frame from the *non-primary* send queue (queue 1).
    let packet = {
        let mut p = vec![0u8; 64];
        p[0] = 0xb1;
        p
    };
    payload_mem.write_at(0, &packet).unwrap();
    let seg = TxSegment {
        ty: net_backend::TxSegmentType::Head(net_backend::TxMetadata {
            id: TxId(7),
            segment_count: 1,
            len: packet.len() as u32,
            ..Default::default()
        }),
        gpa: 0,
        len: packet.len() as u32,
    };
    queues[1].tx_avail(&mut pool, &[seg]).unwrap();

    // Poll for the transmit completion on queue 1 and the looped-back receive on
    // queue 0.
    let mut tx_completed = false;
    let mut rx_received: Option<RxId> = None;
    let mut spurious_tx_on_primary = false;
    loop {
        let mut ctx = CancelContext::new().with_timeout(Duration::from_secs(5));
        if ctx
            .until_cancelled(poll_fn(|cx| {
                let mut ready = Poll::Pending;
                for q in queues.iter_mut() {
                    if q.poll_ready(cx, &mut pool).is_ready() {
                        ready = Poll::Ready(());
                    }
                }
                ready
            }))
            .await
            .is_err()
        {
            break;
        }

        let mut tx_done = [TxId(0); 4];
        if queues[1].tx_poll(&mut pool, &mut tx_done).unwrap_or(0) > 0 {
            tx_completed = true;
        }
        // The transmit came from queue 1, so its completion must not land on
        // queue 0's completion queue.
        if queues[0].tx_poll(&mut pool, &mut tx_done).unwrap_or(0) > 0 {
            spurious_tx_on_primary = true;
        }

        let mut rx = [RxId(0)];
        if queues[0].rx_poll(&mut pool, &mut rx).unwrap() > 0 {
            rx_received = Some(rx[0]);
        }

        if tx_completed && rx_received.is_some() {
            break;
        }
    }

    assert!(
        tx_completed,
        "transmit from the non-primary send queue did not complete on its own completion queue"
    );
    assert!(
        !spurious_tx_on_primary,
        "transmit completion was misrouted to the primary send queue"
    );
    let rx_id =
        rx_received.expect("looped-back packet was not delivered to the primary receive queue");

    // Confirm the received bytes match what was transmitted from queue 1.
    let buffer_size = pool.capacity(rx_id) as u64;
    let mut received = vec![0u8; packet.len()];
    payload_mem
        .read_at(buffer_size * rx_id.0 as u64, &mut received)
        .unwrap();
    assert_eq!(received, packet);

    drop(queues);
    endpoint.stop().await;
}

/// (the emulator's receive task) can make progress while the test holds no
/// pending future of its own.
async fn run_executor_for(ms: u64) {
    let mut ctx = CancelContext::new().with_timeout(Duration::from_millis(ms));
    let _ = ctx.until_cancelled(std::future::pending::<()>()).await;
}

/// A `MANA_FENCE_RQ` is an ordering barrier, not a packet: the device posts a
/// bare `CQE_RX_OBJECT_FENCE` that consumes no posted receive buffer. This test
/// fences a receive object with buffers posted but no traffic, then asserts
/// net_mana's `rx_poll` reports the fence (via the `rx_fence` counter) without
/// delivering a packet and, crucially, without recording a receive error --
/// which is what happens if the fence falls through to the catch-all CQE arm
/// (it pops a `posted_rx` and increments `rx_errors`). That makes `rx_errors ==
/// 0` a regression guard for the dedicated fence arm.
#[async_test]
async fn rx_fence_cqe_is_bare_completion(driver: DefaultDriver) {
    let pages = 256;
    let mem = DeviceTestMemory::new(pages * 2, true, "rx_fence_bare");
    let payload_mem = mem.payload_mem();
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(LoopbackEndpoint::new()),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let dev_config = ManaQueryDeviceCfgResp {
        pf_cap_flags1: 0.into(),
        pf_cap_flags2: 0,
        pf_cap_flags3: 0,
        pf_cap_flags4: 0,
        max_num_vports: 1,
        bm_hostmode: 0,
        reserved: 0,
        max_num_eqs: 64,
        adapter_mtu: 0,
        reserved2: 0,
        adapter_link_speed_mbps: 0,
    };
    let thing = ManaDevice::new(&driver, device, 1, 1, None).await.unwrap();
    let vport = thing.new_vport(0, None, &dev_config).await.unwrap();
    let mut endpoint = ManaEndpoint::new(driver.clone(), vport, GuestDmaMode::DirectDma).await;
    let tx_config = endpoint.vport.config_tx().await.unwrap();

    let mut arena = ResourceArena::new();
    let (mut queue, resources) = endpoint.new_queue(&tx_config, &mut arena, 0).await.unwrap();

    endpoint
        .vport
        .config_rx(&RxConfig {
            rx_enable: Some(true),
            rss_enable: Some(false),
            hash_key: None,
            default_rxobj: Some(resources.rxq.wq_obj()),
            indirection_table: None,
            cqe_coalescing: false,
        })
        .await
        .unwrap();

    let mut pool = net_backend::tests::Bufs::new(payload_mem.clone());

    // Post receive buffers so there is a non-empty posted_rx that the fence
    // would (incorrectly) consume if it were treated as a packet completion.
    queue.rx_avail(&mut pool, &(1..=16u32).map(RxId).collect::<Vec<_>>());

    // Fence the receive object. The device posts a single CQE_RX_OBJECT_FENCE.
    endpoint
        .vport
        .fence_rq(resources.rxq.wq_obj())
        .await
        .unwrap();

    // Drive the queue until the fence CQE is processed (or the deadline trips).
    let mut rx_ids = [RxId(0); 8];
    let mut rx_n = 0;
    loop {
        let mut context = CancelContext::new().with_timeout(Duration::from_secs(5));
        if context
            .until_cancelled(poll_fn(|cx| queue.poll_ready(cx, &mut pool)))
            .await
            .is_err()
        {
            break;
        }
        rx_n += queue.rx_poll(&mut pool, &mut rx_ids[rx_n..]).unwrap();
        let _ = queue.tx_poll(&mut pool, &mut [TxId(0); 1]);
        if queue.stats.rx_fence.get() + queue.stats.rx_errors.get() >= 1 || rx_n > 0 {
            break;
        }
    }

    assert_eq!(
        queue.stats.rx_fence.get(),
        1,
        "the fence CQE must signal exactly one fence"
    );
    assert_eq!(rx_n, 0, "a fence carries no packet");
    assert_eq!(
        queue.stats.rx_packets.get(),
        0,
        "a fence delivers no packets"
    );
    assert_eq!(
        queue.stats.rx_errors.get(),
        0,
        "a fence is a barrier, not a receive error"
    );

    drop(queue);
    endpoint.vport.destroy(arena).await;
    endpoint.stop().await;
}

/// Backend state for [`FenceOrderEndpoint`]. Receive completions are injected
/// by the test (via `staged`) rather than produced from transmitted frames, and
/// -- unlike a loopback backend -- staging does NOT wake the device's receive
/// task. That leaves staged receives "ready but unposted" until something else
/// wakes the task, which is exactly the window a fence must not jump.
#[derive(Default)]
struct FenceOrderState {
    /// Receive buffers the device has handed to the backend.
    buffers: VecDeque<RxId>,
    /// Number of identical packets staged to complete on the next poll.
    staged: usize,
    /// Bytes written into each completed receive buffer.
    packet: Vec<u8>,
    /// Waker registered by the device's receive task. The test never fires it,
    /// so staging is silent.
    waker: Option<Waker>,
}

/// A test backend whose receive completions are staged out-of-band by the test
/// without waking the device's receive task, used to prove the fence is posted
/// after in-flight receives.
#[derive(InspectMut)]
#[inspect(skip)]
struct FenceOrderEndpoint {
    state: Arc<Mutex<FenceOrderState>>,
}

#[async_trait]
impl Endpoint for FenceOrderEndpoint {
    fn endpoint_type(&self) -> &'static str {
        "fence-order-test"
    }

    async fn get_queues(
        &mut self,
        config: Vec<QueueConfig>,
        _rss: Option<&RssConfig<'_>>,
        queues: &mut Vec<Box<dyn Queue>>,
    ) -> anyhow::Result<()> {
        for _ in 0..config.len() {
            queues.push(Box::new(FenceOrderQueue {
                state: self.state.clone(),
            }));
        }
        Ok(())
    }

    async fn stop(&mut self) {}

    fn is_ordered(&self) -> bool {
        true
    }

    fn multiqueue_support(&self) -> MultiQueueSupport {
        MultiQueueSupport {
            max_queues: 1,
            indirection_table_size: 128,
        }
    }
}

#[derive(InspectMut)]
#[inspect(skip)]
struct FenceOrderQueue {
    state: Arc<Mutex<FenceOrderState>>,
}

impl Queue for FenceOrderQueue {
    fn poll_ready(&mut self, cx: &mut Context<'_>, _pool: &mut dyn BufferAccess) -> Poll<()> {
        let mut state = self.state.lock();
        if state.staged > 0 && !state.buffers.is_empty() {
            Poll::Ready(())
        } else {
            state.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    fn rx_avail(&mut self, _pool: &mut dyn BufferAccess, done: &[RxId]) {
        self.state.lock().buffers.extend(done.iter().copied());
    }

    fn rx_poll(
        &mut self,
        pool: &mut dyn BufferAccess,
        packets: &mut [RxId],
    ) -> anyhow::Result<usize> {
        let mut state = self.state.lock();
        let mut n = 0;
        while n < packets.len() && state.staged > 0 && !state.buffers.is_empty() {
            let rx_id = state.buffers.pop_front().unwrap();
            let data = state.packet.clone();
            pool.write_packet(
                rx_id,
                &net_backend::RxMetadata {
                    offset: 0,
                    len: data.len(),
                    ..Default::default()
                },
                &data,
            );
            state.staged -= 1;
            packets[n] = rx_id;
            n += 1;
        }
        Ok(n)
    }

    fn tx_avail(
        &mut self,
        _pool: &mut dyn BufferAccess,
        segments: &[TxSegment],
    ) -> anyhow::Result<(bool, usize)> {
        let sent = segments
            .iter()
            .filter(|s| matches!(s.ty, net_backend::TxSegmentType::Head(_)))
            .count();
        Ok((true, sent))
    }

    fn tx_poll(
        &mut self,
        _pool: &mut dyn BufferAccess,
        _done: &mut [TxId],
    ) -> Result<usize, net_backend::TxError> {
        Ok(0)
    }
}

/// The fence is a drain barrier: a `CQE_RX_OBJECT_FENCE` must be posted strictly
/// after every receive completion the device has already produced for the
/// queue. This stages four receives that are ready in the backend but not yet
/// posted (and that do NOT wake the receive task), fences the queue, and asserts
/// that by the time net_mana observes the fence it has already delivered all
/// four packets. If the device posts the fence inline (the pre-barrier
/// behavior) the receive task is never woken to drain the staged receives, so
/// the fence is observed with zero packets delivered -- a true regression guard.
#[async_test]
async fn rx_fence_orders_after_inflight_receives(driver: DefaultDriver) {
    const NUM_PACKETS: usize = 4;
    const PACKET_LEN: usize = 64;

    let state = Arc::new(Mutex::new(FenceOrderState {
        packet: vec![0xAB; PACKET_LEN],
        ..Default::default()
    }));

    let pages = 256;
    let mem = DeviceTestMemory::new(pages * 2, true, "rx_fence_order");
    let payload_mem = mem.payload_mem();
    let msi_conn = MsiConnection::new(AssignedBusRange::new(), 0);
    let device = gdma::GdmaDevice::new(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        mem.guest_memory(),
        msi_conn.target(),
        vec![VportConfig {
            mac_address: [1, 2, 3, 4, 5, 6].into(),
            endpoint: Box::new(FenceOrderEndpoint {
                state: state.clone(),
            }),
        }],
        &mut ExternallyManagedMmioIntercepts,
    );
    let device = EmulatedDevice::new(device, msi_conn, mem.dma_client());
    let dev_config = ManaQueryDeviceCfgResp {
        pf_cap_flags1: 0.into(),
        pf_cap_flags2: 0,
        pf_cap_flags3: 0,
        pf_cap_flags4: 0,
        max_num_vports: 1,
        bm_hostmode: 0,
        reserved: 0,
        max_num_eqs: 64,
        adapter_mtu: 0,
        reserved2: 0,
        adapter_link_speed_mbps: 0,
    };
    let thing = ManaDevice::new(&driver, device, 1, 1, None).await.unwrap();
    let vport = thing.new_vport(0, None, &dev_config).await.unwrap();
    let mut endpoint = ManaEndpoint::new(driver.clone(), vport, GuestDmaMode::DirectDma).await;
    let tx_config = endpoint.vport.config_tx().await.unwrap();

    let mut arena = ResourceArena::new();
    let (mut queue, resources) = endpoint.new_queue(&tx_config, &mut arena, 0).await.unwrap();

    endpoint
        .vport
        .config_rx(&RxConfig {
            rx_enable: Some(true),
            rss_enable: Some(false),
            hash_key: None,
            default_rxobj: Some(resources.rxq.wq_obj()),
            indirection_table: None,
            cqe_coalescing: false,
        })
        .await
        .unwrap();

    let mut pool = net_backend::tests::Bufs::new(payload_mem.clone());

    // Post receive buffers and let the device's receive task drain them into the
    // backend, so the backend can complete staged packets and the task is parked
    // (poll_ready Pending) before we stage anything.
    queue.rx_avail(&mut pool, &(1..=16u32).map(RxId).collect::<Vec<_>>());
    let mut handed = 0;
    for _ in 0..40 {
        handed = state.lock().buffers.len();
        if handed >= NUM_PACKETS {
            break;
        }
        run_executor_for(25).await;
    }
    assert!(
        handed >= NUM_PACKETS,
        "device must hand at least {NUM_PACKETS} receive buffers to the backend (got {handed})"
    );

    // Stage the receives WITHOUT waking the receive task: they are now ready in
    // the backend but unposted, the precise window the fence must not overtake.
    state.lock().staged = NUM_PACKETS;

    // Fence the queue. With the drain barrier the fence is routed through the
    // receive task, which drains the staged receives before posting the fence.
    endpoint
        .vport
        .fence_rq(resources.rxq.wq_obj())
        .await
        .unwrap();

    // Drive the queue until the fence is observed, counting delivered packets.
    let mut rx_ids = [RxId(0); NUM_PACKETS + 4];
    let mut rx_n = 0;
    loop {
        let mut context = CancelContext::new().with_timeout(Duration::from_secs(5));
        if context
            .until_cancelled(poll_fn(|cx| queue.poll_ready(cx, &mut pool)))
            .await
            .is_err()
        {
            break;
        }
        rx_n += queue.rx_poll(&mut pool, &mut rx_ids[rx_n..]).unwrap();
        if queue.stats.rx_fence.get() >= 1 {
            break;
        }
    }

    assert_eq!(
        queue.stats.rx_fence.get(),
        1,
        "the fence must be observed exactly once"
    );
    assert_eq!(
        rx_n, NUM_PACKETS,
        "every staged receive must be delivered before the fence is observed"
    );
    assert_eq!(
        queue.stats.rx_packets.get(),
        NUM_PACKETS as u64,
        "all staged packets must be counted as received"
    );
    assert_eq!(
        queue.stats.rx_errors.get(),
        0,
        "the fence path must not record a receive error"
    );

    drop(queue);
    endpoint.vport.destroy(arena).await;
    endpoint.stop().await;
}
