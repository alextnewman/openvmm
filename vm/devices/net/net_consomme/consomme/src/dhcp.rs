// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::Access;
use super::Client;
use super::DropReason;
use crate::ChecksumState;
use crate::MIN_MTU;
use heapless::Vec as HeaplessVec;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::DHCP_MAX_DNS_SERVER_COUNT;
use smoltcp::wire::DhcpMessageType;
use smoltcp::wire::DhcpPacket;
use smoltcp::wire::DhcpRepr;
use smoltcp::wire::EthernetAddress;
use smoltcp::wire::EthernetFrame;
use smoltcp::wire::EthernetProtocol;
use smoltcp::wire::EthernetRepr;
use smoltcp::wire::IpAddress;
use smoltcp::wire::IpProtocol;
use smoltcp::wire::Ipv4Address;
use smoltcp::wire::Ipv4Packet;
use smoltcp::wire::Ipv4Repr;
use smoltcp::wire::UdpPacket;
use smoltcp::wire::UdpRepr;

pub const DHCP_SERVER: u16 = 67;
pub const DHCP_CLIENT: u16 = 68;

impl<T: Client> Access<'_, T> {
    pub(crate) fn handle_dhcp(&mut self, payload: &[u8]) -> Result<(), DropReason> {
        let dhcp_packet = DhcpPacket::new_checked(payload)?;
        let dhcp_req = DhcpRepr::parse(&dhcp_packet)?;
        let your_ip;
        let message_type;
        match dhcp_req.message_type {
            DhcpMessageType::Discover => {
                your_ip = Some(self.inner.state.params.client_ip);
                message_type = DhcpMessageType::Offer;
            }
            DhcpMessageType::Request => {
                your_ip = match dhcp_req.requested_ip {
                    Some(addr) if addr == self.inner.state.params.client_ip => Some(addr),
                    None => Some(self.inner.state.params.client_ip),
                    Some(_) => None,
                };
                message_type = DhcpMessageType::Ack;
            }
            ty => return Err(DropReason::UnsupportedDhcp(ty)),
        }

        let mut dns_servers: HeaplessVec<Ipv4Address, DHCP_MAX_DNS_SERVER_COUNT> =
            HeaplessVec::new();
        dns_servers.extend(
            self.inner
                .state
                .params
                .nameservers
                .iter()
                .filter_map(|ip| match ip {
                    IpAddress::Ipv4(addr) => Some(*addr),
                    _ => None,
                })
                .take(DHCP_MAX_DNS_SERVER_COUNT),
        );

        let resp_dhcp = if let Some(your_ip) = your_ip {
            DhcpRepr {
                message_type,
                transaction_id: dhcp_req.transaction_id,
                secs: 0,
                client_hardware_address: dhcp_req.client_hardware_address,
                client_ip: Ipv4Address::UNSPECIFIED,
                your_ip,
                server_ip: self.inner.state.params.gateway_ip,
                router: Some(self.inner.state.params.gateway_ip),
                subnet_mask: Some(self.inner.state.params.net_mask),
                relay_agent_ip: Ipv4Address::UNSPECIFIED,
                // Echo the client's broadcast flag (RFC 2131 4.1). The Windows DHCP
                // client sets it in DISCOVER and drops any OFFER/ACK that does not
                // echo it back as invalid, stalling DHCP; the previous hard-coded
                // `false` was the cause. Linux's dhclient is lax and accepts either.
                broadcast: dhcp_req.broadcast,
                requested_ip: None,
                client_identifier: None,
                server_identifier: Some(self.inner.state.params.gateway_ip),
                parameter_request_list: None,
                dns_servers: Some(dns_servers),
                max_size: None,
                lease_duration: Some(86400),
                renew_duration: None,
                rebind_duration: None,
                additional_options: &[],
            }
        } else {
            DhcpRepr {
                message_type: DhcpMessageType::Nak,
                transaction_id: dhcp_req.transaction_id,
                secs: 0,
                client_hardware_address: dhcp_req.client_hardware_address,
                client_ip: Ipv4Address::UNSPECIFIED,
                your_ip: Ipv4Address::BROADCAST,
                server_ip: self.inner.state.params.gateway_ip,
                router: None,
                subnet_mask: None,
                relay_agent_ip: Ipv4Address::UNSPECIFIED,
                // Echo the client's broadcast flag (see the OFFER/ACK path above).
                broadcast: dhcp_req.broadcast,
                requested_ip: None,
                client_identifier: None,
                server_identifier: None,
                parameter_request_list: None,
                dns_servers: None,
                max_size: None,
                lease_duration: None,
                renew_duration: None,
                rebind_duration: None,
                additional_options: &[],
            }
        };

        let resp_udp = UdpRepr {
            src_port: DHCP_SERVER,
            dst_port: DHCP_CLIENT,
        };
        // RFC 2131 4.1: keep the layer-2 and layer-3 destinations consistent and
        // honor the client's broadcast flag. When the flag is clear the client can
        // receive a unicast reply before it has bound an address, so unicast the
        // reply to (chaddr, yiaddr). When the flag is set -- as the Windows DHCP
        // client does -- or there is no address to offer (NAK), the client cannot
        // yet receive unicast, so broadcast at both layers. The previous code
        // emitted a unicast layer-2 frame with a 255.255.255.255 destination IP;
        // that martian is dropped by the Windows stack (Linux's raw-socket dhclient
        // ignores the mismatch), which stalled DHCP for the Windows guest.
        let (resp_eth_dst, resp_ip_dst) = match your_ip {
            Some(ip) if !dhcp_req.broadcast => (dhcp_req.client_hardware_address, ip),
            _ => (EthernetAddress::BROADCAST, Ipv4Address::BROADCAST),
        };
        let resp_ipv4 = Ipv4Repr {
            src_addr: self.inner.state.params.gateway_ip,
            dst_addr: resp_ip_dst,
            next_header: IpProtocol::Udp,
            payload_len: resp_udp.header_len() + resp_dhcp.buffer_len(),
            hop_limit: 64,
        };
        let resp_eth = EthernetRepr {
            src_addr: self.inner.state.params.gateway_mac,
            dst_addr: resp_eth_dst,
            ethertype: EthernetProtocol::Ipv4,
        };

        let mut resp_buffer = [0; MIN_MTU];
        let mut resp_eth_packet = EthernetFrame::new_unchecked(&mut resp_buffer);
        resp_eth.emit(&mut resp_eth_packet);
        let mut resp_ipv4_packet = Ipv4Packet::new_unchecked(resp_eth_packet.payload_mut());
        resp_ipv4.emit(&mut resp_ipv4_packet, &ChecksumCapabilities::default());
        let mut resp_udp_packet = UdpPacket::new_unchecked(resp_ipv4_packet.payload_mut());
        resp_udp.emit(
            &mut resp_udp_packet,
            &IpAddress::Ipv4(resp_ipv4.src_addr),
            &IpAddress::Ipv4(resp_ipv4.dst_addr),
            resp_dhcp.buffer_len(),
            |udp_payload| {
                let mut resp_dhcp_packet = DhcpPacket::new_unchecked(udp_payload);
                resp_dhcp.emit(&mut resp_dhcp_packet).unwrap();
            },
            &ChecksumCapabilities::default(),
        );

        self.client.recv(
            &resp_buffer[..resp_eth.buffer_len()
                + resp_ipv4.buffer_len()
                + resp_udp.header_len()
                + resp_dhcp.buffer_len()],
            // DHCP is UDP: consomme emits a correct UDP checksum above, so deliver
            // with the UDP checksum marked verified (like every other UDP path).
            // Marking only the IPv4 checksum (l4_protocol=Unknown) is what a real
            // NIC would never do for a UDP frame; the Windows VF path drops such an
            // OFFER (its RX offload treats an IP-verified/L4-unindicated UDP packet
            // as unacceptable), stalling DHCP, while Linux software-verifies and
            // accepts. UDP4 is both faithful and fixes the Windows stall.
            &ChecksumState::UDP4,
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::ChecksumState;
    use crate::Client;
    use crate::Consomme;
    use crate::ConsommeParams;
    use crate::MIN_MTU;
    use pal_async::DefaultDriver;
    use parking_lot::Mutex;
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::DhcpMessageType;
    use smoltcp::wire::DhcpPacket;
    use smoltcp::wire::DhcpRepr;
    use smoltcp::wire::EthernetAddress;
    use smoltcp::wire::EthernetFrame;
    use smoltcp::wire::EthernetProtocol;
    use smoltcp::wire::EthernetRepr;
    use smoltcp::wire::IpAddress;
    use smoltcp::wire::IpProtocol;
    use smoltcp::wire::Ipv4Address;
    use smoltcp::wire::Ipv4Packet;
    use smoltcp::wire::Ipv4Repr;
    use smoltcp::wire::UdpPacket;
    use smoltcp::wire::UdpRepr;
    use std::sync::Arc;

    /// Captures each frame consomme delivers to the guest along with the
    /// checksum state it is delivered with.
    struct CaptureClient {
        driver: Arc<DefaultDriver>,
        received: Arc<Mutex<Vec<(Vec<u8>, ChecksumState)>>>,
    }

    impl Client for CaptureClient {
        fn driver(&self) -> &dyn pal_async::driver::Driver {
            &*self.driver
        }

        fn recv(&mut self, data: &[u8], checksum: &ChecksumState) {
            self.received.lock().push((data.to_vec(), *checksum));
        }

        fn rx_mtu(&mut self) -> usize {
            1514
        }
    }

    /// Builds an Ethernet/IPv4/UDP-framed DHCP DISCOVER as a guest would emit
    /// it, with the BOOTP broadcast flag set to `broadcast`.
    fn build_discover(client_mac: EthernetAddress, broadcast: bool) -> Vec<u8> {
        let dhcp = DhcpRepr {
            message_type: DhcpMessageType::Discover,
            transaction_id: 0x1234_5678,
            secs: 0,
            client_hardware_address: client_mac,
            client_ip: Ipv4Address::UNSPECIFIED,
            your_ip: Ipv4Address::UNSPECIFIED,
            server_ip: Ipv4Address::UNSPECIFIED,
            router: None,
            subnet_mask: None,
            relay_agent_ip: Ipv4Address::UNSPECIFIED,
            broadcast,
            requested_ip: None,
            client_identifier: None,
            server_identifier: None,
            parameter_request_list: None,
            dns_servers: None,
            max_size: None,
            lease_duration: None,
            renew_duration: None,
            rebind_duration: None,
            additional_options: &[],
        };
        let udp = UdpRepr {
            src_port: super::DHCP_CLIENT,
            dst_port: super::DHCP_SERVER,
        };
        let ipv4 = Ipv4Repr {
            src_addr: Ipv4Address::UNSPECIFIED,
            dst_addr: Ipv4Address::BROADCAST,
            next_header: IpProtocol::Udp,
            payload_len: udp.header_len() + dhcp.buffer_len(),
            hop_limit: 64,
        };
        let eth = EthernetRepr {
            src_addr: client_mac,
            dst_addr: EthernetAddress::BROADCAST,
            ethertype: EthernetProtocol::Ipv4,
        };

        let mut buffer = vec![0u8; MIN_MTU];
        let mut eth_packet = EthernetFrame::new_unchecked(&mut buffer);
        eth.emit(&mut eth_packet);
        let mut ipv4_packet = Ipv4Packet::new_unchecked(eth_packet.payload_mut());
        ipv4.emit(&mut ipv4_packet, &ChecksumCapabilities::default());
        let mut udp_packet = UdpPacket::new_unchecked(ipv4_packet.payload_mut());
        udp.emit(
            &mut udp_packet,
            &IpAddress::Ipv4(ipv4.src_addr),
            &IpAddress::Ipv4(ipv4.dst_addr),
            dhcp.buffer_len(),
            |payload| {
                let mut dhcp_packet = DhcpPacket::new_unchecked(payload);
                dhcp.emit(&mut dhcp_packet).unwrap();
            },
            &ChecksumCapabilities::default(),
        );
        let len = eth.buffer_len() + ipv4.buffer_len() + udp.header_len() + dhcp.buffer_len();
        buffer.truncate(len);
        buffer
    }

    /// The decoded destinations of the single OFFER consomme delivers, plus the
    /// configured client identity for unicast assertions.
    struct DecodedOffer {
        eth_dst: EthernetAddress,
        ip_dst: Ipv4Address,
        dhcp_broadcast: bool,
        checksum: ChecksumState,
        client_mac: EthernetAddress,
        client_ip: Ipv4Address,
    }

    /// Sends a DISCOVER with the given broadcast flag and returns the decoded
    /// destinations of the single OFFER consomme delivers.
    fn offer_for(broadcast: bool) -> DecodedOffer {
        pal_async::DefaultPool::run_with(|driver| async move {
            let mut consomme = Consomme::new(ConsommeParams::new().expect("params"));
            let params = consomme.params_mut();
            let client_mac = params.client_mac;
            let client_ip = params.client_ip;
            let mut client = CaptureClient {
                driver: Arc::new(driver),
                received: Arc::new(Mutex::new(Vec::new())),
            };
            let discover = build_discover(client_mac, broadcast);

            {
                let mut access = consomme.access(&mut client);
                access.send(&discover, &ChecksumState::NONE).expect("send");
            }

            let received = client.received.lock();
            assert_eq!(received.len(), 1, "expected exactly one DHCP reply");
            let (frame, checksum) = &received[0];

            let eth = EthernetFrame::new_checked(frame.as_slice()).expect("eth");
            let eth_dst = eth.dst_addr();
            let ipv4 = Ipv4Packet::new_checked(eth.payload()).expect("ipv4");
            let ip_dst = ipv4.dst_addr();
            let udp = UdpPacket::new_checked(ipv4.payload()).expect("udp");
            assert_eq!(udp.src_port(), super::DHCP_SERVER);
            assert_eq!(udp.dst_port(), super::DHCP_CLIENT);
            let dhcp_packet = DhcpPacket::new_checked(udp.payload()).expect("dhcp");
            let dhcp = DhcpRepr::parse(&dhcp_packet).expect("dhcp repr");
            assert_eq!(dhcp.message_type, DhcpMessageType::Offer);

            DecodedOffer {
                eth_dst,
                ip_dst,
                dhcp_broadcast: dhcp.broadcast,
                checksum: *checksum,
                client_mac,
                client_ip,
            }
        })
    }

    // A broadcast-flagged DISCOVER (as the Windows DHCP client sends) must get a
    // reply that echoes the flag and is broadcast at both layer 2 and layer 3,
    // with the UDP checksum indicated as verified.
    #[test]
    fn offer_honors_broadcast_flag() {
        let offer = offer_for(true);
        assert_eq!(offer.eth_dst, EthernetAddress::BROADCAST);
        assert_eq!(offer.ip_dst, Ipv4Address::BROADCAST);
        assert!(offer.dhcp_broadcast, "OFFER must echo the broadcast flag");
        assert!(
            offer.checksum.ipv4 && offer.checksum.udp && !offer.checksum.tcp,
            "UDP4 checksum"
        );
    }

    // A DISCOVER with the broadcast flag clear gets a consistent unicast reply:
    // layer-2 destination is the client MAC and layer-3 destination is the
    // offered address (never a unicast/broadcast martian).
    #[test]
    fn offer_unicasts_when_flag_clear() {
        let offer = offer_for(false);
        assert_eq!(offer.eth_dst, offer.client_mac);
        assert_eq!(offer.ip_dst, offer.client_ip);
        assert!(
            !offer.dhcp_broadcast,
            "OFFER must not set the broadcast flag"
        );
        assert!(
            offer.checksum.ipv4 && offer.checksum.udp && !offer.checksum.tcp,
            "UDP4 checksum"
        );
    }
}
