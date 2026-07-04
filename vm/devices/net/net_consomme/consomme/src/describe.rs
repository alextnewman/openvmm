// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Compact, best-effort one-line descriptions of Ethernet frames for
//! packet-boundary ("edge") tracing at the consomme backend.
//!
//! The goal is to make it possible to see, at TRACE level, exactly which
//! frames the guest hands to the backend and which frames the backend hands
//! back -- with enough L2/L3/L4 detail (including DHCP message type) to answer
//! "did DHCP complete?", "is the guest ACKing our replies?", "what did we drop
//! and why?" without a packet capture.
//!
//! [`describe_frame`] returns a [`fmt::Display`] wrapper rather than a
//! `String`, so when it is used as a tracing field --
//! `frame = %describe_frame(buf)` -- the (relatively expensive) parsing and
//! formatting only runs when the event is actually enabled. It is therefore
//! zero-cost when the target/level is disabled, and never panics on malformed
//! input.

use core::fmt;
use smoltcp::wire::DhcpMessageType;
use smoltcp::wire::DhcpPacket;
use smoltcp::wire::DhcpRepr;

const ETH_HDR: usize = 14;
const IPV4_MIN_HDR: usize = 20;
const IPV6_HDR: usize = 40;
const UDP_HDR: usize = 8;
const TCP_MIN_HDR: usize = 20;

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

/// A [`fmt::Display`] wrapper over a raw Ethernet frame that renders a compact,
/// single-line summary. Cheap to construct; parsing happens only on `Display`.
pub struct FrameSummary<'a>(&'a [u8]);

/// Wrap `data` for lazy, compact single-line rendering in a tracing field.
pub fn describe_frame(data: &[u8]) -> FrameSummary<'_> {
    FrameSummary(data)
}

impl fmt::Display for FrameSummary<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let data = self.0;
        if data.len() < ETH_HDR {
            return write!(f, "runt len={}", data.len());
        }
        let ethertype = be16(data, 12);
        let payload = &data[ETH_HDR..];
        match ethertype {
            0x0806 => write_arp(f, payload),
            0x0800 => write_ipv4(f, payload, data.len()),
            0x86dd => write_ipv6(f, payload, data.len()),
            other => write!(f, "ethertype=0x{other:04x} len={}", data.len()),
        }
    }
}

fn fmt_ipv4(b: &[u8], off: usize) -> String {
    format!("{}.{}.{}.{}", b[off], b[off + 1], b[off + 2], b[off + 3])
}

fn write_arp(f: &mut fmt::Formatter<'_>, p: &[u8]) -> fmt::Result {
    // ARP for IPv4-over-Ethernet: op at [6..8], sender IP at [14..18],
    // target IP at [24..28].
    if p.len() < 28 {
        return write!(f, "ARP (short)");
    }
    let op = match be16(p, 6) {
        1 => "who-has",
        2 => "is-at",
        n => return write!(f, "ARP op={n}"),
    };
    write!(
        f,
        "ARP {op} tpa={} spa={}",
        fmt_ipv4(p, 24),
        fmt_ipv4(p, 14)
    )
}

fn write_ipv4(f: &mut fmt::Formatter<'_>, p: &[u8], total: usize) -> fmt::Result {
    if p.len() < IPV4_MIN_HDR || (p[0] >> 4) != 4 {
        return write!(f, "IPv4 (short) len={total}");
    }
    let ihl = ((p[0] & 0x0f) as usize) * 4;
    let proto = p[9];
    let src = fmt_ipv4(p, 12);
    let dst = fmt_ipv4(p, 16);
    write!(f, "IPv4 {} {src}->{dst}", proto_short(proto))?;
    if ihl >= IPV4_MIN_HDR && p.len() >= ihl {
        write_l4(f, proto, &p[ihl..])?;
    }
    Ok(())
}

fn write_ipv6(f: &mut fmt::Formatter<'_>, p: &[u8], total: usize) -> fmt::Result {
    if p.len() < IPV6_HDR || (p[0] >> 4) != 6 {
        return write!(f, "IPv6 (short) len={total}");
    }
    let proto = p[6]; // next_header (no ext-header walking; best-effort)
    let src = fmt_ipv6(p, 8);
    let dst = fmt_ipv6(p, 24);
    write!(f, "IPv6 {} {src}->{dst}", proto_short(proto))?;
    write_l4(f, proto, &p[IPV6_HDR..])?;
    Ok(())
}

fn write_l4(f: &mut fmt::Formatter<'_>, proto: u8, l4: &[u8]) -> fmt::Result {
    match proto {
        17 => {
            // UDP
            if l4.len() < UDP_HDR {
                return Ok(());
            }
            let (sp, dp) = (be16(l4, 0), be16(l4, 2));
            write!(f, " {sp}->{dp}")?;
            write_dhcp(f, sp, dp, &l4[UDP_HDR..])
        }
        6 => {
            // TCP
            if l4.len() < TCP_MIN_HDR {
                return Ok(());
            }
            write!(
                f,
                " {}->{} [{}]",
                be16(l4, 0),
                be16(l4, 2),
                tcp_flags(l4[13])
            )
        }
        58 => {
            // ICMPv6 (NDP lives here)
            if l4.is_empty() {
                return Ok(());
            }
            write!(f, " {}", icmpv6_name(l4[0]))
        }
        1 => {
            // ICMP
            if l4.is_empty() {
                return Ok(());
            }
            write!(f, " type={}", l4[0])
        }
        _ => Ok(()),
    }
}

fn write_dhcp(f: &mut fmt::Formatter<'_>, sp: u16, dp: u16, l7: &[u8]) -> fmt::Result {
    let is = |want: u16| sp == want || dp == want;
    if is(546) || is(547) {
        return write!(f, " DHCPv6");
    }
    if is(67) || is(68) {
        // Try to pull the DHCP message type out; fall back to a bare label.
        if let Ok(pkt) = DhcpPacket::new_checked(l7) {
            if let Ok(repr) = DhcpRepr::parse(&pkt) {
                return write!(f, " DHCP:{}", dhcp_mt_name(repr.message_type));
            }
        }
        return write!(f, " DHCP");
    }
    Ok(())
}

fn tcp_flags(flag_byte: u8) -> String {
    // flags live in the low 6 bits: URG ACK PSH RST SYN FIN
    let mut s = String::new();
    if flag_byte & 0x02 != 0 {
        s.push('S');
    }
    if flag_byte & 0x10 != 0 {
        s.push('A');
    }
    if flag_byte & 0x01 != 0 {
        s.push('F');
    }
    if flag_byte & 0x04 != 0 {
        s.push('R');
    }
    if flag_byte & 0x08 != 0 {
        s.push('P');
    }
    if s.is_empty() {
        s.push('.');
    }
    s
}

fn proto_short(p: u8) -> &'static str {
    match p {
        6 => "TCP",
        17 => "UDP",
        1 => "ICMP",
        58 => "ICMPv6",
        2 => "IGMP",
        _ => "proto",
    }
}

fn icmpv6_name(ty: u8) -> &'static str {
    match ty {
        133 => "RS",
        134 => "RA",
        135 => "NS",
        136 => "NA",
        130 => "MLD-query",
        143 => "MLDv2-report",
        128 => "echo-req",
        129 => "echo-reply",
        _ => "icmpv6",
    }
}

fn dhcp_mt_name(mt: DhcpMessageType) -> &'static str {
    match mt {
        DhcpMessageType::Discover => "DISCOVER",
        DhcpMessageType::Offer => "OFFER",
        DhcpMessageType::Request => "REQUEST",
        DhcpMessageType::Decline => "DECLINE",
        DhcpMessageType::Ack => "ACK",
        DhcpMessageType::Nak => "NAK",
        DhcpMessageType::Release => "RELEASE",
        DhcpMessageType::Inform => "INFORM",
        _ => "DHCP?",
    }
}

fn fmt_ipv6(b: &[u8], off: usize) -> String {
    let mut groups = [0u16; 8];
    for (i, g) in groups.iter_mut().enumerate() {
        *g = be16(b, off + i * 2);
    }
    // Compact-ish rendering (not full RFC 5952 zero-compression, but readable).
    groups
        .iter()
        .map(|g| format!("{g:x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0xff; 6]); // dst
        v.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]); // src
        v.extend_from_slice(&ethertype.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], l4: &[u8]) -> Vec<u8> {
        let total = 20 + l4.len();
        let mut v = vec![0u8; 20];
        v[0] = 0x45;
        v[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        v[8] = 64; // ttl
        v[9] = proto;
        v[12..16].copy_from_slice(&src);
        v[16..20].copy_from_slice(&dst);
        v.extend_from_slice(l4);
        eth(0x0800, &v)
    }

    fn udp(sp: u16, dp: u16, l7: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 8];
        v[0..2].copy_from_slice(&sp.to_be_bytes());
        v[2..4].copy_from_slice(&dp.to_be_bytes());
        v[4..6].copy_from_slice(&((8 + l7.len()) as u16).to_be_bytes());
        v.extend_from_slice(l7);
        v
    }

    fn dhcp_discover() -> Vec<u8> {
        // Minimal RFC 2131 BOOTREQUEST + magic cookie + option 53=DISCOVER.
        let mut v = vec![0u8; 240];
        v[0] = 1; // op = BOOTREQUEST
        v[1] = 1; // htype = ethernet
        v[2] = 6; // hlen
        v[4..8].copy_from_slice(&0x1234_5678u32.to_be_bytes()); // xid
        v[28..34].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]); // chaddr
        v[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]); // magic cookie
        v.extend_from_slice(&[53, 1, 1]); // option 53: DHCP message type = DISCOVER
        v.push(255); // end
        v
    }

    #[test]
    fn arp_request() {
        let mut p = vec![0u8; 28];
        p[6..8].copy_from_slice(&1u16.to_be_bytes()); // request
        p[14..18].copy_from_slice(&[10, 0, 0, 2]); // sender IP
        p[24..28].copy_from_slice(&[10, 0, 0, 1]); // target IP
        let frame = eth(0x0806, &p);
        let s = describe_frame(&frame).to_string();
        assert_eq!(s, "ARP who-has tpa=10.0.0.1 spa=10.0.0.2", "{s}");
    }

    #[test]
    fn dhcp_discover_is_labeled() {
        let frame = ipv4(
            17,
            [0, 0, 0, 0],
            [255, 255, 255, 255],
            &udp(68, 67, &dhcp_discover()),
        );
        let s = describe_frame(&frame).to_string();
        assert!(
            s.starts_with("IPv4 UDP 0.0.0.0->255.255.255.255 68->67"),
            "{s}"
        );
        assert!(
            s.contains("DHCP:DISCOVER"),
            "expected decoded DHCP message type in: {s}"
        );
    }

    #[test]
    fn tcp_syn_flags() {
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&49152u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 0x50; // data offset = 5 words
        tcp[13] = 0x02; // SYN
        let frame = ipv4(6, [10, 0, 0, 2], [1, 1, 1, 1], &tcp);
        let s = describe_frame(&frame).to_string();
        assert_eq!(s, "IPv4 TCP 10.0.0.2->1.1.1.1 49152->443 [S]", "{s}");
    }

    #[test]
    fn ipv6_ndp_neighbor_solicit() {
        let mut ip6 = vec![0u8; 40];
        ip6[0] = 0x60; // version 6
        ip6[6] = 58; // next header = ICMPv6
        let mut icmp = vec![0u8; 8];
        icmp[0] = 135; // Neighbor Solicitation
        ip6.extend_from_slice(&icmp);
        let frame = eth(0x86dd, &ip6);
        let s = describe_frame(&frame).to_string();
        assert!(s.starts_with("IPv6 ICMPv6"), "{s}");
        assert!(s.ends_with(" NS"), "{s}");
    }

    #[test]
    fn malformed_does_not_panic() {
        assert_eq!(describe_frame(&[]).to_string(), "runt len=0");
        assert_eq!(describe_frame(&[0u8; 10]).to_string(), "runt len=10");
        // Ethernet header claiming IPv4 but with a truncated L3 header.
        let s = describe_frame(&eth(0x0800, &[0x45, 0, 0])).to_string();
        assert!(s.starts_with("IPv4 (short)"), "{s}");
    }
}
