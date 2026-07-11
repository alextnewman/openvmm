// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Software emulation of the device's receive-side RSS (Receive Side Scaling)
//! Toeplitz hash.
//!
//! Real MANA hardware computes a Toeplitz hash over each received packet's flow
//! tuple using the driver-supplied 40-byte hash key, and reports it in the
//! receive completion OOB (`rx_hashtype` plus the per-packet `pkt_hash`). The
//! guest stack uses the hash to steer receives across processors (RSS on
//! Windows, RPS/RFS on Linux). Emulating it here pulls that offload into the
//! device so the emulated NIC presents the same behavior a physical MANA NIC
//! does when the driver has configured RSS.

use gdma_defs::bnic::MANA_HASH_IPV4;
use gdma_defs::bnic::MANA_HASH_IPV6;
use gdma_defs::bnic::MANA_HASH_TCP_IPV4;
use gdma_defs::bnic::MANA_HASH_TCP_IPV6;
use gdma_defs::bnic::MANA_HASH_UDP_IPV4;
use gdma_defs::bnic::MANA_HASH_UDP_IPV6;

/// The RSS hash key length, in bytes. The driver programs a key of this size
/// via `MANA_CONFIG_VPORT_RX`. A 40-byte key covers Toeplitz inputs up to 36
/// bytes (the IPv6 TCP/UDP 4-tuple: two 16-byte addresses plus two ports).
pub const MANA_HASH_KEY_SIZE: usize = 40;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// Computes the Microsoft-standard Toeplitz hash of `input` under `key`.
///
/// The key is treated as a big-endian bit stream. Processing the input most
/// significant bit first, for every 1 bit the 32-bit key window aligned to that
/// bit position is XORed into the running result.
fn toeplitz_hash(key: &[u8], input: &[u8]) -> u32 {
    // `window` holds the 32 key bits aligned with the current input bit; it
    // starts as the first four key bytes (key bits 0..32).
    let mut window = u32::from_be_bytes([key[0], key[1], key[2], key[3]]);
    let mut result = 0u32;
    for (byte_index, &byte) in input.iter().enumerate() {
        for bit in 0..8u32 {
            if byte & (0x80 >> bit) != 0 {
                result ^= window;
            }
            // Shift the window left by one, bringing in key bit
            // `byte_index * 8 + bit + 32`. Bits past the end of the key are 0.
            let next_index = byte_index * 8 + bit as usize + 32;
            let next_bit = key
                .get(next_index / 8)
                .map_or(0, |b| (b >> (7 - (next_index % 8))) & 1);
            window = (window << 1) | next_bit as u32;
        }
    }
    result
}

/// Returns the `(hashtype, [src_port, dst_port])` bytes for a TCP or UDP packet
/// whose L4 header starts at `l4`, or `None` for another protocol or a
/// truncated header.
fn l4_ports(
    packet: &[u8],
    l4: usize,
    protocol: u8,
    tcp_type: u16,
    udp_type: u16,
) -> Option<(u16, [u8; 4])> {
    let hashtype = match protocol {
        IPPROTO_TCP => tcp_type,
        IPPROTO_UDP => udp_type,
        _ => return None,
    };
    let ports = packet.get(l4..l4 + 4)?;
    Some((hashtype, [ports[0], ports[1], ports[2], ports[3]]))
}

fn hash_ipv4(packet: &[u8], off: usize, key: &[u8]) -> Option<(u16, u32)> {
    let ihl = (*packet.get(off)? & 0x0f) as usize * 4;
    if ihl < 20 {
        return None;
    }
    let header = packet.get(off..off + ihl)?;
    let protocol = header[9];
    let src = &header[12..16];
    let dst = &header[16..20];

    // A fragmented packet (nonzero fragment offset, or More Fragments set) can
    // only be hashed on the addresses -- the L4 ports live in the first
    // fragment alone -- so fall through to the IPv4 (L3) hash.
    let frag_field = u16::from_be_bytes([header[6], header[7]]);
    let is_fragment = frag_field & 0x1fff != 0 || frag_field & 0x2000 != 0;

    if !is_fragment {
        if let Some((hashtype, ports)) = l4_ports(
            packet,
            off + ihl,
            protocol,
            MANA_HASH_TCP_IPV4,
            MANA_HASH_UDP_IPV4,
        ) {
            let mut input = [0u8; 12];
            input[0..4].copy_from_slice(src);
            input[4..8].copy_from_slice(dst);
            input[8..12].copy_from_slice(&ports);
            return Some((hashtype, toeplitz_hash(key, &input)));
        }
    }

    let mut input = [0u8; 8];
    input[0..4].copy_from_slice(src);
    input[4..8].copy_from_slice(dst);
    Some((MANA_HASH_IPV4, toeplitz_hash(key, &input)))
}

fn hash_ipv6(packet: &[u8], off: usize, key: &[u8]) -> Option<(u16, u32)> {
    let header = packet.get(off..off + 40)?;
    let next_header = header[6];
    let src = &header[8..24];
    let dst = &header[24..40];

    // Only hash the L4 ports when the fixed IPv6 header is immediately followed
    // by a TCP/UDP header. Packets carrying extension headers would use the
    // `*_EX` hash types (which require walking the header chain); the device
    // falls back to the IPv6 (L3) hash for them, which the driver accepts.
    if let Some((hashtype, ports)) = l4_ports(
        packet,
        off + 40,
        next_header,
        MANA_HASH_TCP_IPV6,
        MANA_HASH_UDP_IPV6,
    ) {
        let mut input = [0u8; 36];
        input[0..16].copy_from_slice(src);
        input[16..32].copy_from_slice(dst);
        input[32..36].copy_from_slice(&ports);
        return Some((hashtype, toeplitz_hash(key, &input)));
    }

    let mut input = [0u8; 32];
    input[0..16].copy_from_slice(src);
    input[16..32].copy_from_slice(dst);
    Some((MANA_HASH_IPV6, toeplitz_hash(key, &input)))
}

/// Parses `packet` (a full Ethernet frame) and computes its RSS hash under
/// `key`, returning the `(rx_hashtype, hash_value)` pair the device reports in
/// the receive completion OOB.
///
/// Returns `None` for packets the device does not hash -- non-IP frames, or
/// frames whose headers are malformed or truncated -- in which case the OOB
/// reports a zero hash type (the "no hash computed" state).
pub fn compute_rx_hash(packet: &[u8], key: &[u8; MANA_HASH_KEY_SIZE]) -> Option<(u16, u32)> {
    // Ethernet header: destination MAC (6) + source MAC (6) + ethertype (2).
    let mut off = 12;
    let mut ethertype = u16::from_be_bytes([*packet.get(off)?, *packet.get(off + 1)?]);
    off += 2;
    // Skip a single 802.1Q VLAN tag if present (the device strips it, but the
    // frame handed to the buffer still carries it).
    if ethertype == ETHERTYPE_VLAN {
        ethertype = u16::from_be_bytes([*packet.get(off + 2)?, *packet.get(off + 3)?]);
        off += 4;
    }
    match ethertype {
        ETHERTYPE_IPV4 => hash_ipv4(packet, off, key),
        ETHERTYPE_IPV6 => hash_ipv6(packet, off, key),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Microsoft-standard RSS hash key used in the published Toeplitz
    /// verification vectors.
    const TEST_KEY: [u8; MANA_HASH_KEY_SIZE] = [
        0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f,
        0xb0, 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30,
        0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
    ];

    // The two canonical Microsoft RSS verification vectors for the first flow
    // (src 66.9.149.187:2794 -> dst 161.142.100.80:1766).
    const IPV4_2TUPLE: [u8; 8] = [66, 9, 149, 187, 161, 142, 100, 80];
    const IPV4_2TUPLE_HASH: u32 = 0x323e8fc2;
    const IPV4_4TUPLE: [u8; 12] = [66, 9, 149, 187, 161, 142, 100, 80, 0x0a, 0xea, 0x06, 0xe6];
    const IPV4_4TUPLE_HASH: u32 = 0x51ccc178;

    #[test]
    fn toeplitz_matches_published_vectors() {
        assert_eq!(toeplitz_hash(&TEST_KEY, &IPV4_2TUPLE), IPV4_2TUPLE_HASH);
        assert_eq!(toeplitz_hash(&TEST_KEY, &IPV4_4TUPLE), IPV4_4TUPLE_HASH);
    }

    /// Builds an Ethernet + IPv4 frame with the given L4 protocol and ports.
    fn ipv4_frame(protocol: u8, src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut frame = vec![
            // Ethernet: dst MAC, src MAC, ethertype 0x0800.
            0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x08, 0x00,
        ];
        // IPv4 header (20 bytes, IHL=5).
        let mut ip = vec![
            0x45, 0x00, 0, 40, 0, 0, 0, 0, 64, protocol, 0, 0, 66, 9, 149, 187, 161, 142, 100, 80,
        ];
        frame.append(&mut ip);
        // L4 ports.
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[0u8; 4]);
        frame
    }

    #[test]
    fn tcp_ipv4_frame_hashes_4tuple() {
        let frame = ipv4_frame(IPPROTO_TCP, 2794, 1766);
        assert_eq!(
            compute_rx_hash(&frame, &TEST_KEY),
            Some((MANA_HASH_TCP_IPV4, IPV4_4TUPLE_HASH))
        );
    }

    #[test]
    fn udp_ipv4_frame_uses_udp_hashtype() {
        let frame = ipv4_frame(IPPROTO_UDP, 2794, 1766);
        assert_eq!(
            compute_rx_hash(&frame, &TEST_KEY),
            Some((MANA_HASH_UDP_IPV4, IPV4_4TUPLE_HASH))
        );
    }

    #[test]
    fn non_l4_ipv4_frame_hashes_addresses_only() {
        // ICMP (protocol 1) is neither TCP nor UDP, so the device hashes the
        // addresses and reports the IPv4 (L3) hash type.
        let frame = ipv4_frame(1, 2794, 1766);
        assert_eq!(
            compute_rx_hash(&frame, &TEST_KEY),
            Some((MANA_HASH_IPV4, IPV4_2TUPLE_HASH))
        );
    }

    #[test]
    fn vlan_tagged_frame_is_parsed() {
        let mut frame = ipv4_frame(IPPROTO_TCP, 2794, 1766);
        // Insert an 802.1Q tag: rewrite the ethertype to 0x8100 and splice in
        // the TCI (0x0064) + the real ethertype (0x0800).
        frame[12] = 0x81;
        frame[13] = 0x00;
        frame.splice(14..14, [0x00, 0x64, 0x08, 0x00]);
        assert_eq!(
            compute_rx_hash(&frame, &TEST_KEY),
            Some((MANA_HASH_TCP_IPV4, IPV4_4TUPLE_HASH))
        );
    }

    #[test]
    fn non_ip_frame_is_not_hashed() {
        // An ARP frame (ethertype 0x0806) is not hashed.
        let frame = vec![
            0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x08, 0x06, 0, 1, 0x08, 0, 6, 4,
        ];
        assert_eq!(compute_rx_hash(&frame, &TEST_KEY), None);
    }

    #[test]
    fn truncated_frame_is_not_hashed() {
        // Ethertype says IPv4 but there is no IP header.
        let frame = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x08, 0x00];
        assert_eq!(compute_rx_hash(&frame, &TEST_KEY), None);
    }

    #[test]
    fn tcp_ipv6_frame_hashes_4tuple() {
        let mut frame = vec![
            // Ethernet: dst MAC, src MAC, ethertype 0x86dd.
            0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x86, 0xdd,
        ];
        // IPv6 header: version/traffic class, flow label, payload len, next
        // header = TCP, hop limit, src (16), dst (16).
        let mut ip = vec![0x60, 0, 0, 0, 0, 24, IPPROTO_TCP, 64];
        ip.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ip.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        frame.append(&mut ip);
        frame.extend_from_slice(&2794u16.to_be_bytes());
        frame.extend_from_slice(&1766u16.to_be_bytes());
        let (hashtype, _value) = compute_rx_hash(&frame, &TEST_KEY).expect("ipv6 tcp hashed");
        assert_eq!(hashtype, MANA_HASH_TCP_IPV6);
    }
}
