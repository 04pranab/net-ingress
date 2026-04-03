/*
    icmp.c — ICMP Header Parsing (Implementation)

    ICMP parsing is simpler than IPv4 because the header is always exactly
    8 bytes long (at least the fixed portion). There are no variable-length
    options, no IHL field to decode.

    The key operation here is checksum verification. Unlike IPv4, where the
    checksum covers only the header, the ICMP checksum covers the ENTIRE
    ICMP message — header plus any payload data. This means we must pass
    ALL remaining bytes (from the current offset to end of packet) into
    the checksum function, not just 8 bytes.
*/

#include "icmp.h"
#include "ipv4.h"    /* We reuse ipv4_checksum — same algorithm. */


net_status_t icmp_parse(packet_t *pkt, icmp_header_t *hdr) {
    if (pkt == NULL || hdr == NULL) {
        return NET_ERR_INVALID;
    }

    /* We need at least the 8-byte fixed ICMP header. */
    if (packet_remaining(pkt) < ICMP_HEADER_LEN) {
        return NET_ERR_PARSE;
    }

    const uint8_t *p = packet_current_ptr(pkt);
    uint16_t icmp_total_len = packet_remaining(pkt);

    /* Byte 0: Type. */
    hdr->type = p[0];

    /* Byte 1: Code. */
    hdr->code = p[1];

    /* Bytes 2–3: Checksum. */
    hdr->checksum = ((uint16_t)p[2] << 8) | p[3];

    /*
        Verify checksum over the FULL remaining ICMP message (header + data).
        A valid ICMP message checksums to 0x0000 when the checksum field
        is included in the calculation (same one's complement behavior as IPv4).
    */
    if (ipv4_checksum(p, icmp_total_len) != 0x0000) {
        return NET_ERR_PARSE;
    }

    /*
        Bytes 4–5: Identifier.
        Bytes 6–7: Sequence Number.
        
        These are only semantically meaningful for Echo Request (Type 8)
        and Echo Reply (Type 0). For other types, these bytes may have
        different meanings — but we extract them as 16-bit integers either
        way since the layout is the same.
    */
    hdr->identifier = ((uint16_t)p[4] << 8) | p[5];
    hdr->sequence   = ((uint16_t)p[6] << 8) | p[7];

    /*
        Advance past the 8-byte ICMP header. Any remaining bytes are ICMP
        payload (e.g., the data portion of a ping). Those bytes stay
        accessible via packet_current_ptr for any higher-level logic
        that cares about them.
    */
    return packet_advance(pkt, ICMP_HEADER_LEN);
}
