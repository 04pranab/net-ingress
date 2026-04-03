/*
    ipv4.c — IPv4 Header Parsing (Implementation)

    This file implements the IPv4 header parser. It reads raw bytes from a
    packet_t, validates them according to RFC 791, and fills an ipv4_header_t
    with the decoded results.

    TWO IMPORTANT CONCEPTS USED HERE:

    1. ENDIANNESS
       Network protocols transmit multi-byte integers in big-endian order
       (most-significant byte first). Most modern CPUs are little-endian
       (least-significant byte first). If we simply cast a byte pointer to
       a uint16_t and read it, we will get the bytes in the wrong order on
       a little-endian machine.

       The solution is to manually reconstruct multi-byte values from
       individual bytes using bit shifts. For a 16-bit big-endian value
       at bytes [i] and [i+1]:

           value = ((uint16_t)bytes[i] << 8) | bytes[i+1]

       For a 32-bit big-endian value at bytes [i..i+3]:

           value = ((uint32_t)bytes[i]   << 24)
                 | ((uint32_t)bytes[i+1] << 16)
                 | ((uint32_t)bytes[i+2] <<  8)
                 |  (uint32_t)bytes[i+3]

       This approach works identically on any architecture. No byte-swap
       intrinsics, no ntohs(), no platform assumptions.

    2. THE ONE'S COMPLEMENT CHECKSUM
       IPv4 uses a simple but effective checksum algorithm. We explain it
       fully in the ipv4_checksum function below.
*/

#include "ipv4.h"


/* -----------------------------------------------------------------------
   ipv4_checksum
   ----------------------------------------------------------------------- */

uint16_t ipv4_checksum(const uint8_t *data, uint16_t len) {
    uint32_t sum = 0;
    uint16_t i;

    /*
        Step 1: Sum all 16-bit words.
        We process two bytes at a time, reconstructing each 16-bit word
        in big-endian order using shifts (same reasoning as above).
    */
    for (i = 0; i + 1 < len; i += 2) {
        sum += ((uint16_t)data[i] << 8) | data[i + 1];
    }

    /*
        Step 2: Handle a trailing odd byte (if len is not even).
        The odd byte is treated as the high byte of a 16-bit word with
        a zero low byte. In practice, IPv4 headers are always an even
        number of bytes (IHL is in 32-bit words), but we handle it anyway.
    */
    if (len % 2 != 0) {
        sum += (uint16_t)data[len - 1] << 8;
    }

    /*
        Step 3: Fold carry bits back into the 16-bit result.
        After summing, 'sum' may be larger than 16 bits. We "fold" the
        upper 16 bits back into the lower 16 bits repeatedly until
        the result fits in 16 bits.

        Example: sum = 0x0001FFFE
            -> (0xFFFE + 0x0001) = 0xFFFF  -> no carry left.
    */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    /*
        Step 4: One's complement (bitwise invert).
        The final result is the bitwise NOT of the folded sum.
        
        When a receiver recomputes the checksum over the entire header
        (including the checksum field itself), the result should be 0xFFFF,
        which after inversion becomes 0x0000 — indicating no errors.

        We cast to uint16_t to discard the upper bits of the 32-bit value.
    */
    return (uint16_t)(~sum);
}


/* -----------------------------------------------------------------------
   ipv4_parse
   ----------------------------------------------------------------------- */

net_status_t ipv4_parse(packet_t *pkt, ipv4_header_t *hdr) {
    if (pkt == NULL || hdr == NULL) {
        return NET_ERR_INVALID;
    }

    /* We need at least 20 bytes for the minimum IPv4 header. */
    if (packet_remaining(pkt) < IPV4_MIN_HEADER_LEN) {
        return NET_ERR_PARSE;
    }

    const uint8_t *p = packet_current_ptr(pkt);

    /*
        Byte 0 contains both Version (high nibble) and IHL (low nibble).
        A nibble is 4 bits. We extract each with masking and shifting:
            Version = (byte0 >> 4) & 0x0F    <- shift right 4, take low 4 bits
            IHL     = byte0 & 0x0F           <- take low 4 bits directly
    */
    hdr->version = (p[0] >> 4) & 0x0F;
    uint8_t ihl_words = p[0] & 0x0F;   /* IHL in 32-bit words */
    hdr->ihl = ihl_words * 4;          /* Convert to bytes */

    /* Validate version — we only handle IPv4. */
    if (hdr->version != 4) {
        return NET_ERR_UNSUPPORTED;
    }

    /* IHL must be at least 5 words (20 bytes). */
    if (ihl_words < 5) {
        return NET_ERR_PARSE;
    }

    /* Make sure the full header (including any options) fits in the packet. */
    if (packet_remaining(pkt) < hdr->ihl) {
        return NET_ERR_PARSE;
    }

    /* Byte 1: Type of Service (we parse but do not use it). */
    /* (skipped — not stored in ipv4_header_t for simplicity) */

    /* Bytes 2–3: Total Length (big-endian 16-bit). */
    hdr->total_length = ((uint16_t)p[2] << 8) | p[3];

    /* Sanity-check: total_length must fit within remaining packet bytes. */
    if (hdr->total_length < hdr->ihl || hdr->total_length > packet_remaining(pkt)) {
        return NET_ERR_PARSE;
    }

    /* Bytes 4–7: Identification and Fragment Offset — we skip these for now. */

    /* Byte 8: Time to Live. */
    hdr->ttl = p[8];

    /* Byte 9: Protocol — identifies the payload type (TCP=6, ICMP=1, UDP=17). */
    hdr->protocol = p[9];

    /* Bytes 10–11: Header Checksum. */
    hdr->checksum = ((uint16_t)p[10] << 8) | p[11];

    /*
        Verify the header checksum.
        We compute the checksum over the full header (ihl bytes). Because
        the checksum field is INCLUDED in this range, a correct packet will
        produce 0x0000 after the one's complement sum and inversion.
        
        Wait — we said ipv4_checksum returns ~sum, so for a correct header
        where sum = 0xFFFF, ~0xFFFF = 0x0000. So we check for 0x0000.
    */
    if (ipv4_checksum(p, hdr->ihl) != 0x0000) {
        return NET_ERR_PARSE;
    }

    /* Bytes 12–15: Source IP address (big-endian 32-bit). */
    hdr->src_addr = ((uint32_t)p[12] << 24)
                  | ((uint32_t)p[13] << 16)
                  | ((uint32_t)p[14] <<  8)
                  |  (uint32_t)p[15];

    /* Bytes 16–19: Destination IP address (big-endian 32-bit). */
    hdr->dst_addr = ((uint32_t)p[16] << 24)
                  | ((uint32_t)p[17] << 16)
                  | ((uint32_t)p[18] <<  8)
                  |  (uint32_t)p[19];

    /*
        Update the packet's known protocol so the dispatch stage can
        route it without re-inspecting the IPv4 header.
    */
    switch (hdr->protocol) {
        case 1:  pkt->protocol = NET_PROTO_ICMP; break;
        case 6:  pkt->protocol = NET_PROTO_TCP;  break;
        case 17: pkt->protocol = NET_PROTO_UDP;  break;  /* parsed but not handled yet */
        default: pkt->protocol = NET_PROTO_UNKNOWN; break;
    }

    /*
        Advance the packet offset past the entire IPv4 header (including
        any options, which occupy bytes 20 through ihl-1).
        The next parser will start reading from here.
    */
    return packet_advance(pkt, hdr->ihl);
}
