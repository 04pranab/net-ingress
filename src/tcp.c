/*
    tcp.c — TCP Header Parsing (Implementation)

    TCP header parsing follows the same pattern as IPv4 and ICMP:
    validate inputs, check bounds, decode fields byte by byte using
    explicit shifts (no endian assumptions), advance the offset.

    The most interesting part is the Data Offset field, which tells us
    how long the TCP header actually is — potentially longer than 20 bytes
    if TCP options are present (like MSS, window scaling, timestamps, etc.).
    We must skip past all options to position the offset at the TCP payload.
*/

#include "tcp.h"


net_status_t tcp_parse(packet_t *pkt, tcp_header_t *hdr) {
    if (pkt == NULL || hdr == NULL) {
        return NET_ERR_INVALID;
    }

    /* We need at least 20 bytes for the minimum TCP header. */
    if (packet_remaining(pkt) < TCP_MIN_HEADER_LEN) {
        return NET_ERR_PARSE;
    }

    const uint8_t *p = packet_current_ptr(pkt);

    /* Bytes 0–1: Source port. */
    hdr->src_port = ((uint16_t)p[0] << 8) | p[1];

    /* Bytes 2–3: Destination port. */
    hdr->dst_port = ((uint16_t)p[2] << 8) | p[3];

    /* Bytes 4–7: Sequence number (32-bit big-endian). */
    hdr->seq_number = ((uint32_t)p[4] << 24)
                    | ((uint32_t)p[5] << 16)
                    | ((uint32_t)p[6] <<  8)
                    |  (uint32_t)p[7];

    /* Bytes 8–11: Acknowledgment number (32-bit big-endian). */
    hdr->ack_number = ((uint32_t)p[8]  << 24)
                    | ((uint32_t)p[9]  << 16)
                    | ((uint32_t)p[10] <<  8)
                    |  (uint32_t)p[11];

    /*
        Byte 12: Data Offset (high nibble) and 4 reserved bits (low nibble).
        Data Offset is the TCP header length in 32-bit words, just like
        IPv4's IHL. We multiply by 4 to get bytes.
    */
    uint8_t data_offset_words = (p[12] >> 4) & 0x0F;
    hdr->data_offset = data_offset_words * 4;

    /* Data Offset must be at least 5 (20 bytes). */
    if (data_offset_words < 5) {
        return NET_ERR_PARSE;
    }

    /* The full header (including options) must fit in the remaining data. */
    if (packet_remaining(pkt) < hdr->data_offset) {
        return NET_ERR_PARSE;
    }

    /*
        Byte 13: Flags.
        The 6 classic flags occupy bits [5:0] of byte 13.
        (Bits 7 and 6 are either reserved or CWR/ECE for ECN — we ignore them.)
        
        We mask with 0x3F to extract only the 6 classic flags.
    */
    hdr->flags = p[13] & 0x3F;

    /* Bytes 14–15: Window size. */
    hdr->window = ((uint16_t)p[14] << 8) | p[15];

    /* Bytes 16–17: Checksum (stored but not verified — see tcp.h for explanation). */
    hdr->checksum = ((uint16_t)p[16] << 8) | p[17];

    /* Bytes 18–19: Urgent Pointer — only meaningful if URG flag is set.
       We do not store this for now since urgent data is rarely relevant
       in a teaching ingress subsystem. */

    /*
        Advance past the full TCP header, including any options.
        hdr->data_offset already reflects the total header size in bytes.
        After this advance, the packet offset points to the TCP payload.
    */
    return packet_advance(pkt, hdr->data_offset);
}
