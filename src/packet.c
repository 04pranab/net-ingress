/*
    packet.c — Packet Abstraction (Implementation)

    The packet_t is a lightweight view over a raw byte buffer. It holds no
    data of its own — it simply annotates a pointer with a length, a current
    parse position (offset), and a protocol tag.

    All functions here are short. That is intentional. The packet layer is
    not doing heavy lifting — it is providing a clean, safe interface for
    the parsing stages above it to access bytes without going out of bounds.
*/

#include "packet.h"


/* -----------------------------------------------------------------------
   packet_init
   ----------------------------------------------------------------------- */

net_status_t packet_init(packet_t *pkt, const uint8_t *data, uint16_t length) {
    if (pkt == NULL || data == NULL || length == 0) {
        return NET_ERR_INVALID;
    }

    pkt->raw      = data;
    pkt->length   = length;
    pkt->offset   = 0;                   /* No bytes consumed yet. */
    pkt->protocol = NET_PROTO_UNKNOWN;   /* Unknown until IPv4 header is parsed. */

    return NET_OK;
}


/* -----------------------------------------------------------------------
   packet_remaining
   ----------------------------------------------------------------------- */

uint16_t packet_remaining(const packet_t *pkt) {
    if (pkt == NULL) return 0;

    /*
        Guard against the case where offset somehow exceeded length.
        This should not happen if packet_advance is used correctly, but
        a saturating subtraction is more robust than unsigned underflow.
    */
    if (pkt->offset >= pkt->length) return 0;

    return pkt->length - pkt->offset;
}


/* -----------------------------------------------------------------------
   packet_current_ptr
   ----------------------------------------------------------------------- */

const uint8_t *packet_current_ptr(const packet_t *pkt) {
    if (pkt == NULL) return NULL;
    if (pkt->offset >= pkt->length) return NULL;

    /*
        Pointer arithmetic: raw points to byte 0.
        raw + offset points to the byte at position 'offset'.
        This is where the current parsing stage should start reading.
    */
    return pkt->raw + pkt->offset;
}


/* -----------------------------------------------------------------------
   packet_advance
   ----------------------------------------------------------------------- */

net_status_t packet_advance(packet_t *pkt, uint16_t bytes) {
    if (pkt == NULL || bytes == 0) {
        return NET_ERR_INVALID;
    }

    /*
        Bounds check: make sure we are not asked to advance past the end
        of the packet. This would leave offset in an invalid state and
        cause the next caller of packet_current_ptr to read garbage.
    */
    if ((uint32_t)pkt->offset + bytes > pkt->length) {
        return NET_ERR_INVALID;
    }

    pkt->offset += bytes;
    return NET_OK;
}
