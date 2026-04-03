#ifndef PACKET_H
#define PACKET_H

/*
    packet.h — Packet Abstraction

    This is the second stage in the ingress pipeline.

    After raw bytes arrive in the ring buffer (netbuf), the next step is to
    give those bytes *meaning*. The netbuf_slot_t is just bytes and a length —
    it knows nothing about what kind of network data it contains. The packet
    layer wraps those bytes in a structure that tracks what we have parsed so
    far and where we are in the byte stream.

    ANALOGY: Think of a raw slot as an unopened envelope. The packet_t is
    the same envelope, but now annotated with "From: 192.168.1.1", "To:
    192.168.1.2", "Protocol: TCP" — information we extracted by reading it.

    The packet_t does NOT own the data. It holds a pointer into a netbuf_slot_t.
    This is intentional: we avoid copying bytes more than necessary. The raw
    data stays in the ring buffer while parsing stages annotate the packet_t
    with metadata they discover.
*/

#include <stdint.h>
#include <stddef.h>
#include "net_types.h"

/*
    packet_t — the central data structure of the ingress pipeline.

    Fields:
        raw        — pointer to the raw byte data (NOT owned by this struct)
        length     — total number of valid bytes pointed to by raw
        offset     — how many bytes we have already "consumed" during parsing
                     (starts at 0; advances as each header layer is parsed)
        protocol   — the identified network-layer protocol (set after IPv4 parse)

    The offset field deserves special attention. As we parse headers from the
    front of the packet, we advance offset to mark our current position. So:

        After Ethernet parsing: offset = 14  (Ethernet header is 14 bytes)
        After IPv4 parsing:     offset = 14 + IP header length (usually 34)
        At TCP/ICMP payload:    offset points to where protocol data begins

    This lets each parsing stage say "start reading at offset" without
    needing to pass adjusted pointers — the packet itself tracks its place.
*/
typedef struct {
    const uint8_t *raw;
    uint16_t       length;
    uint16_t       offset;
    net_protocol_t protocol;
} packet_t;


/* -----------------------------------------------------------------------
   Public API
   ----------------------------------------------------------------------- */

/*
    packet_init — Initialize a packet_t from a raw byte buffer.

    This is typically called right after dequeuing a slot from the netbuf.
    It sets up the packet struct to point at the slot's data and resets
    the parsing position (offset) to zero.

    Parameters:
        pkt    — the packet_t to initialize
        data   — pointer to raw bytes (usually slot->data)
        length — number of valid bytes

    Returns:
        NET_OK          on success
        NET_ERR_INVALID if pkt or data is NULL, or length is 0
*/
net_status_t packet_init(packet_t *pkt, const uint8_t *data, uint16_t length);

/*
    packet_remaining — How many unread bytes are left in the packet.

    This is (length - offset). Returns 0 if offset has reached or
    passed the end of the packet.

    Useful for bounds-checking before reading the next header: always
    verify that enough bytes remain before attempting to parse.
*/
uint16_t packet_remaining(const packet_t *pkt);

/*
    packet_current_ptr — Returns a pointer to the byte at the current offset.

    This is how parsing stages read headers: they call this to get a pointer
    to the start of the next header, then cast it to the appropriate struct.

    Returns NULL if pkt is NULL or offset is out of bounds.

    IMPORTANT: The returned pointer is only valid as long as the underlying
    netbuf_slot_t has not been overwritten. Always parse, do not store.
*/
const uint8_t *packet_current_ptr(const packet_t *pkt);

/*
    packet_advance — Move the offset forward by 'bytes'.

    Called after a parsing stage finishes reading a header, to skip past it
    and position the parser at the start of the next layer.

    Returns:
        NET_OK           on success
        NET_ERR_INVALID  if pkt is NULL or the advance would exceed packet length
*/
net_status_t packet_advance(packet_t *pkt, uint16_t bytes);

#endif /* PACKET_H */
