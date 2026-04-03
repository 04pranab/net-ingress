#ifndef ICMP_H
#define ICMP_H

/*
    icmp.h — ICMP Header Parsing

    ICMP (Internet Control Message Protocol, RFC 792) is the protocol
    responsible for diagnostic and control messages at the network layer.
    The most familiar ICMP message is the Echo Request/Reply pair — this
    is what the 'ping' command uses.

    ICMP lives directly on top of IPv4. After the IPv4 header is parsed
    and the packet offset advances past it, if the protocol field says
    ICMP (protocol number 1), we hand the packet to this module.

    THE ICMP HEADER LAYOUT:

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |      Type     |      Code     |           Checksum            |  <- bytes 0–3
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |           Identifier          |        Sequence Number        |  <- bytes 4–7
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |     Data (variable, depends on Type/Code) ...                 |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    KEY FIELDS:

    Type (8 bits):  The broad category of the ICMP message.
                    Examples: 0 = Echo Reply, 8 = Echo Request, 3 = Dest Unreachable.

    Code (8 bits):  A sub-type within the given Type.
                    For Echo Request/Reply, Code is always 0.
                    For Type 3 (Destination Unreachable), Code specifies why:
                    0 = Net Unreachable, 1 = Host Unreachable, 3 = Port Unreachable, etc.

    Checksum (16 bits): One's complement checksum over the entire ICMP message
                    (header + data). Same algorithm as IPv4 header checksum.

    Identifier (16 bits): Used to match Echo Requests with Echo Replies.
                    Typically set to the sending process's PID.

    Sequence Number (16 bits): Incremented for each Echo Request sent.
                    The reply copies it back so the sender can match them up.

    Note: Identifier and Sequence Number are only meaningful for Echo messages
    (Type 0 and 8). Other ICMP types use bytes 4–7 differently.
*/

#include <stdint.h>
#include "net_types.h"
#include "packet.h"

/* The fixed-size portion of every ICMP header is 8 bytes. */
#define ICMP_HEADER_LEN 8

/*
    Common ICMP type values. Not exhaustive — just the most important ones
    for a teaching system. Real kernels use a much larger set.
*/
#define ICMP_TYPE_ECHO_REPLY        0
#define ICMP_TYPE_DEST_UNREACHABLE  3
#define ICMP_TYPE_ECHO_REQUEST      8
#define ICMP_TYPE_TIME_EXCEEDED     11

/*
    icmp_header_t — A parsed ICMP header.

    Like ipv4_header_t, this is a decoded copy of the fields, not a raw
    memory overlay. Fields are in host byte order.
*/
typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t identifier;     /* Meaningful only for Echo Request/Reply */
    uint16_t sequence;       /* Meaningful only for Echo Request/Reply */
} icmp_header_t;


/* -----------------------------------------------------------------------
   Public API
   ----------------------------------------------------------------------- */

/*
    icmp_parse — Parse the ICMP header from the current packet position.

    Should be called after ipv4_parse has advanced the offset past the
    IPv4 header. Reads the 8-byte ICMP header, validates the checksum,
    and advances the packet offset past the ICMP header.

    Parameters:
        pkt — the packet to parse from (offset must be at start of ICMP header)
        hdr — output: populated with parsed field values

    Returns:
        NET_OK          on success
        NET_ERR_INVALID if pkt or hdr is NULL
        NET_ERR_PARSE   if too few bytes remain, or checksum fails
*/
net_status_t icmp_parse(packet_t *pkt, icmp_header_t *hdr);

#endif /* ICMP_H */
