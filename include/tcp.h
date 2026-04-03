#ifndef TCP_H
#define TCP_H

/*
    tcp.h — TCP Header Parsing

    TCP (Transmission Control Protocol, RFC 793) is the protocol that
    provides reliable, ordered, connection-oriented delivery of data.
    It is the "T" in HTTP, SSH, FTP, and most internet applications.

    TCP lives on top of IPv4. After ipv4_parse advances the offset past
    the IPv4 header and identifies the protocol as TCP, this module takes
    over.

    THE TCP HEADER LAYOUT:

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |          Source Port          |       Destination Port        |  bytes 0–3
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                        Sequence Number                        |  bytes 4–7
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                    Acknowledgment Number                      |  bytes 8–11
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |  Data |       |C|E|U|A|P|R|S|F|                               |
       | Offset|  Res. |W|C|R|C|S|S|Y|I|            Window            |  bytes 12–15
       |       |       |R|E|G|K|H|T|N|N|                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |           Checksum            |         Urgent Pointer        |  bytes 16–19
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                    Options (if Data Offset > 5)               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                             Data                              |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    KEY FIELDS:

    Source Port / Destination Port (16 bits each):
                    Port numbers identify the application on each end.
                    For example, port 80 = HTTP, 443 = HTTPS, 22 = SSH.

    Sequence Number (32 bits):
                    Each byte of TCP data has a sequence number. This field
                    holds the number of the FIRST byte in this segment.
                    Sequence numbers are how TCP reassembles out-of-order packets.

    Acknowledgment Number (32 bits):
                    When the ACK flag is set, this field holds the next
                    sequence number the sender expects to receive — effectively
                    acknowledging all bytes up to (ack_number - 1).

    Data Offset (4 bits):
                    Like IPv4's IHL, this is the TCP header length in 32-bit words.
                    Minimum is 5 (20 bytes). Maximum is 15 (60 bytes).

    Flags (9 bits, we track the 6 classic ones):
                    SYN — synchronize: used to initiate a connection
                    ACK — acknowledge: the ack_number field is valid
                    FIN — finish: sender wants to close the connection
                    RST — reset: abort the connection
                    PSH — push: receiver should pass data to app immediately
                    URG — urgent: the urgent pointer field is significant

    Window (16 bits):
                    How many bytes the receiver is willing to accept right
                    now (flow control). A window of 0 means "stop sending."

    Checksum (16 bits):
                    Like ICMP, but covers a "pseudo-header" + TCP header + data.
                    The pseudo-header includes the source/dest IPs from IPv4.
                    We implement a simplified check here — see tcp_parse notes.
*/

#include <stdint.h>
#include "net_types.h"
#include "packet.h"

/* The minimum TCP header length in bytes (Data Offset = 5). */
#define TCP_MIN_HEADER_LEN 20

/*
    TCP flag bit masks — applied to the flags byte in tcp_header_t.
    These correspond to the classic six flags in the TCP header.
*/
#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20

/*
    tcp_header_t — A parsed TCP header.

    All multi-byte fields are in host byte order after parsing.
    'data_offset' is already converted to bytes (multiplied by 4).
    'flags' is a bitmask — use the TCP_FLAG_* constants to test individual flags.
*/
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_number;
    uint32_t ack_number;
    uint8_t  data_offset;    /* Header length in bytes (already * 4) */
    uint8_t  flags;          /* Bitmask of TCP_FLAG_* values          */
    uint16_t window;
    uint16_t checksum;
} tcp_header_t;


/* -----------------------------------------------------------------------
   Public API
   ----------------------------------------------------------------------- */

/*
    tcp_parse — Parse the TCP header from the current packet position.

    Should be called after ipv4_parse has advanced the offset past the IPv4
    header. Reads at least the 20-byte minimum TCP header, validates structure,
    and advances the packet offset past the full TCP header (including options).

    Note on the TCP checksum: A full TCP checksum requires constructing a
    "pseudo-header" from the IPv4 source/dest addresses and total length.
    To keep this module self-contained, we validate structure and flags but
    do not verify the checksum. In a real kernel, the checksum would be
    offloaded to hardware (NIC checksum offload) or computed with the IPv4
    context passed in. We store the checksum field for completeness.

    Parameters:
        pkt — the packet to parse from (offset at start of TCP header)
        hdr — output: populated with parsed field values

    Returns:
        NET_OK          on success
        NET_ERR_INVALID if pkt or hdr is NULL
        NET_ERR_PARSE   if too few bytes remain or data_offset is invalid
*/
net_status_t tcp_parse(packet_t *pkt, tcp_header_t *hdr);

#endif /* TCP_H */
