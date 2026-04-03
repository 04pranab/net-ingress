#ifndef IPV4_H
#define IPV4_H

/*
    ipv4.h — IPv4 Header Parsing

    This is the third stage in the ingress pipeline.

    Once we have a packet_t pointing at raw bytes, the first real parsing
    task is reading the IPv4 header. IPv4 is the most common network-layer
    protocol and sits at the heart of internet communication.

    THE IPv4 HEADER LAYOUT (from RFC 791):

    Every IPv4 packet begins with a header of at least 20 bytes. Its fields
    are laid out in big-endian byte order (also called "network byte order").

    Bit positions (each row = 32 bits = 4 bytes):

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |Version|  IHL  |Type of Service|          Total Length         |  <- bytes 0–3
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |         Identification        |Flags|      Fragment Offset    |  <- bytes 4–7
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |  Time to Live |    Protocol   |         Header Checksum       |  <- bytes 8–11
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                       Source Address                          |  <- bytes 12–15
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                    Destination Address                        |  <- bytes 16–19
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                    Options (if IHL > 5)                       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    KEY FIELDS EXPLAINED:

    Version (4 bits):   Always 4 for IPv4. We reject anything else.

    IHL (4 bits):       Internet Header Length — the number of 32-bit WORDS
                        in the header. Minimum is 5 (5 × 4 = 20 bytes).
                        Maximum is 15 (15 × 4 = 60 bytes). Values below 5
                        are invalid and must be rejected.

    Total Length (16 bits): Total size of the entire IP packet (header + payload),
                        in bytes. We use this to detect truncated packets.

    Protocol (8 bits):  Identifies the transport-layer protocol carried in the
                        payload. 1 = ICMP, 6 = TCP, 17 = UDP.
                        These match the values in our net_protocol_t enum.

    TTL (8 bits):       Time to Live — decremented by each router. Prevents
                        packets from circulating forever. Not checked here,
                        but stored for completeness.

    Checksum (16 bits): A one's complement checksum over the header bytes only.
                        We verify this to detect corruption.

    Source/Dest IP (32 bits each): The sender's and receiver's IP addresses,
                        stored as 32-bit big-endian integers.
                        Example: 192.168.1.1 = 0xC0A80101
*/

#include <stdint.h>
#include "net_types.h"
#include "packet.h"

/*
    IPV4_MIN_HEADER_LEN — The minimum valid IPv4 header length in bytes.
    Any packet with fewer bytes before the payload cannot be a valid IPv4 packet.
*/
#define IPV4_MIN_HEADER_LEN 20

/*
    ipv4_header_t — A parsed, decoded IPv4 header.

    This struct holds the fields we extract from the raw bytes. It is NOT
    a direct memory overlay of the packet bytes (we avoid that approach
    because of alignment, endianness, and portability concerns). Instead,
    we explicitly copy and byte-swap each field during parsing.

    All multi-byte fields are stored in HOST byte order after parsing.
    This means you can compare them with regular integer literals without
    worrying about endianness.
*/
typedef struct {
    uint8_t  version;           /* Should always be 4                       */
    uint8_t  ihl;               /* Header length in bytes (already * 4)     */
    uint8_t  ttl;               /* Time to Live                             */
    uint8_t  protocol;          /* Transport-layer protocol number          */
    uint16_t total_length;      /* Total IP packet length in bytes          */
    uint16_t checksum;          /* Header checksum (as found in packet)     */
    uint32_t src_addr;          /* Source IP address (host byte order)      */
    uint32_t dst_addr;          /* Destination IP address (host byte order) */
} ipv4_header_t;


/* -----------------------------------------------------------------------
   Public API
   ----------------------------------------------------------------------- */

/*
    ipv4_parse — Parse the IPv4 header from a packet.

    Reads from the current offset in 'pkt', validates the header,
    populates 'hdr' with decoded field values, and advances the packet
    offset past the IPv4 header (to the start of the payload).

    Also sets pkt->protocol to the identified transport protocol.

    Validation performed:
        - Enough bytes remain for a minimum IPv4 header
        - Version field == 4
        - IHL is at least 5 (meaning >= 20 bytes)
        - Total length is consistent with available data
        - Header checksum is correct

    Parameters:
        pkt — the packet to parse from (offset must be at start of IP header)
        hdr — output: populated with parsed field values

    Returns:
        NET_OK              on success
        NET_ERR_INVALID     if pkt or hdr is NULL
        NET_ERR_PARSE       if any validation check fails
        NET_ERR_UNSUPPORTED if the version is not IPv4
*/
net_status_t ipv4_parse(packet_t *pkt, ipv4_header_t *hdr);

/*
    ipv4_checksum — Compute the one's complement checksum over 'len' bytes.

    This is the same algorithm used by IPv4 (and TCP/UDP/ICMP) for header
    integrity checking. It is exposed here so that tests can verify it
    independently and so that upper-layer parsers can reuse it.

    The algorithm:
        1. Sum all 16-bit words in the byte range (big-endian).
        2. Fold any carry bits from the high 16 bits back into the low 16 bits.
        3. Take the bitwise complement (~) of the result.
        4. A correct header will produce a checksum of 0x0000 when the
           checksum field itself is included in the input.

    Parameters:
        data — pointer to the start of the bytes to checksum
        len  — number of bytes (should be even; a trailing odd byte is zero-padded)

    Returns:
        The computed 16-bit checksum value.
*/
uint16_t ipv4_checksum(const uint8_t *data, uint16_t len);

#endif /* IPV4_H */
