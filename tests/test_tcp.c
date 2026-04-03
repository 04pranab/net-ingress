/*
    test_tcp.c — Tests for TCP Header Parsing

    We construct real TCP segment headers byte by byte.
    A TCP SYN packet (connection initiation) has:
        - IPv4 header (20 bytes)
        - TCP header (20 bytes minimum): src/dst ports, seq, ack, flags, window
        - No payload (SYN is just a header)

    We test multiple flag combinations because flag parsing is one of the
    trickier parts of TCP — it is easy to get the bit positions wrong.
*/

#include "test_harness.h"
#include "../include/tcp.h"
#include "../include/ipv4.h"
#include "../include/packet.h"
#include <string.h>

static void build_ipv4_hdr(uint8_t *buf, uint8_t proto, uint16_t payload_len) {
    uint16_t total = 20 + payload_len;
    buf[0]  = 0x45;
    buf[1]  = 0x00;
    buf[2]  = (uint8_t)(total >> 8);
    buf[3]  = (uint8_t)(total & 0xFF);
    buf[4]  = 0x00; buf[5]  = 0x01;
    buf[6]  = 0x40; buf[7]  = 0x00;
    buf[8]  = 0x40;
    buf[9]  = proto;
    buf[10] = 0x00; buf[11] = 0x00;
    buf[12] = 0x0A; buf[13] = 0x00; buf[14] = 0x00; buf[15] = 0x01; /* 10.0.0.1 */
    buf[16] = 0x0A; buf[17] = 0x00; buf[18] = 0x00; buf[19] = 0x02; /* 10.0.0.2 */
    uint16_t ck = ipv4_checksum(buf, 20);
    buf[10] = (uint8_t)(ck >> 8);
    buf[11] = (uint8_t)(ck & 0xFF);
}

/*
    build_tcp_hdr — write a minimal 20-byte TCP header at tcp_start.

    Parameters:
        tcp_start  — pointer to where the TCP header begins
        src_port   — source port
        dst_port   — destination port
        seq        — sequence number
        flags      — flag byte (e.g., TCP_FLAG_SYN, TCP_FLAG_ACK | TCP_FLAG_FIN)
        window     — window size
*/
static void build_tcp_hdr(uint8_t *t, uint16_t src, uint16_t dst,
                           uint32_t seq, uint8_t flags, uint16_t window) {
    t[0]  = (uint8_t)(src >> 8);
    t[1]  = (uint8_t)(src & 0xFF);
    t[2]  = (uint8_t)(dst >> 8);
    t[3]  = (uint8_t)(dst & 0xFF);
    t[4]  = (uint8_t)(seq >> 24);
    t[5]  = (uint8_t)(seq >> 16);
    t[6]  = (uint8_t)(seq >>  8);
    t[7]  = (uint8_t)(seq & 0xFF);
    /* ACK number = 0 (not set for a pure SYN). */
    t[8]  = 0; t[9]  = 0; t[10] = 0; t[11] = 0;
    /*
        Byte 12: Data Offset = 5 (no options), top nibble = 0101 = 0x5.
        Low nibble: reserved bits = 0.
        So byte 12 = 0x50.
    */
    t[12] = 0x50;
    t[13] = flags;
    t[14] = (uint8_t)(window >> 8);
    t[15] = (uint8_t)(window & 0xFF);
    /* Checksum and urgent pointer (we do not compute TCP checksum — see tcp.h). */
    t[16] = 0; t[17] = 0;
    t[18] = 0; t[19] = 0;
}

#define PKT_LEN  40   /* 20 IP + 20 TCP (no payload) */

/* -----------------------------------------------------------------------
   Tests
   ----------------------------------------------------------------------- */

static void test_tcp_valid_syn(void) {
    uint8_t raw[PKT_LEN];
    memset(raw, 0, sizeof(raw));
    build_ipv4_hdr(raw, 6, 20);
    build_tcp_hdr(raw + 20,
                  0xC000,          /* src port: 49152 (ephemeral)   */
                  80,              /* dst port: HTTP                 */
                  0x12345678,      /* sequence number                */
                  TCP_FLAG_SYN,    /* flags: SYN                     */
                  65535);          /* window: max                    */

    packet_t pkt;
    ipv4_header_t ip;
    tcp_header_t  tcp;
    packet_init(&pkt, raw, PKT_LEN);

    CHECK(ipv4_parse(&pkt, &ip)  == NET_OK);
    CHECK(tcp_parse (&pkt, &tcp) == NET_OK);

    CHECK(tcp.src_port    == 0xC000);
    CHECK(tcp.dst_port    == 80);
    CHECK(tcp.seq_number  == 0x12345678);
    CHECK(tcp.ack_number  == 0);
    CHECK(tcp.data_offset == 20);
    CHECK(tcp.window      == 65535);

    /* SYN flag should be set, others should not. */
    CHECK((tcp.flags & TCP_FLAG_SYN) != 0);
    CHECK((tcp.flags & TCP_FLAG_ACK) == 0);
    CHECK((tcp.flags & TCP_FLAG_FIN) == 0);
    CHECK((tcp.flags & TCP_FLAG_RST) == 0);

    /* Offset should be at byte 40 — end of packet, no payload. */
    CHECK(pkt.offset == 40);
    CHECK(packet_remaining(&pkt) == 0);
}

static void test_tcp_syn_ack_flags(void) {
    uint8_t raw[PKT_LEN];
    memset(raw, 0, sizeof(raw));
    build_ipv4_hdr(raw, 6, 20);
    build_tcp_hdr(raw + 20, 80, 0xC000, 0xDEADBEEF,
                  TCP_FLAG_SYN | TCP_FLAG_ACK, 8192);

    packet_t pkt;
    ipv4_header_t ip;
    tcp_header_t  tcp;
    packet_init(&pkt, raw, PKT_LEN);
    ipv4_parse(&pkt, &ip);
    CHECK(tcp_parse(&pkt, &tcp) == NET_OK);

    CHECK((tcp.flags & TCP_FLAG_SYN) != 0);
    CHECK((tcp.flags & TCP_FLAG_ACK) != 0);
    CHECK((tcp.flags & TCP_FLAG_FIN) == 0);
}

static void test_tcp_fin_ack_flags(void) {
    uint8_t raw[PKT_LEN];
    memset(raw, 0, sizeof(raw));
    build_ipv4_hdr(raw, 6, 20);
    build_tcp_hdr(raw + 20, 80, 0xC001, 0x00000001,
                  TCP_FLAG_FIN | TCP_FLAG_ACK, 1024);

    packet_t pkt;
    ipv4_header_t ip;
    tcp_header_t  tcp;
    packet_init(&pkt, raw, PKT_LEN);
    ipv4_parse(&pkt, &ip);
    CHECK(tcp_parse(&pkt, &tcp) == NET_OK);

    CHECK((tcp.flags & TCP_FLAG_FIN) != 0);
    CHECK((tcp.flags & TCP_FLAG_ACK) != 0);
    CHECK((tcp.flags & TCP_FLAG_SYN) == 0);
}

static void test_tcp_null_args(void) {
    uint8_t raw[PKT_LEN];
    memset(raw, 0, sizeof(raw));
    tcp_header_t tcp;
    packet_t pkt;
    packet_init(&pkt, raw, PKT_LEN);

    CHECK(tcp_parse(NULL, &tcp) == NET_ERR_INVALID);
    CHECK(tcp_parse(&pkt, NULL) == NET_ERR_INVALID);
}

static void test_tcp_too_short(void) {
    uint8_t raw[19];  /* One byte short of minimum TCP header. */
    memset(raw, 0, sizeof(raw));
    packet_t pkt;
    tcp_header_t tcp;
    packet_init(&pkt, raw, 19);
    CHECK(tcp_parse(&pkt, &tcp) == NET_ERR_PARSE);
}

static void test_tcp_invalid_data_offset(void) {
    uint8_t raw[PKT_LEN];
    memset(raw, 0, sizeof(raw));
    build_ipv4_hdr(raw, 6, 20);
    build_tcp_hdr(raw + 20, 1234, 80, 1, TCP_FLAG_SYN, 512);
    /* Force Data Offset to 3 (too small — minimum is 5). */
    raw[32] = 0x30;  /* byte 12 of TCP = byte 32 overall: top nibble = 3 */

    packet_t pkt;
    ipv4_header_t ip;
    tcp_header_t  tcp;
    packet_init(&pkt, raw, PKT_LEN);
    ipv4_parse(&pkt, &ip);
    CHECK(tcp_parse(&pkt, &tcp) == NET_ERR_PARSE);
}

/* -----------------------------------------------------------------------
   Main
   ----------------------------------------------------------------------- */

int main(void) {
    printf("=== tcp tests ===\n");

    test_tcp_valid_syn();
    test_tcp_syn_ack_flags();
    test_tcp_fin_ack_flags();
    test_tcp_null_args();
    test_tcp_too_short();
    test_tcp_invalid_data_offset();

    TEST_SUMMARY();
}
