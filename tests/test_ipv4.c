/*
    test_ipv4.c — Tests for IPv4 Header Parsing

    To test a parser, we need real byte sequences. We cannot use Wireshark
    captures here — we must construct packets byte by byte so the tests are
    self-contained, portable, and hardware-free.

    The helper function build_ipv4_header() assembles a minimal valid IPv4
    header in a byte array. We then deliberately corrupt individual fields
    to test that the parser catches each kind of invalid input.

    Understanding these tests is itself a networking lesson: you will see
    exactly how IPv4 header bytes are structured.
*/

#include "test_harness.h"
#include "../include/ipv4.h"
#include "../include/packet.h"
#include <string.h>

/* -----------------------------------------------------------------------
   Helper: build a valid minimum IPv4 header (20 bytes) into buf[].

   Fields:
       version  = 4
       IHL      = 5  (20 bytes, no options)
       TOS      = 0
       total_len = 20 + payload_len
       id       = 0x0001
       flags    = 0x40 (don't fragment), frag_offset = 0
       ttl      = 64
       protocol = proto (1=ICMP, 6=TCP, 17=UDP)
       src      = 192.168.0.1  = 0xC0A80001
       dst      = 192.168.0.2  = 0xC0A80002

   The checksum field is computed and inserted automatically.
   ----------------------------------------------------------------------- */

static void build_ipv4_header(uint8_t *buf, uint8_t proto, uint16_t payload_len) {
    uint16_t total_len = 20 + payload_len;

    buf[0]  = 0x45;                          /* version=4, IHL=5            */
    buf[1]  = 0x00;                          /* TOS                         */
    buf[2]  = (uint8_t)(total_len >> 8);     /* total length high byte      */
    buf[3]  = (uint8_t)(total_len & 0xFF);   /* total length low byte       */
    buf[4]  = 0x00; buf[5]  = 0x01;          /* identification              */
    buf[6]  = 0x40; buf[7]  = 0x00;          /* flags=DF, fragment offset=0 */
    buf[8]  = 0x40;                          /* TTL = 64                    */
    buf[9]  = proto;                         /* protocol                    */
    buf[10] = 0x00; buf[11] = 0x00;          /* checksum — placeholder      */
    buf[12] = 0xC0; buf[13] = 0xA8;          /* src: 192.168               */
    buf[14] = 0x00; buf[15] = 0x01;          /* src: .0.1                  */
    buf[16] = 0xC0; buf[17] = 0xA8;          /* dst: 192.168               */
    buf[18] = 0x00; buf[19] = 0x02;          /* dst: .0.2                  */

    /*
        Now compute and insert the correct checksum.
        ipv4_checksum over a header with checksum=0 gives the correct value
        to place in bytes [10:11]. But actually, ipv4_checksum is designed
        so that when we checksum a complete header (including the checksum
        field), the result is 0x0000. So we need the one's complement of the
        partial sum with checksum=0, which is exactly what ipv4_checksum returns.
    */
    uint16_t cksum = ipv4_checksum(buf, 20);
    buf[10] = (uint8_t)(cksum >> 8);
    buf[11] = (uint8_t)(cksum & 0xFF);
}

/* -----------------------------------------------------------------------
   Test data: a full packet buffer (header + dummy payload).
   We use a fixed-size array large enough for header + some payload.
   ----------------------------------------------------------------------- */
#define TEST_PKT_LEN  40   /* 20 byte header + 20 byte dummy payload */

/* -----------------------------------------------------------------------
   1. Basic valid parse
   ----------------------------------------------------------------------- */

static void test_parse_valid_icmp(void) {
    uint8_t raw[TEST_PKT_LEN];
    memset(raw, 0, sizeof(raw));
    build_ipv4_header(raw, 1 /* ICMP */, 20);

    packet_t pkt;
    ipv4_header_t hdr;
    packet_init(&pkt, raw, TEST_PKT_LEN);

    CHECK(ipv4_parse(&pkt, &hdr) == NET_OK);
    CHECK(hdr.version      == 4);
    CHECK(hdr.ihl          == 20);
    CHECK(hdr.ttl          == 64);
    CHECK(hdr.protocol     == 1);             /* ICMP */
    CHECK(hdr.total_length == 40);
    CHECK(hdr.src_addr     == 0xC0A80001);    /* 192.168.0.1 */
    CHECK(hdr.dst_addr     == 0xC0A80002);    /* 192.168.0.2 */
    CHECK(pkt.protocol     == NET_PROTO_ICMP);
    /* Offset should have advanced past the 20-byte header. */
    CHECK(pkt.offset       == 20);
}

static void test_parse_valid_tcp(void) {
    uint8_t raw[TEST_PKT_LEN];
    memset(raw, 0, sizeof(raw));
    build_ipv4_header(raw, 6 /* TCP */, 20);

    packet_t pkt;
    ipv4_header_t hdr;
    packet_init(&pkt, raw, TEST_PKT_LEN);

    CHECK(ipv4_parse(&pkt, &hdr) == NET_OK);
    CHECK(hdr.protocol     == 6);
    CHECK(pkt.protocol     == NET_PROTO_TCP);
}

static void test_parse_unknown_proto_marked_correctly(void) {
    uint8_t raw[TEST_PKT_LEN];
    memset(raw, 0, sizeof(raw));
    build_ipv4_header(raw, 200 /* unknown */, 20);

    packet_t pkt;
    ipv4_header_t hdr;
    packet_init(&pkt, raw, TEST_PKT_LEN);

    /*
        parse itself succeeds — the IPv4 header is structurally valid.
        But pkt.protocol should be NET_PROTO_UNKNOWN because protocol 200
        is not in our supported set.
    */
    CHECK(ipv4_parse(&pkt, &hdr) == NET_OK);
    CHECK(pkt.protocol == NET_PROTO_UNKNOWN);
}

/* -----------------------------------------------------------------------
   2. NULL argument handling
   ----------------------------------------------------------------------- */

static void test_parse_null_pkt(void) {
    ipv4_header_t hdr;
    CHECK(ipv4_parse(NULL, &hdr) == NET_ERR_INVALID);
}

static void test_parse_null_hdr(void) {
    uint8_t raw[40];
    memset(raw, 0, sizeof(raw));
    packet_t pkt;
    packet_init(&pkt, raw, 40);
    CHECK(ipv4_parse(&pkt, NULL) == NET_ERR_INVALID);
}

/* -----------------------------------------------------------------------
   3. Truncated packet (too few bytes)
   ----------------------------------------------------------------------- */

static void test_parse_too_short(void) {
    uint8_t raw[19];   /* One byte short of minimum header. */
    memset(raw, 0, sizeof(raw));
    packet_t pkt;
    ipv4_header_t hdr;
    packet_init(&pkt, raw, 19);
    CHECK(ipv4_parse(&pkt, &hdr) == NET_ERR_PARSE);
}

/* -----------------------------------------------------------------------
   4. Invalid version field
   ----------------------------------------------------------------------- */

static void test_parse_wrong_version(void) {
    uint8_t raw[TEST_PKT_LEN];
    memset(raw, 0, sizeof(raw));
    build_ipv4_header(raw, 1, 20);
    /* Corrupt version to 6 (IPv6). */
    raw[0] = (raw[0] & 0x0F) | (6 << 4);

    packet_t pkt;
    ipv4_header_t hdr;
    packet_init(&pkt, raw, TEST_PKT_LEN);
    CHECK(ipv4_parse(&pkt, &hdr) == NET_ERR_UNSUPPORTED);
}

/* -----------------------------------------------------------------------
   5. Invalid IHL
   ----------------------------------------------------------------------- */

static void test_parse_ihl_too_small(void) {
    uint8_t raw[TEST_PKT_LEN];
    memset(raw, 0, sizeof(raw));
    build_ipv4_header(raw, 1, 20);
    /* Set IHL to 4 (less than minimum of 5). Low nibble of byte 0. */
    raw[0] = (raw[0] & 0xF0) | 0x04;

    packet_t pkt;
    ipv4_header_t hdr;
    packet_init(&pkt, raw, TEST_PKT_LEN);
    CHECK(ipv4_parse(&pkt, &hdr) == NET_ERR_PARSE);
}

/* -----------------------------------------------------------------------
   6. Corrupted checksum
   ----------------------------------------------------------------------- */

static void test_parse_bad_checksum(void) {
    uint8_t raw[TEST_PKT_LEN];
    memset(raw, 0, sizeof(raw));
    build_ipv4_header(raw, 1, 20);
    /* Flip one bit in the checksum. */
    raw[10] ^= 0x01;

    packet_t pkt;
    ipv4_header_t hdr;
    packet_init(&pkt, raw, TEST_PKT_LEN);
    CHECK(ipv4_parse(&pkt, &hdr) == NET_ERR_PARSE);
}

/* -----------------------------------------------------------------------
   7. ipv4_checksum independently
   ----------------------------------------------------------------------- */

static void test_checksum_correct_header(void) {
    uint8_t raw[TEST_PKT_LEN];
    memset(raw, 0, sizeof(raw));
    build_ipv4_header(raw, 1, 20);
    /*
        A valid header with checksum already filled in:
        recomputing the checksum over all 20 bytes must give 0x0000.
    */
    CHECK(ipv4_checksum(raw, 20) == 0x0000);
}

static void test_checksum_detects_corruption(void) {
    uint8_t raw[TEST_PKT_LEN];
    memset(raw, 0, sizeof(raw));
    build_ipv4_header(raw, 1, 20);
    raw[15] ^= 0xFF;  /* Corrupt the last byte of src address. */
    CHECK(ipv4_checksum(raw, 20) != 0x0000);
}

/* -----------------------------------------------------------------------
   Main
   ----------------------------------------------------------------------- */

int main(void) {
    printf("=== ipv4 tests ===\n");

    test_parse_valid_icmp();
    test_parse_valid_tcp();
    test_parse_unknown_proto_marked_correctly();
    test_parse_null_pkt();
    test_parse_null_hdr();
    test_parse_too_short();
    test_parse_wrong_version();
    test_parse_ihl_too_small();
    test_parse_bad_checksum();
    test_checksum_correct_header();
    test_checksum_detects_corruption();

    TEST_SUMMARY();
}
