/*
    test_icmp.c — Tests for ICMP Header Parsing

    We construct real ICMP Echo Request packets byte by byte.
    An ICMP Echo Request (ping) has:
        - IPv4 header (20 bytes)
        - ICMP header (8 bytes): type=8, code=0, checksum, id, seq
        - Optional payload (here: 8 bytes of dummy data)

    The ICMP checksum covers the ICMP header + payload together.
    We compute it using the same ipv4_checksum function (same algorithm).
*/

#include "test_harness.h"
#include "../include/icmp.h"
#include "../include/ipv4.h"
#include "../include/packet.h"
#include <string.h>

/* Re-use the IPv4 header builder from test_ipv4.c logic, inlined here. */
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
    buf[12] = 0x7F; buf[13] = 0x00; buf[14] = 0x00; buf[15] = 0x01; /* 127.0.0.1 */
    buf[16] = 0x7F; buf[17] = 0x00; buf[18] = 0x00; buf[19] = 0x01;
    uint16_t ck = ipv4_checksum(buf, 20);
    buf[10] = (uint8_t)(ck >> 8);
    buf[11] = (uint8_t)(ck & 0xFF);
}

/*
    build_icmp_echo — build an ICMP Echo Request at buf + offset.

    Writes 8-byte ICMP header + 8 bytes of payload = 16 bytes total.
    Computes and inserts the ICMP checksum.
*/
static void build_icmp_echo(uint8_t *icmp_start, uint16_t id, uint16_t seq) {
    icmp_start[0] = 8;                          /* type: Echo Request  */
    icmp_start[1] = 0;                          /* code: 0             */
    icmp_start[2] = 0; icmp_start[3] = 0;       /* checksum: placeholder */
    icmp_start[4] = (uint8_t)(id  >> 8);
    icmp_start[5] = (uint8_t)(id  & 0xFF);
    icmp_start[6] = (uint8_t)(seq >> 8);
    icmp_start[7] = (uint8_t)(seq & 0xFF);
    /* 8-byte payload: just incrementing bytes */
    for (int i = 0; i < 8; i++) {
        icmp_start[8 + i] = (uint8_t)i;
    }
    /* Checksum over the full 16 bytes (header + payload). */
    uint16_t ck = ipv4_checksum(icmp_start, 16);
    icmp_start[2] = (uint8_t)(ck >> 8);
    icmp_start[3] = (uint8_t)(ck & 0xFF);
}

#define PKT_LEN  36  /* 20 IP hdr + 8 ICMP hdr + 8 payload */

/* -----------------------------------------------------------------------
   Tests
   ----------------------------------------------------------------------- */

static void test_icmp_valid_echo_request(void) {
    uint8_t raw[PKT_LEN];
    memset(raw, 0, sizeof(raw));
    build_ipv4_hdr(raw, 1, 16);
    build_icmp_echo(raw + 20, 0x1234, 0x0001);

    packet_t pkt;
    ipv4_header_t ip;
    icmp_header_t icmp;
    packet_init(&pkt, raw, PKT_LEN);

    CHECK(ipv4_parse(&pkt, &ip)   == NET_OK);
    CHECK(icmp_parse(&pkt, &icmp) == NET_OK);

    CHECK(icmp.type       == ICMP_TYPE_ECHO_REQUEST);
    CHECK(icmp.code       == 0);
    CHECK(icmp.identifier == 0x1234);
    CHECK(icmp.sequence   == 0x0001);
    /* Offset should now be at byte 28 (20 IP + 8 ICMP), pointing to payload. */
    CHECK(pkt.offset == 28);
    CHECK(packet_remaining(&pkt) == 8);  /* 8 bytes of payload remain */
}

static void test_icmp_null_args(void) {
    uint8_t raw[PKT_LEN];
    memset(raw, 0, sizeof(raw));
    icmp_header_t icmp;
    packet_t pkt;
    packet_init(&pkt, raw, PKT_LEN);

    CHECK(icmp_parse(NULL, &icmp) == NET_ERR_INVALID);
    CHECK(icmp_parse(&pkt, NULL)  == NET_ERR_INVALID);
}

static void test_icmp_too_short(void) {
    /* Only 7 bytes of data — less than the 8-byte ICMP minimum. */
    uint8_t raw[7] = {8, 0, 0, 0, 0, 1, 0};
    packet_t pkt;
    icmp_header_t icmp;
    packet_init(&pkt, raw, 7);
    CHECK(icmp_parse(&pkt, &icmp) == NET_ERR_PARSE);
}

static void test_icmp_bad_checksum(void) {
    uint8_t raw[PKT_LEN];
    memset(raw, 0, sizeof(raw));
    build_ipv4_hdr(raw, 1, 16);
    build_icmp_echo(raw + 20, 0x0001, 0x0001);
    /* Corrupt one byte of the ICMP payload — invalidates checksum. */
    raw[28] ^= 0xFF;

    packet_t pkt;
    ipv4_header_t ip;
    icmp_header_t icmp;
    packet_init(&pkt, raw, PKT_LEN);
    ipv4_parse(&pkt, &ip);
    CHECK(icmp_parse(&pkt, &icmp) == NET_ERR_PARSE);
}

/* -----------------------------------------------------------------------
   Main
   ----------------------------------------------------------------------- */

int main(void) {
    printf("=== icmp tests ===\n");

    test_icmp_valid_echo_request();
    test_icmp_null_args();
    test_icmp_too_short();
    test_icmp_bad_checksum();

    TEST_SUMMARY();
}
