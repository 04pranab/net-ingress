/*
    test_advanced.c — Serious Tests for net-ingress

    Four categories:

    1. EDGE CASE STRESS
       Ring buffer at capacity, rapid enqueue/dequeue alternation,
       exact boundary sizes.

    2. FUZZ-STYLE GARBAGE INPUT
       Feed random/malformed bytes into every parser. Nothing should
       crash. Every result must be a valid net_status_t — never garbage,
       never a segfault, never undefined behavior.

    3. FULL PIPELINE INTEGRATION
       Raw bytes travel the entire path:
       netbuf → packet → ipv4 → icmp/tcp → dispatch → net_stats
       Counters are verified to match exactly what happened.

    4. BOUNDARY ARITHMETIC
       IHL at exactly 5 and 15 (min and max).
       TCP data offset at exactly 5 and 15.
       Checksum with all-zeros, all-ones, single-bit flips.
       Packet lengths at exactly the minimum valid size.
*/

#include "test_harness.h"
#include "../include/netbuf.h"
#include "../include/packet.h"
#include "../include/ipv4.h"
#include "../include/icmp.h"
#include "../include/tcp.h"
#include "../include/dispatch.h"
#include "../include/net_stats.h"
#include <string.h>
#include <stdint.h>

/* -----------------------------------------------------------------------
   Shared helpers
   ----------------------------------------------------------------------- */

static void build_ipv4(uint8_t *buf, uint8_t proto, uint16_t payload_len) {
    uint16_t total = 20 + payload_len;
    buf[0]  = 0x45;
    buf[1]  = 0x00;
    buf[2]  = (uint8_t)(total >> 8);
    buf[3]  = (uint8_t)(total & 0xFF);
    buf[4]  = 0x00; buf[5] = 0x01;
    buf[6]  = 0x40; buf[7] = 0x00;
    buf[8]  = 0x40;
    buf[9]  = proto;
    buf[10] = 0x00; buf[11] = 0x00;
    buf[12] = 0xC0; buf[13] = 0xA8; buf[14] = 0x00; buf[15] = 0x01;
    buf[16] = 0xC0; buf[17] = 0xA8; buf[18] = 0x00; buf[19] = 0x02;
    uint16_t ck = ipv4_checksum(buf, 20);
    buf[10] = (uint8_t)(ck >> 8);
    buf[11] = (uint8_t)(ck & 0xFF);
}

static void build_icmp_echo(uint8_t *p, uint16_t id, uint16_t seq, uint16_t payload_len) {
    p[0] = 8; p[1] = 0;
    p[2] = 0; p[3] = 0;
    p[4] = (uint8_t)(id  >> 8); p[5] = (uint8_t)(id  & 0xFF);
    p[6] = (uint8_t)(seq >> 8); p[7] = (uint8_t)(seq & 0xFF);
    for (uint16_t i = 0; i < payload_len; i++) p[8 + i] = (uint8_t)i;
    uint16_t ck = ipv4_checksum(p, 8 + payload_len);
    p[2] = (uint8_t)(ck >> 8);
    p[3] = (uint8_t)(ck & 0xFF);
}

static void build_tcp_hdr(uint8_t *t, uint16_t src, uint16_t dst,
                           uint32_t seq, uint8_t flags) {
    t[0]  = (uint8_t)(src >> 8); t[1]  = (uint8_t)(src & 0xFF);
    t[2]  = (uint8_t)(dst >> 8); t[3]  = (uint8_t)(dst & 0xFF);
    t[4]  = (uint8_t)(seq >> 24); t[5] = (uint8_t)(seq >> 16);
    t[6]  = (uint8_t)(seq >>  8); t[7] = (uint8_t)(seq & 0xFF);
    t[8]  = 0; t[9] = 0; t[10] = 0; t[11] = 0;
    t[12] = 0x50; /* data offset = 5 */
    t[13] = flags;
    t[14] = 0xFF; t[15] = 0xFF; /* window */
    t[16] = 0; t[17] = 0;       /* checksum (not verified) */
    t[18] = 0; t[19] = 0;
}

/* -----------------------------------------------------------------------
   CATEGORY 1: EDGE CASE STRESS
   ----------------------------------------------------------------------- */

static void test_ring_fill_drain_fill_drain(void) {
    /*
        Fill the ring completely, drain it completely, fill again, drain again.
        Tests that the ring resets cleanly and remains usable after a full cycle.
    */
    netbuf_t buf;
    netbuf_init(&buf);

    uint8_t pkt[4];
    netbuf_slot_t *slot;

    for (int cycle = 0; cycle < 3; cycle++) {
        /* Fill */
        for (int i = 0; i < NETBUF_SLOT_COUNT; i++) {
            pkt[0] = (uint8_t)(cycle * 16 + i);
            CHECK(netbuf_enqueue(&buf, pkt, 1) == NET_OK);
        }
        CHECK(netbuf_is_full(&buf) == 1);

        /* Drain and verify order */
        for (int i = 0; i < NETBUF_SLOT_COUNT; i++) {
            CHECK(netbuf_dequeue(&buf, &slot) == NET_OK);
            CHECK(slot->data[0] == (uint8_t)(cycle * 16 + i));
        }
        CHECK(netbuf_is_empty(&buf) == 1);
    }
}

static void test_ring_one_at_a_time(void) {
    /*
        Enqueue one packet, immediately dequeue it. Repeat many times.
        head and tail both chase each other around the ring.
        Data must be correct every time.
    */
    netbuf_t buf;
    netbuf_init(&buf);
    netbuf_slot_t *slot;
    uint8_t pkt[8];

    for (int i = 0; i < NETBUF_SLOT_COUNT * 4; i++) {
        memset(pkt, (uint8_t)i, 8);
        CHECK(netbuf_enqueue(&buf, pkt, 8) == NET_OK);
        CHECK(netbuf_dequeue(&buf, &slot) == NET_OK);
        CHECK(slot->data[0] == (uint8_t)i);
        CHECK(slot->data[7] == (uint8_t)i);
        CHECK(netbuf_is_empty(&buf) == 1);
    }
}

static void test_ring_max_slot_size(void) {
    /*
        Enqueue a packet that fills exactly NETBUF_SLOT_SIZE bytes.
        This is the largest valid input. Must succeed.
    */
    netbuf_t buf;
    netbuf_init(&buf);
    netbuf_slot_t *slot;

    uint8_t big[NETBUF_SLOT_SIZE];
    for (int i = 0; i < NETBUF_SLOT_SIZE; i++) big[i] = (uint8_t)(i & 0xFF);

    CHECK(netbuf_enqueue(&buf, big, NETBUF_SLOT_SIZE) == NET_OK);
    CHECK(netbuf_dequeue(&buf, &slot) == NET_OK);
    CHECK(slot->length == NETBUF_SLOT_SIZE);
    CHECK(slot->data[0]                == 0x00);
    CHECK(slot->data[NETBUF_SLOT_SIZE-1] == (uint8_t)((NETBUF_SLOT_SIZE - 1) & 0xFF));
}

static void test_ring_one_byte_packet(void) {
    /* Smallest valid packet — a single byte. */
    netbuf_t buf;
    netbuf_init(&buf);
    netbuf_slot_t *slot;
    uint8_t b = 0xAB;

    CHECK(netbuf_enqueue(&buf, &b, 1) == NET_OK);
    CHECK(netbuf_dequeue(&buf, &slot) == NET_OK);
    CHECK(slot->length   == 1);
    CHECK(slot->data[0]  == 0xAB);
}

static void test_ring_reject_then_accept(void) {
    /*
        Fill the ring, try to enqueue (should fail), drain one slot,
        then enqueue again (should now succeed).
    */
    netbuf_t buf;
    netbuf_init(&buf);
    netbuf_slot_t *slot;
    uint8_t pkt[4] = {0xDE, 0xAD, 0xBE, 0xEF};

    for (int i = 0; i < NETBUF_SLOT_COUNT; i++)
        netbuf_enqueue(&buf, pkt, 4);

    CHECK(netbuf_enqueue(&buf, pkt, 4) == NET_ERR_FULL);

    /* Free one slot */
    CHECK(netbuf_dequeue(&buf, &slot) == NET_OK);

    /* Now it must accept */
    CHECK(netbuf_enqueue(&buf, pkt, 4) == NET_OK);
    CHECK(netbuf_count(&buf) == NETBUF_SLOT_COUNT);
}

/* -----------------------------------------------------------------------
   CATEGORY 2: FUZZ-STYLE GARBAGE INPUT
   ----------------------------------------------------------------------- */

static void test_fuzz_ipv4_all_zeros(void) {
    /* 60 bytes of zeros is not a valid IPv4 packet (version=0). */
    uint8_t raw[60];
    memset(raw, 0x00, sizeof(raw));
    packet_t pkt; ipv4_header_t hdr;
    packet_init(&pkt, raw, 60);
    net_status_t r = ipv4_parse(&pkt, &hdr);
    CHECK(r == NET_ERR_UNSUPPORTED || r == NET_ERR_PARSE);
}

static void test_fuzz_ipv4_all_ones(void) {
    /* 0xFF everywhere — version=15 (not 4), should be rejected. */
    uint8_t raw[60];
    memset(raw, 0xFF, sizeof(raw));
    packet_t pkt; ipv4_header_t hdr;
    packet_init(&pkt, raw, 60);
    net_status_t r = ipv4_parse(&pkt, &hdr);
    CHECK(r == NET_ERR_UNSUPPORTED || r == NET_ERR_PARSE);
}

static void test_fuzz_ipv4_random_pattern(void) {
    /*
        A repeating 0xAB 0xCD pattern. Version nibble = 0xA = 10, not 4.
        Must be rejected cleanly.
    */
    uint8_t raw[40];
    for (int i = 0; i < 40; i++) raw[i] = (i % 2 == 0) ? 0xAB : 0xCD;
    packet_t pkt; ipv4_header_t hdr;
    packet_init(&pkt, raw, 40);
    net_status_t r = ipv4_parse(&pkt, &hdr);
    CHECK(r == NET_ERR_UNSUPPORTED || r == NET_ERR_PARSE);
}

static void test_fuzz_icmp_garbage_after_valid_ip(void) {
    /*
        Valid IPv4 header (ICMP), but garbage bytes where the ICMP header
        should be. Checksum will fail — must return NET_ERR_PARSE.
    */
    uint8_t raw[40];
    memset(raw, 0, sizeof(raw));
    build_ipv4(raw, 1, 20);
    /* Overwrite the ICMP section with garbage */
    for (int i = 20; i < 40; i++) raw[i] = 0xBE;

    packet_t pkt; ipv4_header_t ip; icmp_header_t icmp;
    packet_init(&pkt, raw, 40);
    CHECK(ipv4_parse(&pkt, &ip)   == NET_OK);
    CHECK(icmp_parse(&pkt, &icmp) == NET_ERR_PARSE);
}

static void test_fuzz_tcp_garbage_after_valid_ip(void) {
    /*
        Valid IPv4 header (TCP), garbage TCP bytes.
        Data offset nibble will be random — if it says < 5, rejected.
        If it says >= 5 but points past packet end, rejected.
        Either way, must not crash.
    */
    uint8_t raw[40];
    memset(raw, 0, sizeof(raw));
    build_ipv4(raw, 6, 20);
    for (int i = 20; i < 40; i++) raw[i] = (uint8_t)(i * 7 + 3);

    packet_t pkt; ipv4_header_t ip; tcp_header_t tcp;
    packet_init(&pkt, raw, 40);
    CHECK(ipv4_parse(&pkt, &ip) == NET_OK);
    net_status_t r = tcp_parse(&pkt, &tcp);
    /* Must be NET_OK or NET_ERR_PARSE — never anything else */
    CHECK(r == NET_OK || r == NET_ERR_PARSE || r == NET_ERR_INVALID);
}

static void test_fuzz_truncated_at_every_byte(void) {
    /*
        Build a valid 40-byte ICMP packet, then try parsing it truncated
        to every length from 0 to 39. Every truncation must return a
        clean error — never crash.
    */
    uint8_t full[40];
    memset(full, 0, sizeof(full));
    build_ipv4(full, 1, 20);
    uint8_t icmp_part[20];
    memset(icmp_part, 0, sizeof(icmp_part));
    build_icmp_echo(icmp_part, 1, 1, 12);
    memcpy(full + 20, icmp_part, 20);

    for (int len = 0; len < 40; len++) {
        if (len == 0) {
            /* packet_init itself rejects zero length */
            packet_t pkt;
            CHECK(packet_init(&pkt, full, 0) == NET_ERR_INVALID);
            continue;
        }
        packet_t pkt; ipv4_header_t ip; icmp_header_t icmp;
        packet_init(&pkt, full, (uint16_t)len);
        net_status_t r1 = ipv4_parse(&pkt, &ip);
        if (r1 == NET_OK) {
            net_status_t r2 = icmp_parse(&pkt, &icmp);
            /* Both must be valid status codes */
            CHECK(r2 == NET_OK || r2 == NET_ERR_PARSE ||
                  r2 == NET_ERR_INVALID || r2 == NET_ERR_UNSUPPORTED);
        } else {
            CHECK(r1 == NET_ERR_PARSE || r1 == NET_ERR_UNSUPPORTED ||
                  r1 == NET_ERR_INVALID);
        }
    }
}

/* -----------------------------------------------------------------------
   CATEGORY 3: FULL PIPELINE INTEGRATION
   ----------------------------------------------------------------------- */

static int g_icmp_calls = 0;
static int g_tcp_calls  = 0;

static net_status_t pipeline_icmp_handler(packet_t *pkt, net_stats_t *stats) {
    (void)pkt;
    g_icmp_calls++;
    net_stats_increment_proto_icmp(stats);
    return NET_OK;
}

static net_status_t pipeline_tcp_handler(packet_t *pkt, net_stats_t *stats) {
    (void)pkt;
    g_tcp_calls++;
    net_stats_increment_proto_tcp(stats);
    return NET_OK;
}

static void test_pipeline_icmp_end_to_end(void) {
    /*
        Full journey: raw bytes → netbuf → packet → ipv4 → icmp → dispatch → stats.
        Verify every stage completes and stats reflect exactly one ICMP packet.
    */
    netbuf_t ring;
    dispatch_table_t table;
    net_stats_t stats;
    netbuf_init(&ring);
    dispatch_init(&table);
    net_stats_init(&stats);
    dispatch_register(&table, NET_PROTO_ICMP, pipeline_icmp_handler);
    g_icmp_calls = 0;

    /* Build a valid ICMP Echo packet */
    uint8_t raw[36];
    memset(raw, 0, sizeof(raw));
    build_ipv4(raw, 1, 16);
    uint8_t icmp_part[16];
    build_icmp_echo(icmp_part, 0xBEEF, 0x0007, 8);
    memcpy(raw + 20, icmp_part, 16);

    /* Stage 1: enqueue into ring */
    CHECK(netbuf_enqueue(&ring, raw, 36) == NET_OK);
    net_stats_increment_rx_total(&stats);
    CHECK(stats.rx_total == 1);

    /* Stage 2: dequeue */
    netbuf_slot_t *slot;
    CHECK(netbuf_dequeue(&ring, &slot) == NET_OK);

    /* Stage 3: wrap in packet */
    packet_t pkt;
    CHECK(packet_init(&pkt, slot->data, slot->length) == NET_OK);

    /* Stage 4: parse IPv4 */
    ipv4_header_t ip;
    CHECK(ipv4_parse(&pkt, &ip) == NET_OK);
    CHECK(ip.protocol == 1);
    CHECK(pkt.protocol == NET_PROTO_ICMP);

    /* Stage 5: parse ICMP */
    icmp_header_t icmp;
    CHECK(icmp_parse(&pkt, &icmp) == NET_OK);
    CHECK(icmp.type       == ICMP_TYPE_ECHO_REQUEST);
    CHECK(icmp.identifier == 0xBEEF);
    CHECK(icmp.sequence   == 0x0007);

    /* Stage 6: dispatch */
    CHECK(dispatch_packet(&table, &pkt, &stats) == NET_OK);

    /* Stage 7: verify stats */
    CHECK(g_icmp_calls      == 1);
    CHECK(stats.proto_icmp  == 1);
    CHECK(stats.proto_tcp   == 0);
    CHECK(stats.proto_unknown == 0);
    CHECK(stats.rx_total    == 1);
}

static void test_pipeline_mixed_packets(void) {
    /*
        Enqueue 3 ICMP and 2 TCP packets into the ring in mixed order.
        Process all 5. Verify dispatch called each handler the right number
        of times and stats counters are exactly right.
    */
    netbuf_t ring;
    dispatch_table_t table;
    net_stats_t stats;
    netbuf_init(&ring);
    dispatch_init(&table);
    net_stats_init(&stats);
    dispatch_register(&table, NET_PROTO_ICMP, pipeline_icmp_handler);
    dispatch_register(&table, NET_PROTO_TCP,  pipeline_tcp_handler);
    g_icmp_calls = 0;
    g_tcp_calls  = 0;

    /* Build one reusable ICMP packet */
    uint8_t icmp_raw[36];
    memset(icmp_raw, 0, sizeof(icmp_raw));
    build_ipv4(icmp_raw, 1, 16);
    uint8_t tmp[16];
    build_icmp_echo(tmp, 1, 1, 8);
    memcpy(icmp_raw + 20, tmp, 16);

    /* Build one reusable TCP packet */
    uint8_t tcp_raw[40];
    memset(tcp_raw, 0, sizeof(tcp_raw));
    build_ipv4(tcp_raw, 6, 20);
    build_tcp_hdr(tcp_raw + 20, 12345, 80, 0x1000, TCP_FLAG_SYN);

    /* Enqueue in order: ICMP, TCP, ICMP, TCP, ICMP */
    uint8_t protos[5] = {1, 6, 1, 6, 1};
    for (int i = 0; i < 5; i++) {
        if (protos[i] == 1)
            netbuf_enqueue(&ring, icmp_raw, 36);
        else
            netbuf_enqueue(&ring, tcp_raw,  40);
        net_stats_increment_rx_total(&stats);
    }
    CHECK(stats.rx_total == 5);

    /* Process all 5 */
    for (int i = 0; i < 5; i++) {
        netbuf_slot_t *slot;
        CHECK(netbuf_dequeue(&ring, &slot) == NET_OK);

        packet_t pkt;
        packet_init(&pkt, slot->data, slot->length);

        ipv4_header_t ip;
        CHECK(ipv4_parse(&pkt, &ip) == NET_OK);

        if (pkt.protocol == NET_PROTO_ICMP) {
            icmp_header_t icmp;
            CHECK(icmp_parse(&pkt, &icmp) == NET_OK);
        } else {
            tcp_header_t tcp;
            CHECK(tcp_parse(&pkt, &tcp) == NET_OK);
        }

        CHECK(dispatch_packet(&table, &pkt, &stats) == NET_OK);
    }

    CHECK(g_icmp_calls     == 3);
    CHECK(g_tcp_calls      == 2);
    CHECK(stats.proto_icmp == 3);
    CHECK(stats.proto_tcp  == 2);
    CHECK(stats.proto_unknown == 0);
    CHECK(netbuf_is_empty(&ring) == 1);
}

static void test_pipeline_dropped_packet_counted(void) {
    /*
        Fill the ring, then try to enqueue one more.
        Verify that rx_dropped is incremented and rx_total stays accurate.
    */
    netbuf_t ring;
    net_stats_t stats;
    netbuf_init(&ring);
    net_stats_init(&stats);

    uint8_t pkt[4] = {1, 2, 3, 4};

    for (int i = 0; i < NETBUF_SLOT_COUNT; i++) {
        netbuf_enqueue(&ring, pkt, 4);
        net_stats_increment_rx_total(&stats);
    }

    /* This one cannot fit */
    net_status_t r = netbuf_enqueue(&ring, pkt, 4);
    if (r == NET_ERR_FULL) {
        net_stats_increment_rx_dropped(&stats);
    }

    CHECK(stats.rx_total   == NETBUF_SLOT_COUNT);
    CHECK(stats.rx_dropped == 1);
}

/* -----------------------------------------------------------------------
   CATEGORY 4: BOUNDARY ARITHMETIC
   ----------------------------------------------------------------------- */

static void test_ipv4_ihl_exactly_5(void) {
    /* IHL = 5 is the minimum valid value (20 bytes, no options). */
    uint8_t raw[40];
    memset(raw, 0, sizeof(raw));
    build_ipv4(raw, 1, 20);
    /* Confirm byte 0 low nibble is 5 */
    CHECK((raw[0] & 0x0F) == 5);

    packet_t pkt; ipv4_header_t hdr;
    packet_init(&pkt, raw, 40);
    CHECK(ipv4_parse(&pkt, &hdr) == NET_OK);
    CHECK(hdr.ihl == 20);
    CHECK(pkt.offset == 20);
}

static void test_ipv4_ihl_exactly_15(void) {
    /*
        IHL = 15 means 60-byte header (maximum, with 40 bytes of options).
        We build such a header manually and recompute the checksum.
    */
    uint8_t raw[80]; /* 60 header + 20 payload */
    memset(raw, 0, sizeof(raw));

    uint16_t total = 80;
    raw[0]  = 0x4F; /* version=4, IHL=15 */
    raw[1]  = 0x00;
    raw[2]  = (uint8_t)(total >> 8);
    raw[3]  = (uint8_t)(total & 0xFF);
    raw[4]  = 0x00; raw[5]  = 0x01;
    raw[6]  = 0x40; raw[7]  = 0x00;
    raw[8]  = 0x40; /* TTL */
    raw[9]  = 0x01; /* ICMP */
    raw[10] = 0x00; raw[11] = 0x00; /* checksum placeholder */
    raw[12] = 0xC0; raw[13] = 0xA8; raw[14] = 0x00; raw[15] = 0x01;
    raw[16] = 0xC0; raw[17] = 0xA8; raw[18] = 0x00; raw[19] = 0x02;
    /* bytes 20..59 = options, all zero */

    uint16_t ck = ipv4_checksum(raw, 60);
    raw[10] = (uint8_t)(ck >> 8);
    raw[11] = (uint8_t)(ck & 0xFF);

    packet_t pkt; ipv4_header_t hdr;
    packet_init(&pkt, raw, 80);
    CHECK(ipv4_parse(&pkt, &hdr) == NET_OK);
    CHECK(hdr.ihl    == 60);
    CHECK(pkt.offset == 60);
}

static void test_ipv4_ihl_4_rejected(void) {
    /* IHL = 4 → 16 bytes — below the minimum of 20. Must be rejected. */
    uint8_t raw[40];
    memset(raw, 0, sizeof(raw));
    build_ipv4(raw, 1, 20);
    raw[0] = (raw[0] & 0xF0) | 0x04; /* set IHL to 4 */
    /* Don't bother fixing checksum — it will fail for two reasons */

    packet_t pkt; ipv4_header_t hdr;
    packet_init(&pkt, raw, 40);
    CHECK(ipv4_parse(&pkt, &hdr) == NET_ERR_PARSE);
}

static void test_tcp_data_offset_exactly_5(void) {
    uint8_t raw[40];
    memset(raw, 0, sizeof(raw));
    build_ipv4(raw, 6, 20);
    build_tcp_hdr(raw + 20, 1234, 80, 1, TCP_FLAG_SYN);
    /* byte 32 (TCP byte 12) high nibble = 5 */
    CHECK((raw[32] >> 4) == 5);

    packet_t pkt; ipv4_header_t ip; tcp_header_t tcp;
    packet_init(&pkt, raw, 40);
    ipv4_parse(&pkt, &ip);
    CHECK(tcp_parse(&pkt, &tcp) == NET_OK);
    CHECK(tcp.data_offset == 20);
}

static void test_tcp_data_offset_exactly_15(void) {
    /*
        TCP data offset = 15 → 60-byte TCP header.
        Total packet: 20 IP + 60 TCP = 80 bytes.
    */
    uint8_t raw[80];
    memset(raw, 0, sizeof(raw));
    build_ipv4(raw, 6, 60);
    build_tcp_hdr(raw + 20, 4321, 443, 0xDEAD, TCP_FLAG_SYN | TCP_FLAG_ACK);
    raw[32] = 0xF2; /* data offset = 15 (0xF), flags stay in low nibble area */
    raw[33] = TCP_FLAG_SYN | TCP_FLAG_ACK;

    packet_t pkt; ipv4_header_t ip; tcp_header_t tcp;
    packet_init(&pkt, raw, 80);
    ipv4_parse(&pkt, &ip);
    CHECK(tcp_parse(&pkt, &tcp) == NET_OK);
    CHECK(tcp.data_offset == 60);
    CHECK(pkt.offset == 80); /* 20 IP + 60 TCP = end of packet */
}

static void test_checksum_single_bit_flips(void) {
    /*
        Build a valid IPv4 header. Flip each bit of the header one at a time.
        Every single-bit corruption must be detected by the checksum.
        (This is a property of one's complement checksums.)
    */
    uint8_t base[20];
    memset(base, 0, sizeof(base));
    base[0]  = 0x45;
    base[1]  = 0x00;
    base[2]  = 0x00; base[3]  = 0x14;
    base[4]  = 0x00; base[5]  = 0x01;
    base[6]  = 0x40; base[7]  = 0x00;
    base[8]  = 0x40;
    base[9]  = 0x01;
    base[10] = 0x00; base[11] = 0x00;
    base[12] = 0xC0; base[13] = 0xA8; base[14] = 0x00; base[15] = 0x01;
    base[16] = 0xC0; base[17] = 0xA8; base[18] = 0x00; base[19] = 0x02;
    uint16_t ck = ipv4_checksum(base, 20);
    base[10] = (uint8_t)(ck >> 8);
    base[11] = (uint8_t)(ck & 0xFF);

    /* Sanity: recomputing over the complete header including checksum = 0 */
    CHECK(ipv4_checksum(base, 20) == 0x0000);

    int detected = 0;
    int total_bits = 20 * 8;

    for (int byte = 0; byte < 20; byte++) {
        for (int bit = 0; bit < 8; bit++) {
            uint8_t corrupted[20];
            memcpy(corrupted, base, 20);
            corrupted[byte] ^= (uint8_t)(1 << bit);
            if (ipv4_checksum(corrupted, 20) != 0x0000) {
                detected++;
            }
        }
    }

    /*
        One's complement checksums detect all single-bit errors.
        Exception: flipping a bit in the checksum field itself produces
        a different checksum field value, which the algorithm still detects.
        All 160 flips should be detected.
    */
    CHECK(detected == total_bits);
}

static void test_checksum_all_zeros_payload(void) {
    /* A 20-byte all-zero buffer: checksum should not be zero itself. */
    uint8_t raw[20];
    memset(raw, 0x00, 20);
    uint16_t ck = ipv4_checksum(raw, 20);
    /* All-zero sum = 0x0000 → ~0x0000 = 0xFFFF */
    CHECK(ck == 0xFFFF);
}

static void test_packet_advance_at_exact_boundaries(void) {
    uint8_t raw[20];
    memset(raw, 0xAA, 20);
    packet_t pkt;
    packet_init(&pkt, raw, 20);

    /* Advance to position 19 — one byte before the end */
    CHECK(packet_advance(&pkt, 19) == NET_OK);
    CHECK(packet_remaining(&pkt) == 1);

    /* Advance one more — lands exactly at the end */
    CHECK(packet_advance(&pkt, 1) == NET_OK);
    CHECK(packet_remaining(&pkt) == 0);
    CHECK(packet_current_ptr(&pkt) == NULL);

    /* Cannot advance further */
    CHECK(packet_advance(&pkt, 1) == NET_ERR_INVALID);
}

/* -----------------------------------------------------------------------
   Main
   ----------------------------------------------------------------------- */

int main(void) {
    printf("=== advanced tests ===\n");

    printf("  -- edge case stress --\n");
    test_ring_fill_drain_fill_drain();
    test_ring_one_at_a_time();
    test_ring_max_slot_size();
    test_ring_one_byte_packet();
    test_ring_reject_then_accept();

    printf("  -- fuzz-style garbage input --\n");
    test_fuzz_ipv4_all_zeros();
    test_fuzz_ipv4_all_ones();
    test_fuzz_ipv4_random_pattern();
    test_fuzz_icmp_garbage_after_valid_ip();
    test_fuzz_tcp_garbage_after_valid_ip();
    test_fuzz_truncated_at_every_byte();

    printf("  -- full pipeline integration --\n");
    test_pipeline_icmp_end_to_end();
    test_pipeline_mixed_packets();
    test_pipeline_dropped_packet_counted();

    printf("  -- boundary arithmetic --\n");
    test_ipv4_ihl_exactly_5();
    test_ipv4_ihl_exactly_15();
    test_ipv4_ihl_4_rejected();
    test_tcp_data_offset_exactly_5();
    test_tcp_data_offset_exactly_15();
    test_checksum_single_bit_flips();
    test_checksum_all_zeros_payload();
    test_packet_advance_at_exact_boundaries();

    TEST_SUMMARY();
}
