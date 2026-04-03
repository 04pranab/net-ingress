/*
    test_dispatch.c — Tests for Internal Packet Dispatch

    We test that handlers can be registered and invoked, that unregistered
    protocols are rejected with NET_ERR_UNSUPPORTED, and that stats are
    updated correctly through the dispatch path.

    Because dispatch_handler_fn is just a function pointer, we can write
    simple stub handlers here that record whether they were called.
*/

#include "test_harness.h"
#include "../include/dispatch.h"
#include "../include/net_stats.h"
#include "../include/packet.h"
#include <string.h>

/* -----------------------------------------------------------------------
   Stub handlers — record call counts so we can verify dispatch routing.
   ----------------------------------------------------------------------- */

static int icmp_handler_called = 0;
static int tcp_handler_called  = 0;

static net_status_t stub_icmp_handler(packet_t *pkt, net_stats_t *stats) {
    (void)pkt;
    icmp_handler_called++;
    net_stats_increment_proto_icmp(stats);
    return NET_OK;
}

static net_status_t stub_tcp_handler(packet_t *pkt, net_stats_t *stats) {
    (void)pkt;
    tcp_handler_called++;
    net_stats_increment_proto_tcp(stats);
    return NET_OK;
}

/* -----------------------------------------------------------------------
   Helper: build a minimal packet_t with a given protocol already set.
   We do not need real bytes here — dispatch only looks at pkt->protocol.
   ----------------------------------------------------------------------- */

static void make_pkt(packet_t *pkt, net_protocol_t proto) {
    static uint8_t dummy[20];
    packet_init(pkt, dummy, 20);
    pkt->protocol = proto;
}

/* -----------------------------------------------------------------------
   Tests
   ----------------------------------------------------------------------- */

static void test_dispatch_init_null(void) {
    CHECK(dispatch_init(NULL) == NET_ERR_INVALID);
}

static void test_dispatch_register_null(void) {
    dispatch_table_t table;
    dispatch_init(&table);
    CHECK(dispatch_register(NULL,   NET_PROTO_ICMP, stub_icmp_handler) == NET_ERR_INVALID);
    CHECK(dispatch_register(&table, NET_PROTO_ICMP, NULL)              == NET_ERR_INVALID);
}

static void test_dispatch_unregistered_protocol(void) {
    dispatch_table_t table;
    net_stats_t stats;
    packet_t pkt;
    dispatch_init(&table);
    net_stats_init(&stats);
    make_pkt(&pkt, NET_PROTO_TCP);  /* TCP not registered */

    CHECK(dispatch_packet(&table, &pkt, &stats) == NET_ERR_UNSUPPORTED);
    /* Unknown counter should have been incremented. */
    CHECK(stats.proto_unknown == 1);
}

static void test_dispatch_routes_icmp(void) {
    dispatch_table_t table;
    net_stats_t stats;
    packet_t pkt;
    dispatch_init(&table);
    net_stats_init(&stats);
    icmp_handler_called = 0;

    dispatch_register(&table, NET_PROTO_ICMP, stub_icmp_handler);
    make_pkt(&pkt, NET_PROTO_ICMP);

    CHECK(dispatch_packet(&table, &pkt, &stats) == NET_OK);
    CHECK(icmp_handler_called == 1);
    CHECK(stats.proto_icmp    == 1);
    CHECK(stats.proto_unknown == 0);
}

static void test_dispatch_routes_tcp(void) {
    dispatch_table_t table;
    net_stats_t stats;
    packet_t pkt;
    dispatch_init(&table);
    net_stats_init(&stats);
    tcp_handler_called = 0;

    dispatch_register(&table, NET_PROTO_TCP, stub_tcp_handler);
    make_pkt(&pkt, NET_PROTO_TCP);

    CHECK(dispatch_packet(&table, &pkt, &stats) == NET_OK);
    CHECK(tcp_handler_called == 1);
    CHECK(stats.proto_tcp    == 1);
}

static void test_dispatch_routes_correctly_with_both_registered(void) {
    dispatch_table_t table;
    net_stats_t stats;
    packet_t pkt;
    dispatch_init(&table);
    net_stats_init(&stats);
    icmp_handler_called = 0;
    tcp_handler_called  = 0;

    dispatch_register(&table, NET_PROTO_ICMP, stub_icmp_handler);
    dispatch_register(&table, NET_PROTO_TCP,  stub_tcp_handler);

    /* Dispatch ICMP — only ICMP handler should fire. */
    make_pkt(&pkt, NET_PROTO_ICMP);
    dispatch_packet(&table, &pkt, &stats);
    CHECK(icmp_handler_called == 1);
    CHECK(tcp_handler_called  == 0);

    /* Dispatch TCP — only TCP handler should fire. */
    make_pkt(&pkt, NET_PROTO_TCP);
    dispatch_packet(&table, &pkt, &stats);
    CHECK(icmp_handler_called == 1);  /* unchanged */
    CHECK(tcp_handler_called  == 1);
}

static void test_dispatch_null_args(void) {
    dispatch_table_t table;
    net_stats_t stats;
    packet_t pkt;
    dispatch_init(&table);
    net_stats_init(&stats);
    make_pkt(&pkt, NET_PROTO_ICMP);

    CHECK(dispatch_packet(NULL,   &pkt,  &stats) == NET_ERR_INVALID);
    CHECK(dispatch_packet(&table, NULL,  &stats) == NET_ERR_INVALID);
    CHECK(dispatch_packet(&table, &pkt,  NULL)   == NET_ERR_INVALID);
}

/* -----------------------------------------------------------------------
   Main
   ----------------------------------------------------------------------- */

int main(void) {
    printf("=== dispatch tests ===\n");

    test_dispatch_init_null();
    test_dispatch_register_null();
    test_dispatch_unregistered_protocol();
    test_dispatch_routes_icmp();
    test_dispatch_routes_tcp();
    test_dispatch_routes_correctly_with_both_registered();
    test_dispatch_null_args();

    TEST_SUMMARY();
}
