/*
    test_packet.c — Tests for the Packet Abstraction

    packet_t is the cursor we move through raw bytes during parsing.
    These tests verify that the cursor initialises correctly, advances
    correctly, stays in bounds, and exposes the right pointers.
*/

#include "test_harness.h"
#include "../include/packet.h"
#include <string.h>

static const uint8_t sample[20] = {
    0x45, 0x00, 0x00, 0x28, /* IPv4 byte 0–3  (version, IHL, len) */
    0x00, 0x01, 0x40, 0x00, /* bytes 4–7                          */
    0x40, 0x01, 0xf4, 0xf7, /* bytes 8–11  (TTL, proto=ICMP, cksum) */
    0x7f, 0x00, 0x00, 0x01, /* src 127.0.0.1                      */
    0x7f, 0x00, 0x00, 0x01  /* dst 127.0.0.1                      */
};

/* -----------------------------------------------------------------------
   packet_init
   ----------------------------------------------------------------------- */

static void test_init_null_pkt(void) {
    CHECK(packet_init(NULL, sample, sizeof(sample)) == NET_ERR_INVALID);
}

static void test_init_null_data(void) {
    packet_t pkt;
    CHECK(packet_init(&pkt, NULL, 20) == NET_ERR_INVALID);
}

static void test_init_zero_length(void) {
    packet_t pkt;
    CHECK(packet_init(&pkt, sample, 0) == NET_ERR_INVALID);
}

static void test_init_sets_fields(void) {
    packet_t pkt;
    CHECK(packet_init(&pkt, sample, sizeof(sample)) == NET_OK);
    CHECK(pkt.raw      == sample);
    CHECK(pkt.length   == sizeof(sample));
    CHECK(pkt.offset   == 0);
    CHECK(pkt.protocol == NET_PROTO_UNKNOWN);
}

/* -----------------------------------------------------------------------
   packet_remaining
   ----------------------------------------------------------------------- */

static void test_remaining_full(void) {
    packet_t pkt;
    packet_init(&pkt, sample, 20);
    CHECK(packet_remaining(&pkt) == 20);
}

static void test_remaining_null(void) {
    CHECK(packet_remaining(NULL) == 0);
}

static void test_remaining_after_advance(void) {
    packet_t pkt;
    packet_init(&pkt, sample, 20);
    packet_advance(&pkt, 5);
    CHECK(packet_remaining(&pkt) == 15);
}

static void test_remaining_at_end(void) {
    packet_t pkt;
    packet_init(&pkt, sample, 20);
    packet_advance(&pkt, 20);
    CHECK(packet_remaining(&pkt) == 0);
}

/* -----------------------------------------------------------------------
   packet_current_ptr
   ----------------------------------------------------------------------- */

static void test_current_ptr_at_start(void) {
    packet_t pkt;
    packet_init(&pkt, sample, 20);
    /* At offset 0, the pointer should equal the raw pointer. */
    CHECK(packet_current_ptr(&pkt) == sample);
}

static void test_current_ptr_after_advance(void) {
    packet_t pkt;
    packet_init(&pkt, sample, 20);
    packet_advance(&pkt, 4);
    /* After advancing 4 bytes, the pointer should be sample + 4. */
    CHECK(packet_current_ptr(&pkt) == sample + 4);
    CHECK(*packet_current_ptr(&pkt) == sample[4]);
}

static void test_current_ptr_at_end(void) {
    packet_t pkt;
    packet_init(&pkt, sample, 20);
    packet_advance(&pkt, 20);
    /* Past the end — must return NULL, not a dangling pointer. */
    CHECK(packet_current_ptr(&pkt) == NULL);
}

static void test_current_ptr_null_pkt(void) {
    CHECK(packet_current_ptr(NULL) == NULL);
}

/* -----------------------------------------------------------------------
   packet_advance
   ----------------------------------------------------------------------- */

static void test_advance_null(void) {
    CHECK(packet_advance(NULL, 4) == NET_ERR_INVALID);
}

static void test_advance_zero(void) {
    packet_t pkt;
    packet_init(&pkt, sample, 20);
    /* Advancing by zero is invalid — it would do nothing and is likely a bug. */
    CHECK(packet_advance(&pkt, 0) == NET_ERR_INVALID);
}

static void test_advance_exact_end(void) {
    packet_t pkt;
    packet_init(&pkt, sample, 20);
    /* Advancing exactly to the end is valid. */
    CHECK(packet_advance(&pkt, 20) == NET_OK);
    CHECK(pkt.offset == 20);
}

static void test_advance_past_end(void) {
    packet_t pkt;
    packet_init(&pkt, sample, 20);
    /* Advancing one byte past the end must fail. */
    CHECK(packet_advance(&pkt, 21) == NET_ERR_INVALID);
    /* Offset must not have changed. */
    CHECK(pkt.offset == 0);
}

static void test_advance_incremental(void) {
    packet_t pkt;
    packet_init(&pkt, sample, 20);

    CHECK(packet_advance(&pkt, 5) == NET_OK);
    CHECK(pkt.offset == 5);
    CHECK(packet_advance(&pkt, 10) == NET_OK);
    CHECK(pkt.offset == 15);
    CHECK(packet_advance(&pkt, 5) == NET_OK);
    CHECK(pkt.offset == 20);
    /* Now at the end — one more byte should fail. */
    CHECK(packet_advance(&pkt, 1) == NET_ERR_INVALID);
}

/* -----------------------------------------------------------------------
   Main
   ----------------------------------------------------------------------- */

int main(void) {
    printf("=== packet tests ===\n");

    test_init_null_pkt();
    test_init_null_data();
    test_init_zero_length();
    test_init_sets_fields();
    test_remaining_full();
    test_remaining_null();
    test_remaining_after_advance();
    test_remaining_at_end();
    test_current_ptr_at_start();
    test_current_ptr_after_advance();
    test_current_ptr_at_end();
    test_current_ptr_null_pkt();
    test_advance_null();
    test_advance_zero();
    test_advance_exact_end();
    test_advance_past_end();
    test_advance_incremental();

    TEST_SUMMARY();
}
