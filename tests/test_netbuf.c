/*
    test_netbuf.c — Tests for the Network Ingress Ring Buffer

    We test every function and every error path in netbuf.h.
    The goal is to demonstrate that the ring buffer behaves correctly
    under all conditions: normal use, boundary conditions, and abuse.

    Tests are grouped into sections that follow the same order as
    the public API in netbuf.h.
*/

#include "test_harness.h"
#include "../include/netbuf.h"
#include <string.h>

/* -----------------------------------------------------------------------
   Helper: build a small byte pattern we can recognise after dequeue.
   ----------------------------------------------------------------------- */
static void fill_pattern(uint8_t *buf, uint16_t len, uint8_t seed) {
    for (uint16_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(seed + i);
    }
}

/* -----------------------------------------------------------------------
   1. netbuf_init
   ----------------------------------------------------------------------- */

static void test_init_null(void) {
    /* Passing NULL must return NET_ERR_INVALID, not crash. */
    CHECK(netbuf_init(NULL) == NET_ERR_INVALID);
}

static void test_init_clears_state(void) {
    netbuf_t buf;
    /* Poison the memory first — init must overwrite it. */
    memset(&buf, 0xFF, sizeof(buf));

    CHECK(netbuf_init(&buf) == NET_OK);
    CHECK(buf.head  == 0);
    CHECK(buf.tail  == 0);
    CHECK(buf.count == 0);
}

/* -----------------------------------------------------------------------
   2. netbuf_is_empty / netbuf_is_full / netbuf_count
   ----------------------------------------------------------------------- */

static void test_queries_after_init(void) {
    netbuf_t buf;
    netbuf_init(&buf);

    CHECK(netbuf_is_empty(&buf) == 1);
    CHECK(netbuf_is_full (&buf) == 0);
    CHECK(netbuf_count   (&buf) == 0);
}

static void test_queries_with_null(void) {
    /* NULL pointers must not crash — return safe defaults. */
    CHECK(netbuf_is_empty(NULL) == 1);
    CHECK(netbuf_is_full (NULL) == 0);
    CHECK(netbuf_count   (NULL) == 0);
}

/* -----------------------------------------------------------------------
   3. netbuf_enqueue
   ----------------------------------------------------------------------- */

static void test_enqueue_null_buf(void) {
    uint8_t data[4] = {0};
    CHECK(netbuf_enqueue(NULL, data, 4) == NET_ERR_INVALID);
}

static void test_enqueue_null_data(void) {
    netbuf_t buf;
    netbuf_init(&buf);
    CHECK(netbuf_enqueue(&buf, NULL, 4) == NET_ERR_INVALID);
}

static void test_enqueue_zero_length(void) {
    netbuf_t buf;
    uint8_t data[4] = {0};
    netbuf_init(&buf);
    CHECK(netbuf_enqueue(&buf, data, 0) == NET_ERR_INVALID);
}

static void test_enqueue_oversized(void) {
    netbuf_t buf;
    uint8_t data[NETBUF_SLOT_SIZE + 1];
    netbuf_init(&buf);
    /* One byte more than the slot can hold — must be rejected. */
    CHECK(netbuf_enqueue(&buf, data, NETBUF_SLOT_SIZE + 1) == NET_ERR_INVALID);
}

static void test_enqueue_single_packet(void) {
    netbuf_t buf;
    uint8_t data[10];
    fill_pattern(data, 10, 0xAA);
    netbuf_init(&buf);

    CHECK(netbuf_enqueue(&buf, data, 10) == NET_OK);
    CHECK(netbuf_count(&buf) == 1);
    CHECK(netbuf_is_empty(&buf) == 0);
    CHECK(netbuf_is_full (&buf) == 0);
}

static void test_enqueue_fills_ring(void) {
    netbuf_t buf;
    uint8_t data[8] = {1,2,3,4,5,6,7,8};
    netbuf_init(&buf);

    /* Fill every slot. */
    for (int i = 0; i < NETBUF_SLOT_COUNT; i++) {
        CHECK(netbuf_enqueue(&buf, data, 8) == NET_OK);
    }

    CHECK(netbuf_is_full(&buf) == 1);
    CHECK(netbuf_count  (&buf) == NETBUF_SLOT_COUNT);
}

static void test_enqueue_when_full(void) {
    netbuf_t buf;
    uint8_t data[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    netbuf_init(&buf);

    for (int i = 0; i < NETBUF_SLOT_COUNT; i++) {
        netbuf_enqueue(&buf, data, 4);
    }

    /* One more — must be rejected. */
    CHECK(netbuf_enqueue(&buf, data, 4) == NET_ERR_FULL);
    /* Count must not have changed. */
    CHECK(netbuf_count(&buf) == NETBUF_SLOT_COUNT);
}

/* -----------------------------------------------------------------------
   4. netbuf_dequeue
   ----------------------------------------------------------------------- */

static void test_dequeue_null_buf(void) {
    netbuf_slot_t *slot = NULL;
    CHECK(netbuf_dequeue(NULL, &slot) == NET_ERR_INVALID);
}

static void test_dequeue_null_slot_out(void) {
    netbuf_t buf;
    netbuf_init(&buf);
    CHECK(netbuf_dequeue(&buf, NULL) == NET_ERR_INVALID);
}

static void test_dequeue_empty(void) {
    netbuf_t buf;
    netbuf_slot_t *slot = NULL;
    netbuf_init(&buf);
    CHECK(netbuf_dequeue(&buf, &slot) == NET_ERR_EMPTY);
    CHECK(slot == NULL);  /* Must not have been written to. */
}

static void test_dequeue_recovers_data(void) {
    netbuf_t buf;
    uint8_t data[5] = {0x10, 0x20, 0x30, 0x40, 0x50};
    netbuf_slot_t *slot = NULL;
    netbuf_init(&buf);

    netbuf_enqueue(&buf, data, 5);
    CHECK(netbuf_dequeue(&buf, &slot) == NET_OK);

    /* Verify the slot gives us back exactly what we enqueued. */
    CHECK(slot != NULL);
    CHECK(slot->length == 5);
    CHECK(slot->data[0] == 0x10);
    CHECK(slot->data[1] == 0x20);
    CHECK(slot->data[4] == 0x50);

    /* Buffer should now be empty again. */
    CHECK(netbuf_is_empty(&buf) == 1);
    CHECK(netbuf_count   (&buf) == 0);
}

/* -----------------------------------------------------------------------
   5. Ring wrap-around (the critical ring buffer property)
   ----------------------------------------------------------------------- */

static void test_ring_wraparound(void) {
    /*
        This test verifies that the ring does not stop working after
        indices wrap around. We:
            1. Fill the ring completely.
            2. Drain half of it.
            3. Fill it up again (indices now wrap around).
            4. Drain all of it.
            5. Verify the data came out in the correct FIFO order.
    */
    netbuf_t buf;
    netbuf_init(&buf);

    uint8_t pkt[4];
    netbuf_slot_t *slot;

    /* Step 1: Fill completely (packets 0..N-1). */
    for (int i = 0; i < NETBUF_SLOT_COUNT; i++) {
        pkt[0] = (uint8_t)i;
        netbuf_enqueue(&buf, pkt, 1);
    }

    /* Step 2: Drain half (read packets 0..N/2-1). */
    for (int i = 0; i < NETBUF_SLOT_COUNT / 2; i++) {
        netbuf_dequeue(&buf, &slot);
        CHECK(slot->data[0] == (uint8_t)i);
    }

    /* Step 3: Re-fill the freed slots (packets N..N + N/2 - 1).
       These writes will wrap tail around the end of the array. */
    for (int i = 0; i < NETBUF_SLOT_COUNT / 2; i++) {
        pkt[0] = (uint8_t)(NETBUF_SLOT_COUNT + i);
        netbuf_enqueue(&buf, pkt, 1);
    }

    CHECK(netbuf_is_full(&buf) == 1);

    /* Step 4 & 5: Drain all. Verify FIFO order is preserved. */
    for (int i = NETBUF_SLOT_COUNT / 2; i < NETBUF_SLOT_COUNT; i++) {
        netbuf_dequeue(&buf, &slot);
        CHECK(slot->data[0] == (uint8_t)i);
    }
    for (int i = 0; i < NETBUF_SLOT_COUNT / 2; i++) {
        netbuf_dequeue(&buf, &slot);
        CHECK(slot->data[0] == (uint8_t)(NETBUF_SLOT_COUNT + i));
    }

    CHECK(netbuf_is_empty(&buf) == 1);
}

/* -----------------------------------------------------------------------
   Main
   ----------------------------------------------------------------------- */

int main(void) {
    printf("=== netbuf tests ===\n");

    test_init_null();
    test_init_clears_state();
    test_queries_after_init();
    test_queries_with_null();
    test_enqueue_null_buf();
    test_enqueue_null_data();
    test_enqueue_zero_length();
    test_enqueue_oversized();
    test_enqueue_single_packet();
    test_enqueue_fills_ring();
    test_enqueue_when_full();
    test_dequeue_null_buf();
    test_dequeue_null_slot_out();
    test_dequeue_empty();
    test_dequeue_recovers_data();
    test_ring_wraparound();

    TEST_SUMMARY();
}
