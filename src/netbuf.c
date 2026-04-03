/*
    netbuf.c — Network Ingress Buffer (Implementation)

    This file implements the ring buffer declared in netbuf.h.

    Every function follows the same pattern:
        1. Validate inputs — return NET_ERR_INVALID immediately if anything is wrong.
        2. Check state    — return NET_ERR_FULL or NET_ERR_EMPTY if appropriate.
        3. Do the work    — copy data, advance index, update count.
        4. Return NET_OK.

    This explicit, early-return style is standard in kernel code. There are no
    silent failures, no global error variables, and no printed messages.
    The caller always knows exactly what happened.
*/

#include "netbuf.h"
#include <string.h>

/*
    We use memcpy and memset from <string.h>. These are the only "standard
    library" functions we allow here, and only because they map directly to
    compiler built-ins or single-instruction hardware operations on most
    architectures. They do NOT allocate memory or depend on libc internals.
*/


/* -----------------------------------------------------------------------
   netbuf_init
   ----------------------------------------------------------------------- */

net_status_t netbuf_init(netbuf_t *buf) {
    if (buf == NULL) {
        return NET_ERR_INVALID;
    }

    /*
        Zero the entire struct. This sets:
            - all slot data bytes to 0x00
            - all slot lengths to 0
            - head, tail, count all to 0

        Starting with a zeroed state is important for reproducibility.
        A buffer that is "initialized" should behave identically every time,
        regardless of whatever garbage was in memory before this call.
    */
    memset(buf, 0, sizeof(netbuf_t));
    return NET_OK;
}


/* -----------------------------------------------------------------------
   netbuf_enqueue
   ----------------------------------------------------------------------- */

net_status_t netbuf_enqueue(netbuf_t *buf, const uint8_t *data, uint16_t length) {
    /* Validate arguments first — never proceed with bad inputs. */
    if (buf == NULL || data == NULL) {
        return NET_ERR_INVALID;
    }
    if (length == 0 || length > NETBUF_SLOT_SIZE) {
        return NET_ERR_INVALID;
    }

    /* Check capacity — a full ring cannot accept more data. */
    if (buf->count == NETBUF_SLOT_COUNT) {
        return NET_ERR_FULL;
    }

    /*
        Write into the slot at position 'tail'.
        
        We copy the raw bytes into the slot's data array. This is a deliberate
        ownership transfer: once enqueued, the ring owns the data. The original
        'data' pointer (e.g., a DMA buffer) is free to be reused by hardware.
        
        After copying, we record the length so the dequeue side knows how
        many bytes in this slot are meaningful.
    */
    netbuf_slot_t *slot = &buf->slots[buf->tail];
    memcpy(slot->data, data, length);
    slot->length = length;

    /*
        Advance tail with wrap-around. The modulo operation is the heart of
        the ring: when tail reaches the end of the array, it wraps back to 0.
        
        Example with NETBUF_SLOT_COUNT = 4:
            tail=0 -> writes slot 0, advances to 1
            tail=1 -> writes slot 1, advances to 2
            tail=3 -> writes slot 3, advances to 0  (wraps!)
    */
    buf->tail = (buf->tail + 1) % NETBUF_SLOT_COUNT;
    buf->count++;

    return NET_OK;
}


/* -----------------------------------------------------------------------
   netbuf_dequeue
   ----------------------------------------------------------------------- */

net_status_t netbuf_dequeue(netbuf_t *buf, netbuf_slot_t **slot) {
    if (buf == NULL || slot == NULL) {
        return NET_ERR_INVALID;
    }

    /* Nothing to read — the buffer is empty. */
    if (buf->count == 0) {
        return NET_ERR_EMPTY;
    }

    /*
        Hand the caller a direct pointer to the head slot.
        
        We do NOT copy data out here. The caller gets a pointer into the ring
        itself. This is efficient — no extra copy — but it means the caller
        must process or copy the data before the ring cycles around and
        reuses this slot.

        In our single-threaded, non-interrupt-driven design, this is safe.
        In a real kernel you would protect this with a critical section.
    */
    *slot = &buf->slots[buf->head];

    /*
        Advance head with wrap-around, same logic as tail in enqueue.
        Decrement count to reflect one fewer occupied slot.
    */
    buf->head = (buf->head + 1) % NETBUF_SLOT_COUNT;
    buf->count--;

    return NET_OK;
}


/* -----------------------------------------------------------------------
   Utility queries
   ----------------------------------------------------------------------- */

int netbuf_is_empty(const netbuf_t *buf) {
    /*
        Guard against NULL so callers can safely use this in conditionals
        without checking first. An invalid buffer is treated as empty —
        it certainly has nothing useful to offer.
    */
    if (buf == NULL) return 1;
    return (buf->count == 0);
}

int netbuf_is_full(const netbuf_t *buf) {
    if (buf == NULL) return 0;
    return (buf->count == NETBUF_SLOT_COUNT);
}

uint8_t netbuf_count(const netbuf_t *buf) {
    if (buf == NULL) return 0;
    return buf->count;
}
