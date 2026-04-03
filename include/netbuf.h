#ifndef NETBUF_H
#define NETBUF_H

/*
    netbuf.h — Network Ingress Buffer

    This is the first stage in the ingress pipeline.

    Before a packet can be parsed or dispatched, its raw bytes must be held
    somewhere. That "somewhere" is the ingress buffer, defined here.

    DESIGN QUESTION: why not just pass raw byte pointers around directly?

    Because in a real OS, the NIC (Network Interface Card) writes incoming
    data into memory faster than the CPU can process it. You need a place
    to accumulate that data safely — a buffer — so that the processing stages
    can work at their own pace without losing incoming bytes.

    This buffer is implemented as a RING BUFFER (also called a circular buffer).
    A ring buffer is a fixed-size array where write and read positions wrap
    around continuously. This gives us:

        - O(1) enqueue and dequeue
        - No dynamic memory allocation
        - No fragmentation
        - Predictable worst-case behavior (critical for kernel code)

    Think of it like a circular conveyor belt: the producer (NIC/hardware)
    places packets on one side, and the consumer (parser) picks them off
    the other. When the belt is full, new packets are rejected — not silently
    dropped, and not cause for a crash.
*/

#include <stdint.h>
#include <stddef.h>
#include "net_types.h"

/*
    NETBUF_SLOT_COUNT defines how many packets the ring can hold at once.
    NETBUF_SLOT_SIZE  defines the maximum byte size of a single packet slot.

    Both are compile-time constants — no runtime sizing, no malloc.

    Ethernet MTU (Maximum Transmission Unit) is 1500 bytes. We use 1536
    as the slot size because it is a clean, power-of-2-aligned value that
    comfortably holds a standard Ethernet frame plus any minor header overhead.

    You can tune these constants for your target system. A small embedded
    kernel might use 4 slots of 512 bytes. The interface remains the same.
*/
#define NETBUF_SLOT_COUNT  16
#define NETBUF_SLOT_SIZE   1536

/*
    netbuf_slot_t represents a single packet-sized slot in the ring.

    It holds:
        data[]  — the raw bytes of one incoming packet
        length  — how many of those bytes are actually valid/occupied

    Why store length separately? Because a slot is always NETBUF_SLOT_SIZE
    bytes wide, but actual packets are almost always smaller. The length
    field tells the next stage "only look at the first N bytes."
*/
typedef struct {
    uint8_t  data[NETBUF_SLOT_SIZE];
    uint16_t length;
} netbuf_slot_t;

/*
    netbuf_t is the ring buffer itself.

    It contains:
        slots[] — the fixed array of packet slots (the "belt")
        head    — index of the next slot to READ from (consumer side)
        tail    — index of the next slot to WRITE into (producer side)
        count   — how many slots are currently occupied

    When count == 0, the buffer is empty.
    When count == NETBUF_SLOT_COUNT, the buffer is full.

    head and tail always move forward, wrapping around with modulo arithmetic:
        next_index = (current_index + 1) % NETBUF_SLOT_COUNT

    This is what makes it a "ring" — the indices never stop, they just loop.
*/
typedef struct {
    netbuf_slot_t slots[NETBUF_SLOT_COUNT];
    uint8_t       head;
    uint8_t       tail;
    uint8_t       count;
} netbuf_t;


/* -----------------------------------------------------------------------
   Public API
   ----------------------------------------------------------------------- */

/*
    netbuf_init — Initialize a netbuf_t to a known empty state.

    Always call this before using a netbuf. Zeroing the struct manually is
    not sufficient because the semantics of head/tail/count must be explicit.

    Parameters:
        buf  — pointer to the netbuf_t to initialize (must not be NULL)

    Returns:
        NET_OK          on success
        NET_ERR_INVALID if buf is NULL
*/
net_status_t netbuf_init(netbuf_t *buf);

/*
    netbuf_enqueue — Copy raw bytes into the next available slot.

    This is the write side — called when new data arrives (e.g., from a NIC).
    It copies 'length' bytes from 'data' into the tail slot, then advances tail.

    We COPY the data rather than storing a pointer because the source buffer
    (e.g., a DMA region) may be reused by hardware immediately after this call.
    Owning a copy is safer and avoids use-after-free bugs.

    Parameters:
        buf     — the ring buffer to write into
        data    — pointer to the raw incoming bytes
        length  — number of bytes to copy (must be <= NETBUF_SLOT_SIZE)

    Returns:
        NET_OK           on success
        NET_ERR_INVALID  if buf or data is NULL, or length is 0 or too large
        NET_ERR_FULL     if the ring is already full
*/
net_status_t netbuf_enqueue(netbuf_t *buf, const uint8_t *data, uint16_t length);

/*
    netbuf_dequeue — Hand a pointer to the head slot to the caller.

    This is the read side — called by the packet stage to get the next
    pending packet. Instead of copying data out, we give the caller a
    direct pointer to the slot inside the ring. This avoids an extra copy.

    IMPORTANT: The caller must finish using the slot BEFORE the ring wraps
    around and overwrites it. In a single-threaded system this is safe as
    long as you process the slot before calling enqueue again. In a real
    kernel with interrupts, a lock or DMA fence would be needed — but that
    is out of scope here.

    Parameters:
        buf   — the ring buffer to read from
        slot  — output: set to point at the head slot on success

    Returns:
        NET_OK           on success
        NET_ERR_INVALID  if buf or slot is NULL
        NET_ERR_EMPTY    if there are no packets waiting
*/
net_status_t netbuf_dequeue(netbuf_t *buf, netbuf_slot_t **slot);

/*
    netbuf_is_empty — Returns 1 if the buffer has no pending packets, 0 otherwise.
    netbuf_is_full  — Returns 1 if the buffer has no free slots, 0 otherwise.
    netbuf_count    — Returns the number of packets currently in the buffer.

    These are utility queries, useful for polling loops, diagnostics, and tests.
    None of them modify the buffer state.
*/
int     netbuf_is_empty(const netbuf_t *buf);
int     netbuf_is_full (const netbuf_t *buf);
uint8_t netbuf_count   (const netbuf_t *buf);

#endif /* NETBUF_H */
