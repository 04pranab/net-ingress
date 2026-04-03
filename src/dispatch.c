/*
    dispatch.c — Internal Packet Dispatch (Implementation)

    Dispatch is the last active stage in the ingress pipeline. By the time
    a packet reaches here, it has been:

        1. Buffered in the ring (netbuf)
        2. Wrapped in a packet_t (packet)
        3. Had its IPv4 header parsed and validated (ipv4)
        4. Had its protocol identified (TCP, ICMP, etc.)

    Dispatch simply looks up the right handler in the table and calls it.
    If no handler exists, it records the event in stats and returns
    NET_ERR_UNSUPPORTED — never silently discards.

    The handler table is a flat array of function pointers. Indexing by
    the raw protocol number (1 for ICMP, 6 for TCP, etc.) works cleanly
    because DISPATCH_MAX_PROTO covers all the values we care about.
*/

#include "dispatch.h"
#include <string.h>

net_status_t dispatch_init(dispatch_table_t *table) {
    if (table == NULL) return NET_ERR_INVALID;
    /*
        Zero the table. A NULL function pointer means "no handler registered."
        dispatch_packet checks for NULL before calling, so this is safe.
    */
    memset(table, 0, sizeof(dispatch_table_t));
    return NET_OK;
}

net_status_t dispatch_register(dispatch_table_t *table,
                                net_protocol_t protocol,
                                dispatch_handler_fn handler) {
    if (table == NULL || handler == NULL) return NET_ERR_INVALID;
    if ((uint8_t)protocol >= DISPATCH_MAX_PROTO)  return NET_ERR_INVALID;

    table->handlers[protocol] = handler;
    return NET_OK;
}

net_status_t dispatch_packet(dispatch_table_t *table,
                              packet_t *pkt,
                              net_stats_t *stats) {
    if (table == NULL || pkt == NULL || stats == NULL) return NET_ERR_INVALID;

    uint8_t proto = (uint8_t)pkt->protocol;

    /*
        Bounds check: make sure the protocol value fits in our table.
        NET_PROTO_UNKNOWN is 0, ICMP is 1, TCP is 6, UDP is 17 — all < 18.
    */
    if (proto >= DISPATCH_MAX_PROTO || table->handlers[proto] == NULL) {
        /*
            No handler registered for this protocol. Record it and report
            as unsupported. The packet is not malformed — we just don't
            handle it yet.
        */
        net_stats_increment_proto_unknown(stats);
        return NET_ERR_UNSUPPORTED;
    }

    /* Call the registered handler. Its return value propagates to the caller. */
    return table->handlers[proto](pkt, stats);
}
