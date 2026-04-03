#ifndef DISPATCH_H
#define DISPATCH_H

/*
    dispatch.h — Internal Packet Dispatch

    This is the fifth stage in the ingress pipeline, and the final one
    before statistics collection.

    After parsing, we know what protocol a packet carries. The dispatch
    stage's job is to route the packet to the correct handler based on
    that protocol. Think of it as a post office sorting room: packets
    arrive parsed and labelled, and dispatch sends each one to its
    appropriate "counter."

    DESIGN NOTE ON FUNCTION POINTERS:

    We implement dispatch using a handler table — an array of function
    pointers indexed by protocol. This is a classic systems programming
    pattern. The alternative would be a switch statement, but a table:

        - Can be extended at runtime (register/deregister handlers)
        - Does not require touching the dispatch logic to add a new protocol
        - Mirrors how real kernel dispatch tables work (e.g., Linux's
          inet_protos[] or file_operations structs)

    A handler is simply a function that accepts a packet_t and does
    something with it (log it, pass it to a socket queue, etc.). In this
    subsystem, our handlers are stubs that update the statistics counters
    and demonstrate the routing logic.
*/

#include "net_types.h"
#include "packet.h"
#include "net_stats.h"

/*
    dispatch_handler_fn — the type signature of a protocol handler function.

    Every handler receives:
        pkt   — the packet, with offset pointing just past the protocol header
        stats — the global stats struct, so the handler can record counts

    It returns a net_status_t to indicate success or failure.
*/
typedef net_status_t (*dispatch_handler_fn)(packet_t *pkt, net_stats_t *stats);

/*
    dispatch_table_t — the routing table.

    We store one handler per protocol. The table is indexed by the
    net_protocol_t enum values. A NULL entry means "no handler registered"
    — the dispatch logic will count it as unsupported.

    Why +1? Because NET_PROTO_UDP is 17, and array indexing requires a
    size at least as large as the maximum index. Alternatively, one could
    use a flat lookup array of size 256 (one per possible protocol byte),
    which is more realistic for a kernel. We keep it small for clarity.
*/
#define DISPATCH_MAX_PROTO 18   /* covers 0..17, all our net_protocol_t values */

typedef struct {
    dispatch_handler_fn handlers[DISPATCH_MAX_PROTO];
} dispatch_table_t;


/* -----------------------------------------------------------------------
   Public API
   ----------------------------------------------------------------------- */

/*
    dispatch_init — Zero the table (all handlers start as NULL / unregistered).

    Parameters:
        table — the dispatch_table_t to initialize

    Returns:
        NET_OK          on success
        NET_ERR_INVALID if table is NULL
*/
net_status_t dispatch_init(dispatch_table_t *table);

/*
    dispatch_register — Associate a handler function with a protocol number.

    Parameters:
        table    — the dispatch table to register into
        protocol — the net_protocol_t value to handle
        handler  — the function to call when a packet of this protocol arrives

    Returns:
        NET_OK              on success
        NET_ERR_INVALID     if table or handler is NULL, or protocol is out of range
*/
net_status_t dispatch_register(dispatch_table_t *table,
                                net_protocol_t protocol,
                                dispatch_handler_fn handler);

/*
    dispatch_packet — Look up and invoke the handler for a parsed packet.

    Uses pkt->protocol to index into the table. If a handler is registered,
    calls it. If not, records an unsupported-protocol event in stats.

    Parameters:
        table — the dispatch table to look up in
        pkt   — the parsed packet to dispatch
        stats — the statistics struct to update

    Returns:
        NET_OK              if a handler was found and returned NET_OK
        NET_ERR_UNSUPPORTED if no handler is registered for this protocol
        NET_ERR_INVALID     if any argument is NULL
        (or whatever the handler itself returns)
*/
net_status_t dispatch_packet(dispatch_table_t *table,
                              packet_t *pkt,
                              net_stats_t *stats);

#endif /* DISPATCH_H */
