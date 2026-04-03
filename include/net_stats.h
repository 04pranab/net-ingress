#ifndef NET_STATS_H
#define NET_STATS_H

/*
    net_stats.h — Network Ingress Statistics

    This is the final piece of the ingress pipeline — the observability layer.

    Every well-designed OS subsystem needs a way to answer the question:
    "What is the system doing?" Without statistics, you are flying blind.
    You cannot tell if packets are being dropped, if parse errors are spiking,
    or if a particular protocol dominates traffic.

    This module provides a single struct, net_stats_t, that accumulates
    counters as the pipeline processes packets. Functions are provided to
    update and read these counters.

    DESIGN PHILOSOPHY:
    Statistics are not an afterthought bolted on after the system works.
    They are first-class citizens, designed alongside the pipeline stages.
    Each counter directly corresponds to an observable event in the system.
    If something important can happen, there should be a counter for it.
*/

#include <stdint.h>
#include "net_types.h"

/*
    net_stats_t — Counters for every observable event in the ingress pipeline.

    All counters are uint32_t. In a production system you might use uint64_t
    for long-running systems that process billions of packets. For a teaching
    OS, 32 bits (up to ~4 billion events) is more than sufficient.

    The counters are grouped by stage:

    BUFFER STAGE (netbuf):
        rx_total         — Every time a raw packet enters the ring buffer.
        rx_dropped       — Every time enqueue fails because the buffer is full.

    PARSING STAGE (ipv4 / icmp / tcp):
        parse_errors     — Every time any parsing stage returns NET_ERR_PARSE.
        checksum_errors  — A subset of parse_errors: specifically checksum failures.

    DISPATCH STAGE:
        proto_icmp       — Packets successfully identified and dispatched as ICMP.
        proto_tcp        — Packets successfully identified and dispatched as TCP.
        proto_udp        — Packets identified as UDP (parsed but no handler yet).
        proto_unknown    — Packets with an unrecognized or unsupported protocol.
*/
typedef struct {
    uint32_t rx_total;
    uint32_t rx_dropped;
    uint32_t parse_errors;
    uint32_t checksum_errors;
    uint32_t proto_icmp;
    uint32_t proto_tcp;
    uint32_t proto_udp;
    uint32_t proto_unknown;
} net_stats_t;


/* -----------------------------------------------------------------------
   Public API
   ----------------------------------------------------------------------- */

/*
    net_stats_init — Zero all counters to a known clean state.

    Always call this before the first use of a net_stats_t.

    Returns:
        NET_OK          on success
        NET_ERR_INVALID if stats is NULL
*/
net_status_t net_stats_init(net_stats_t *stats);

/*
    net_stats_increment_* — Increment individual counters by 1.

    Each function corresponds to one counter in net_stats_t.
    Providing explicit increment functions (rather than directly accessing
    the struct fields) gives us a single place to add overflow detection,
    logging, or atomic operations in the future.

    All functions return NET_ERR_INVALID if stats is NULL, NET_OK otherwise.
*/
net_status_t net_stats_increment_rx_total      (net_stats_t *stats);
net_status_t net_stats_increment_rx_dropped    (net_stats_t *stats);
net_status_t net_stats_increment_parse_errors  (net_stats_t *stats);
net_status_t net_stats_increment_checksum_errors(net_stats_t *stats);
net_status_t net_stats_increment_proto_icmp    (net_stats_t *stats);
net_status_t net_stats_increment_proto_tcp     (net_stats_t *stats);
net_status_t net_stats_increment_proto_udp     (net_stats_t *stats);
net_status_t net_stats_increment_proto_unknown (net_stats_t *stats);

#endif /* NET_STATS_H */
