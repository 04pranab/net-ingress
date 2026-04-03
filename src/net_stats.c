/*
    net_stats.c — Network Ingress Statistics (Implementation)

    This file is intentionally simple. The value of net_stats is not in
    complex logic — it is in the discipline of recording every observable
    event consistently. Each function here does one thing: safely increment
    one counter.

    In a future multi-core or interrupt-driven kernel, these increment
    functions would be the place to add atomic operations (e.g., using
    __sync_fetch_and_add or C11 _Atomic). For now, single-threaded
    increments are correct and clear.
*/

#include "net_stats.h"
#include <string.h>

net_status_t net_stats_init(net_stats_t *stats) {
    if (stats == NULL) return NET_ERR_INVALID;
    memset(stats, 0, sizeof(net_stats_t));
    return NET_OK;
}

/*
    Each increment function follows the exact same pattern:
        1. Guard against NULL.
        2. Increment the counter.
        3. Return NET_OK.

    The repetition is deliberate. It makes each function independently
    readable and independently testable without shared logic that could
    obscure bugs.
*/

net_status_t net_stats_increment_rx_total(net_stats_t *stats) {
    if (stats == NULL) return NET_ERR_INVALID;
    stats->rx_total++;
    return NET_OK;
}

net_status_t net_stats_increment_rx_dropped(net_stats_t *stats) {
    if (stats == NULL) return NET_ERR_INVALID;
    stats->rx_dropped++;
    return NET_OK;
}

net_status_t net_stats_increment_parse_errors(net_stats_t *stats) {
    if (stats == NULL) return NET_ERR_INVALID;
    stats->parse_errors++;
    return NET_OK;
}

net_status_t net_stats_increment_checksum_errors(net_stats_t *stats) {
    if (stats == NULL) return NET_ERR_INVALID;
    stats->checksum_errors++;
    return NET_OK;
}

net_status_t net_stats_increment_proto_icmp(net_stats_t *stats) {
    if (stats == NULL) return NET_ERR_INVALID;
    stats->proto_icmp++;
    return NET_OK;
}

net_status_t net_stats_increment_proto_tcp(net_stats_t *stats) {
    if (stats == NULL) return NET_ERR_INVALID;
    stats->proto_tcp++;
    return NET_OK;
}

net_status_t net_stats_increment_proto_udp(net_stats_t *stats) {
    if (stats == NULL) return NET_ERR_INVALID;
    stats->proto_udp++;
    return NET_OK;
}

net_status_t net_stats_increment_proto_unknown(net_stats_t *stats) {
    if (stats == NULL) return NET_ERR_INVALID;
    stats->proto_unknown++;
    return NET_OK;
}
