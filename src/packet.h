/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef NFQTTL_PACKET_H
#define NFQTTL_PACKET_H
#include <stddef.h>
#include <stdint.h>

/* Called only on IPv4 FORWARD packets. No transport or payload changes. */
static int set_ipv4_ttl(uint8_t *p, size_t n, uint8_t ttl)
{
    if (n < 20 || (p[0] >> 4) != 4) return 0;
    size_t ihl = (p[0] & 15u) * 4u;
    size_t total = ((size_t)p[2] << 8) | p[3];
    if (ihl < 20 || ihl > n || total < ihl || total > n || !ttl)
        return 0;
    if (p[8] == ttl) return 0;
    p[8] = ttl;
    p[10] = p[11] = 0;
    uint32_t sum = 0;
    for (size_t i = 0; i < ihl; i += 2)
        sum += ((uint32_t)p[i] << 8) | p[i + 1];
    while (sum >> 16) sum = (sum & 65535u) + (sum >> 16);
    sum = (~sum) & 65535u;
    p[10] = (uint8_t)(sum >> 8);
    p[11] = (uint8_t)sum;
    return 1;
}
#endif
