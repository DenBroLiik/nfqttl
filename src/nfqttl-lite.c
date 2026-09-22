/* SPDX-License-Identifier: GPL-3.0-or-later
 * Standalone IPv4 TTL worker for Linux/Android. No libnetfilter dependency.
 * Netlink UAPI: Linux nfnetlink_queue.h. Rules and lifecycle belong to service.sh.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include "packet.h"

static volatile sig_atomic_t stopping;
static unsigned char rx[131072] __attribute__((aligned(8)));
static unsigned char tx[131072] __attribute__((aligned(8)));
static void stop(int sig) { (void)sig; stopping = 1; }

static struct nlmsghdr *begin(unsigned type, unsigned flags, unsigned seq,
                              unsigned queue)
{
    memset(tx, 0, NLMSG_SPACE(sizeof(struct nfgenmsg)));
    struct nlmsghdr *h = (void *)tx;
    h->nlmsg_len = NLMSG_LENGTH(sizeof(struct nfgenmsg));
    h->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | type;
    h->nlmsg_flags = NLM_F_REQUEST | flags;
    h->nlmsg_seq = seq;
    struct nfgenmsg *g = NLMSG_DATA(h);
    g->nfgen_family = AF_INET;
    g->version = NFNETLINK_V0;
    g->res_id = htons(queue);
    return h;
}

static int attr(struct nlmsghdr *h, unsigned type, const void *data, size_t len)
{
    size_t pos = NLMSG_ALIGN(h->nlmsg_len);
    size_t size = NLA_HDRLEN + len;
    if (size > UINT16_MAX || pos + NLA_ALIGN(size) > sizeof(tx)) return -1;
    struct nlattr *a = (void *)(tx + pos);
    a->nla_type = type;
    a->nla_len = size;
    memcpy((char *)a + NLA_HDRLEN, data, len);
    memset((char *)a + size, 0, NLA_ALIGN(size) - size);
    h->nlmsg_len = pos + NLA_ALIGN(size);
    return 0;
}

static int send_msg(int fd, struct nlmsghdr *h)
{
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    ssize_t n;
    do { n = sendto(fd, h, h->nlmsg_len, 0,
                   (void *)&kernel, sizeof(kernel)); }
    while (n < 0 && errno == EINTR && !stopping);
    return n == (ssize_t)h->nlmsg_len ? 0 : -1;
}

/* Configuration completes before service.sh attaches the forwarding rules. */
static int ack(int fd, struct nlmsghdr *out)
{
    unsigned seq = out->nlmsg_seq;
    if (send_msg(fd, out)) return -1;
    struct pollfd p = {.fd = fd, .events = POLLIN};
    if (poll(&p, 1, 2000) != 1) { errno = ETIMEDOUT; return -1; }
    ssize_t received = recv(fd, rx, sizeof(rx), 0);
    if (received < 0) return -1;
    int n = received;
    for (struct nlmsghdr *h = (void *)rx; n >= 0 && NLMSG_OK(h, (unsigned)n); h = NLMSG_NEXT(h, n)) {
        if (h->nlmsg_seq != seq || h->nlmsg_type != NLMSG_ERROR) continue;
        if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) break;
        struct nlmsgerr *e = NLMSG_DATA(h);
        if (!e->error) return 0;
        errno = -e->error;
        return -1;
    }
    errno = EPROTO;
    return -1;
}

static int configure(int fd, unsigned queue)
{
    struct nlmsghdr *h = begin(NFQNL_MSG_CONFIG, NLM_F_ACK, 1, queue);
    struct nfqnl_msg_config_cmd cmd = {.command = NFQNL_CFG_CMD_BIND,
                                      .pf = htons(AF_INET)};
    if (attr(h, NFQA_CFG_CMD, &cmd, sizeof(cmd)) || ack(fd, h)) return -1;
    h = begin(NFQNL_MSG_CONFIG, NLM_F_ACK, 2, queue);
    struct nfqnl_msg_config_params p = {.copy_range = htonl(65535),
                                      .copy_mode = NFQNL_COPY_PACKET};
    uint32_t maxlen = htonl(1024);
    /* Preserve GSO packets instead of forcing expensive kernel segmentation.
     * Netfilter recommends NFQA_CFG_F_GSO for queue performance. */
    uint32_t flags = htonl(NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_GSO);
    if (attr(h, NFQA_CFG_PARAMS, &p, sizeof(p)) ||
        attr(h, NFQA_CFG_QUEUE_MAXLEN, &maxlen, sizeof(maxlen)) ||
        attr(h, NFQA_CFG_FLAGS, &flags, sizeof(flags)) ||
        attr(h, NFQA_CFG_MASK, &flags, sizeof(flags))) return -1;
    return ack(fd, h);
}

static int packet(int fd, struct nlmsghdr *h, unsigned queue, unsigned ttl)
{
    if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nfgenmsg))) return -1;
    struct nfgenmsg *g = NLMSG_DATA(h);
    if (ntohs(g->res_id) != queue) return -1;
    size_t offset = NLMSG_LENGTH(sizeof(*g));
    uint32_t id = 0, caplen = 0;
    unsigned hook = 255, protocol = 0;
    int have_id = 0;
    unsigned char *payload = NULL;
    size_t size = 0;
    while (offset + NLA_HDRLEN <= h->nlmsg_len) {
        struct nlattr *a = (void *)((char *)h + offset);
        if (a->nla_len < NLA_HDRLEN || a->nla_len > h->nlmsg_len - offset)
            return -1;
        void *data = (char *)a + NLA_HDRLEN;
        size_t len = a->nla_len - NLA_HDRLEN;
        switch (a->nla_type & NLA_TYPE_MASK) {
        case NFQA_PACKET_HDR:
            if (len < sizeof(struct nfqnl_msg_packet_hdr)) return -1;
            {
                struct nfqnl_msg_packet_hdr ph;
                memcpy(&ph, data, sizeof(ph));
                id = ph.packet_id; hook = ph.hook; protocol = ntohs(ph.hw_protocol);
                have_id = 1;
            }
            break;
        case NFQA_PAYLOAD: payload = data; size = len; break;
        case NFQA_CAP_LEN:
            if (len != sizeof(caplen)) return -1;
            memcpy(&caplen, data, sizeof(caplen)); caplen = ntohl(caplen);
            break;
        }
        offset += NLA_ALIGN(a->nla_len);
    }
    if (!have_id) return -1;
    int changed = payload && protocol == 0x0800 && hook == NF_INET_FORWARD &&
        (!caplen || caplen == size) && size <= UINT16_MAX - NLA_HDRLEN &&
        set_ipv4_ttl(payload, size, ttl);
    struct nlmsghdr *v = begin(NFQNL_MSG_VERDICT, 0, 0, queue);
    struct nfqnl_msg_verdict_hdr vh = {.verdict = htonl(NF_ACCEPT), .id = id};
    if (attr(v, NFQA_VERDICT_HDR, &vh, sizeof(vh))) return -1;
    if (changed && attr(v, NFQA_PAYLOAD, payload, size)) return -1;
    return send_msg(fd, v);
}

static unsigned number(const char *s, unsigned max)
{
    char *end;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if (errno || !*s || *end || !v || v > max) {
        fprintf(stderr, "Invalid numeric argument: %s\n", s); exit(2);
    }
    return v;
}

int main(int argc, char **argv)
{
    unsigned queue = 6464, ttl = 64;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--help")) {
            puts("nfqttl-lite 3.0.0: -n QUEUE -t TTL (IPv4 FORWARD only)"); return 0;
        }
        if ((!strcmp(argv[i], "-n") || !strcmp(argv[i], "-t")) && i + 1 < argc) {
            int isqueue = argv[i][1] == 'n';
            unsigned v = number(argv[++i], isqueue ? 65535 : 255);
            if (isqueue) queue = v; else ttl = v;
        } else { fprintf(stderr, "Unknown/missing argument: %s\n", argv[i]); return 2; }
    }
    struct sigaction sa = {.sa_handler = stop};
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL); sigaction(SIGINT, &sa, NULL);
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (fd < 0) { perror("netlink socket"); return 1; }
    int size = 4 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)))
        perror("receive buffer");
    struct timeval timeout = {.tv_sec = 1};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_nl local = {.nl_family = AF_NETLINK, .nl_pid = getpid()};
    if (bind(fd, (void *)&local, sizeof(local)) || configure(fd, queue)) {
        perror("queue configuration (no rules should be attached)"); close(fd); return 1;
    }
    fprintf(stderr, "READY queue=%u ttl=%u maxlen=1024 gso=1 pid=%ld\n",
            queue, ttl, (long)getpid());
    int status = 0;
    while (!stopping) {
        struct pollfd p = {.fd = fd, .events = POLLIN};
        int ready = poll(&p, 1, 1000);
        if (ready < 0 && errno == EINTR) continue;
        if (!ready) continue;
        if (ready < 0 || !(p.revents & POLLIN)) { status = 1; break; }
        struct sockaddr_nl sender = {0};
        struct iovec iov = {.iov_base = rx, .iov_len = sizeof(rx)};
        struct msghdr msg = {.msg_name = &sender, .msg_namelen = sizeof(sender),
                             .msg_iov = &iov, .msg_iovlen = 1};
        ssize_t received = recvmsg(fd, &msg, 0);
        if (received < 0 && errno == EINTR) continue;
        if (received <= 0 || (msg.msg_flags & MSG_TRUNC)) { status = 1; break; }
        int n = received;
        if (sender.nl_pid != 0) continue;
        for (struct nlmsghdr *h = (void *)rx; n >= 0 && NLMSG_OK(h, (unsigned)n); h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_type == ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET)) {
                if (packet(fd, h, queue, ttl)) { status = 1; break; }
            } else if (h->nlmsg_type == NLMSG_ERROR) { status = 1; break; }
        }
        if (status) break;
    }
    if (status) fprintf(stderr, "Queue receive/verdict error; exiting for supervisor recovery\n");
    close(fd);
    return status;
}
