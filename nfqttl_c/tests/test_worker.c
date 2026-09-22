#define main worker_main
#define sendto capture_sendto
#define recv capture_recv
#define poll capture_poll
#include "../src/nfqttl-lite.c"
#undef main
#undef sendto
#undef recv
#undef poll
#include <assert.h>

static unsigned char sent[131072];
static size_t sent_len;
static int ack_error;
int capture_poll(struct pollfd *fds, nfds_t n, int timeout)
{
    (void)fds; (void)n; (void)timeout; return 1;
}
ssize_t capture_recv(int fd, void *buf, size_t n, int flags)
{
    (void)fd; (void)flags;
    assert(n>=NLMSG_LENGTH(sizeof(struct nlmsgerr)));
    struct nlmsghdr *h=buf;
    memset(buf,0,NLMSG_LENGTH(sizeof(struct nlmsgerr)));
    h->nlmsg_type=NLMSG_ERROR;
    h->nlmsg_seq=((struct nlmsghdr *)(void *)sent)->nlmsg_seq;
    h->nlmsg_len=NLMSG_LENGTH(sizeof(struct nlmsgerr));
    ((struct nlmsgerr *)NLMSG_DATA(h))->error=ack_error;
    return h->nlmsg_len;
}
ssize_t capture_sendto(int fd, const void *buf, size_t n, int flags,
                      const struct sockaddr *addr, socklen_t alen)
{
    (void)fd; (void)flags; (void)addr; (void)alen;
    assert(n <= sizeof(sent)); memcpy(sent, buf, n); sent_len = n; return n;
}
static uint16_t checksum(const unsigned char *p, size_t n)
{
    unsigned sum = 0;
    for (size_t i=0; i<n; i+=2) sum += p[i]*256u+p[i+1];
    while (sum > 65535) sum = (sum & 65535) + (sum >> 16);
    return (uint16_t)~sum;
}
static void make_ip(unsigned char *p, size_t n, unsigned ihl, unsigned ttl)
{
    for (size_t i=0; i<n; ++i) p[i]=(i*13u)&255;
    p[0]=0x40|ihl; p[2]=n>>8; p[3]=n; p[8]=ttl;
    p[10]=p[11]=0;
    unsigned c=checksum(p,ihl*4); p[10]=c>>8; p[11]=c;
}
static void *get_attr(unsigned type, size_t *len)
{
    struct nlmsghdr *h=(void *)sent;
    size_t pos=NLMSG_LENGTH(sizeof(struct nfgenmsg));
    while(pos+NLA_HDRLEN<=h->nlmsg_len){
        struct nlattr *a=(void *)(sent+pos);
        if(a->nla_type==type){*len=a->nla_len-NLA_HDRLEN;return (char *)a+NLA_HDRLEN;}
        pos+=NLA_ALIGN(a->nla_len);
    }
    return NULL;
}
static unsigned char incoming[131072] __attribute__((aligned(8)));
static struct nlmsghdr *message(unsigned hook, unsigned proto, unsigned caplen)
{
    unsigned char ip[64]; make_ip(ip,sizeof(ip),5,63);
    struct nlmsghdr *h=begin(NFQNL_MSG_PACKET,0,0,6464);
    struct nfqnl_msg_packet_hdr ph={.packet_id=htonl(123),.hw_protocol=htons(proto),.hook=hook};
    assert(!attr(h,NFQA_PACKET_HDR,&ph,sizeof(ph)));
    assert(!attr(h,NFQA_PAYLOAD,ip,sizeof(ip)));
    if(caplen){uint32_t c=htonl(caplen);assert(!attr(h,NFQA_CAP_LEN,&c,sizeof(c)));}
    memcpy(incoming,tx,h->nlmsg_len);
    return (void *)incoming;
}
int main(void)
{
    assert(!configure(1,6464));
    size_t config_len;
    uint32_t config_value;
    void *config_attr=get_attr(NFQA_CFG_QUEUE_MAXLEN,&config_len);
    assert(config_attr && config_len==4); memcpy(&config_value,config_attr,4);
    assert(ntohl(config_value)==1024);
    config_attr=get_attr(NFQA_CFG_FLAGS,&config_len);
    assert(config_attr); memcpy(&config_value,config_attr,4);
    assert(ntohl(config_value)==(NFQA_CFG_F_FAIL_OPEN|NFQA_CFG_F_GSO));
    assert(get_attr(NFQA_CFG_MASK,&config_len));
    ack_error=-EPERM; assert(configure(1,6464)==-1 && errno==EPERM); ack_error=0;
    unsigned count=0;
    unsigned char p[1500], before[1500];
    for(unsigned ihl=5;ihl<=15;++ihl) for(unsigned ttl=1;ttl<=255;++ttl){
        make_ip(p,sizeof(p),ihl,ttl); memcpy(before,p,sizeof(p));
        assert(set_ipv4_ttl(p,sizeof(p),64)==(ttl!=64));
        assert(p[8]==64 && checksum(p,ihl*4)==0);
        before[8]=p[8];before[10]=p[10];before[11]=p[11];
        assert(!memcmp(p,before,sizeof(p))); ++count;
    }
    for(unsigned n=0;n<20;++n) assert(!set_ipv4_ttl(p,n,64));
    make_ip(p,100,5,63); p[0]=0x65; assert(!set_ipv4_ttl(p,100,64));
    make_ip(p,100,5,63); p[0]=0x44; assert(!set_ipv4_ttl(p,100,64));
    make_ip(p,100,5,63); p[2]=1; assert(!set_ipv4_ttl(p,100,64));
    make_ip(p,100,5,63); p[3]=10; assert(!set_ipv4_ttl(p,100,64));
    make_ip(p,100,15,63); assert(!set_ipv4_ttl(p,40,64));
    make_ip(p,100,5,63); assert(!set_ipv4_ttl(p,100,0));
    /* Fragment flags/offset and transport bytes remain byte-identical above. */
    for(unsigned hook=0;hook<=4;++hook){
        assert(!packet(1,message(hook,0x0800,0),6464,64));
        size_t len=0; unsigned char *v=get_attr(NFQA_PAYLOAD,&len);
        assert((v!=NULL)==(hook==NF_INET_FORWARD));
        if(v) assert(len==64 && v[8]==64 && checksum(v,20)==0);
        struct nfqnl_msg_verdict_hdr *vh=get_attr(NFQA_VERDICT_HDR,&len);
        assert(vh && ntohl(vh->verdict)==NF_ACCEPT && ntohl(vh->id)==123);
        assert(!get_attr(NFQA_MARK,&len));
    }
    size_t len;
    assert(!packet(1,message(NF_INET_FORWARD,0x86dd,0),6464,64));
    assert(!get_attr(NFQA_PAYLOAD,&len));
    assert(!packet(1,message(NF_INET_FORWARD,0x0800,999),6464,64));
    assert(!get_attr(NFQA_PAYLOAD,&len));
    assert(packet(1,message(NF_INET_FORWARD,0x0800,0),999,64)==-1);
    struct nlmsghdr *h=message(NF_INET_FORWARD,0x0800,0);
    struct nlattr *a=(void *)(incoming+NLMSG_LENGTH(sizeof(struct nfgenmsg)));
    a->nla_len=1; assert(packet(1,h,6464,64)==-1);
    /* Fuzz bounded malformed netlink attributes / IPv4 headers under ASan. */
    srand(42);
    for(unsigned i=0;i<20000;++i){
        h=message(NF_INET_FORWARD,0x0800,0);
        unsigned pos=NLMSG_LENGTH(sizeof(struct nfgenmsg))+(rand()%(h->nlmsg_len-NLMSG_LENGTH(sizeof(struct nfgenmsg))));
        incoming[pos]=(unsigned char)rand();
        (void)packet(1,h,6464,64);
        make_ip(p,100,5,63);p[rand()%100]=(unsigned char)rand();
        (void)set_ipv4_ttl(p,rand()%101,64);
    }
    printf("PASS: %u TTL/checksum/payload cases, validation, verdict scope, 20000 malformed-input cases\n",count);
    return 0;
}
