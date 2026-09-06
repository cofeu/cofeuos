#include "kernel.h"
#include "x86.h"
#include "rtl8139.h"
#include "net.h"

namespace {

/* ---- cekirdek ayarlari ---- */
uint8_t  our_mac[6];
uint32_t our_ip = 0;
uint32_t our_mask = 0;
uint32_t gateway = 0;

uint64_t stat_rx = 0;
uint64_t stat_tx = 0;
uint64_t stat_rx_bytes = 0;

const uint8_t bcast_mac[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/* ---- ARP onbellegi + bekleyicisi ---- */
struct ArpEntry {
    uint32_t ip;
    uint8_t  mac[6];
    bool     valid;
};
ArpEntry arp_cache[8];

volatile bool    arp_waiting = false;
volatile bool    arp_done    = false;
volatile uint32_t arp_want_ip = 0;
uint8_t arp_reply_mac[6];

/* ---- ping bekleyicisi ---- */
volatile bool     ping_active = false;
volatile bool     ping_done   = false;
volatile uint16_t ping_ident  = 0;
volatile uint32_t ping_reply_src = 0;

/* ---- big-endian yardimci ------ */
uint16_t rd16(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }
uint32_t rd32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
void wr16(uint8_t* p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)(v & 0xFF); }
void wr32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)(v & 0xFF);
}

uint16_t ip_checksum(const uint8_t* d, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += ((uint32_t)d[0] << 8) | d[1];
        d += 2; len -= 2;
    }
    if (len) sum += (uint32_t)d[0] << 8;
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)~sum;
}

/* ---- Ethernet gonderimi ---- */
void eth_send(const uint8_t* dmac, uint16_t type, const uint8_t* payload, uint16_t len) {
    uint8_t frame[1514];
    memcpy(frame, dmac, 6);
    memcpy(frame + 6, our_mac, 6);
    frame[12] = (uint8_t)(type >> 8);
    frame[13] = (uint8_t)(type & 0xFF);
    memcpy(frame + 14, payload, len);
    rtl8139_send(frame, (uint16_t)(len + 14));
    stat_tx++;
}

/* ---- ARP ---- */
void arp_send(uint16_t oper, uint32_t tip, const uint8_t* dmac) {
    uint8_t p[28];
    wr16(p, 1);                /* ethernet */
    wr16(p + 2, 0x0800);       /* IPv4    */
    p[4] = 6; p[5] = 4;
    wr16(p + 6, oper);
    memcpy(p + 8, our_mac, 6);
    wr32(p + 14, our_ip);
    memcpy(p + 18, dmac, 6);
    wr32(p + 24, tip);
    eth_send(dmac, 0x0806, p, 28);
}

bool arp_resolve(uint32_t ip, uint8_t* mac) {
    if (ip == 0xFFFFFFFFu) { memset(mac, 0xFF, 6); return true; }
    for (int i = 0; i < 8; i++)
        if (arp_cache[i].valid && arp_cache[i].ip == ip) {
            memcpy(mac, arp_cache[i].mac, 6);
            return true;
        }

    arp_send(1, ip, bcast_mac);                       /* istek */
    arp_want_ip = ip; arp_waiting = true; arp_done = false;
    uint64_t deadline = timer_get_ticks() + 30;       /* 300ms */
    while (!arp_done && timer_get_ticks() < deadline) cpu_hlt();
    arp_waiting = false;
    if (!arp_done) return false;

    memcpy(mac, arp_reply_mac, 6);
    for (int i = 0; i < 8; i++)
        if (!arp_cache[i].valid) {
            arp_cache[i].valid = true;
            arp_cache[i].ip = ip;
            memcpy(arp_cache[i].mac, arp_reply_mac, 6);
            break;
        }
    return true;
}

void handle_arp(const uint8_t* f, uint16_t len) {
    if (len < 42) return;
    const uint8_t* p = f + 14;
    if (rd16(p) != 1 || rd16(p + 2) != 0x0800 || p[4] != 6 || p[5] != 4) return;

    uint16_t oper = rd16(p + 6);
    const uint8_t* sha = p + 8;
    uint32_t spa = rd32(p + 14);
    uint32_t tpa = rd32(p + 24);

    for (int i = 0; i < 8; i++)
        if (arp_cache[i].valid && arp_cache[i].ip == spa) {
            memcpy(arp_cache[i].mac, sha, 6);
            break;
        }

    if (oper == 1 && tpa == our_ip) {
        arp_send(2, spa, sha);                        /* yanit */
    } else if (oper == 2 && arp_waiting && spa == arp_want_ip) {
        memcpy(arp_reply_mac, sha, 6);
        arp_done = true;
    }
}

/* ---- IPv4 ---- */
void ip_send(uint32_t dst, const uint8_t* dmac, uint8_t proto,
             const uint8_t* payload, uint16_t len) {
    uint8_t buf[20 + 1500];
    buf[0] = 0x45; buf[1] = 0;
    uint16_t tot = (uint16_t)(20 + len);
    wr16(buf + 2, tot);
    static uint16_t ip_id = 0x1000;
    wr16(buf + 4, ++ip_id);
    wr16(buf + 6, 0);
    buf[8] = 64; buf[9] = proto;
    wr16(buf + 10, 0);                    /* checksum sonra */
    wr32(buf + 12, our_ip);
    wr32(buf + 16, dst);
    wr16(buf + 10, ip_checksum(buf, 20));
    memcpy(buf + 20, payload, len);

    uint8_t tmpmac[6];
    if (!dmac) {
        if (!arp_resolve(dst, tmpmac)) return;
        dmac = tmpmac;
    }
    eth_send(dmac, 0x0800, buf, tot);
}

void handle_icmp(const uint8_t* ip, uint16_t len, const uint8_t* eth_src) {
    uint32_t ihl = (uint32_t)(ip[0] & 0x0F) * 4u;
    if (ihl < 20 || len < ihl + 8) return;
    const uint8_t* icmp = ip + ihl;
    uint16_t iclen = (uint16_t)(len - ihl);

    if (icmp[0] == 8 && icmp[1] == 0) {               /* echo istek -> yanit */
        uint8_t resp[512];
        if (iclen > sizeof(resp)) iclen = sizeof(resp);
        memset(resp, 0, sizeof(resp));
        memcpy(resp, icmp, iclen);
        resp[0] = 0;                                   /* echo reply */
        resp[1] = 0;
        resp[2] = resp[3] = 0;
        wr16(resp + 2, ip_checksum(resp, iclen));
        ip_send(rd32(ip + 12), eth_src, 1, resp, iclen);
    } else if (icmp[0] == 0 && ping_active) {
        if (rd16(icmp + 4) == ping_ident) {
            ping_reply_src = rd32(ip + 12);
            ping_done = true;
        }
    }
}

/* ---- UDP ---- */
uint16_t udp_checksum(uint32_t saddr, uint32_t daddr, const uint8_t* u, uint16_t ulen) {
    uint32_t sum = 0;
    sum += (saddr >> 16) + (saddr & 0xFFFF);
    sum += (daddr >> 16) + (daddr & 0xFFFF);
    sum += 17;                              /* protokol */
    sum += ulen;
    int n = ulen;
    while (n > 1) { sum += ((uint32_t)u[0] << 8) | u[1]; u += 2; n -= 2; }
    if (n) sum += (uint32_t)u[0] << 8;
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)~sum;
}

void udp_send(uint32_t dst, uint16_t dport, uint16_t sport, const uint8_t* data, uint16_t len) {
    uint8_t u[8 + 1500];
    wr16(u, sport);
    wr16(u + 2, dport);
    wr16(u + 4, (uint16_t)(len + 8));
    wr16(u + 6, 0);
    if (len) memcpy(u + 8, data, len);
    wr16(u + 6, udp_checksum(our_ip, dst, u, (uint16_t)(len + 8)));
    ip_send(dst, NULL, 17, u, (uint16_t)(len + 8));
}

/* ---- DHCP ---- */
volatile bool     dhcp_waiting = false;
volatile bool     dhcp_done = false;
volatile uint32_t dhcp_txid = 0;
volatile int      dhcp_phase = 0;      /* 1=OFFER bekle, 3=ACK bekle */
uint32_t dhcp_offer_ip = 0;
uint32_t dhcp_offer_mask = 0;
uint32_t dhcp_offer_router = 0;
uint32_t dhcp_offer_dns = 0;
uint32_t dhcp_offer_sid = 0;
uint32_t dns_server = 0;

uint8_t* dhcp_build(uint8_t* b, uint8_t mtype) {
    memset(b, 0, 240);
    b[0] = 1; b[1] = 1; b[2] = 6;       /* request, ethernet, mac 6 */
    wr32(b + 4, dhcp_txid);
    wr16(b + 10, 0x8000);               /* yaniti broadcast iste */
    memcpy(b + 28, our_mac, 6);
    b[236] = 0x63; b[237] = 0x82; b[238] = 0x53; b[239] = 0x63;  /* sihirli cookie */
    uint8_t* o = b + 240;
    *o++ = 53; *o++ = 1; *o++ = mtype;
    if (mtype == 3) {                   /* REQUEST: istenen IP + sunucu */
        *o++ = 50; *o++ = 4; wr32(o, dhcp_offer_ip); o += 4;
        *o++ = 54; *o++ = 4; wr32(o, dhcp_offer_sid); o += 4;
    }
    *o++ = 255;
    return o;
}

void handle_dhcp(const uint8_t* b, uint16_t avail) {
    if (b[0] != 2 || b[1] != 1 || b[2] != 6) return;
    if (rd32(b + 4) != dhcp_txid) return;
    if (rd32(b + 236) != 0x63825363u) return;

    uint8_t mtype = 0;
    uint32_t mask = 0, router = 0, dns = 0, sid = 0;
    if (avail > 300) avail = 300;
    const uint8_t* o = b + 240;
    const uint8_t* end = b + 240 + avail;
    while (o + 2 <= end) {
        if (*o == 255) break;
        if (*o == 0) { o++; continue; }
        uint8_t c = *o++;
        uint8_t ln = *o++;
        if (o + ln > end) break;
        if (c == 53 && ln == 1)       { mtype  = o[0]; }
        else if (c == 1 && ln == 4)   { mask   = rd32(o); }
        else if (c == 3 && ln >= 4)   { router = rd32(o); }
        else if (c == 6 && ln >= 4)   { dns    = rd32(o); }
        else if (c == 54 && ln == 4)  { sid    = rd32(o); }
        o += ln;
    }

    if (dhcp_phase == 1 && mtype == 2) {              /* OFFER */
        dhcp_offer_ip = rd32(b + 16);
        dhcp_offer_mask = mask; dhcp_offer_router = router;
        dhcp_offer_dns = dns; dhcp_offer_sid = sid;
        dhcp_done = true;
    } else if (dhcp_phase == 3 && mtype == 5) {       /* ACK */
        dhcp_offer_ip = rd32(b + 16);
        if (mask)   dhcp_offer_mask   = mask;
        if (router) dhcp_offer_router = router;
        if (dns)    dhcp_offer_dns    = dns;
        dhcp_done = true;
    }
}

/* ---- UDP soket kayitlari (kucuk dagitici) ---- */
typedef void (*udp_cb_t)(uint32_t src_ip, uint16_t src_port, const uint8_t* data, uint16_t len);
struct UdpSock { bool used; uint16_t dport; udp_cb_t cb; };
UdpSock udp_socks[8];

int udp_sock_add(uint16_t dport, udp_cb_t cb) {
    for (int i = 0; i < 8; i++)
        if (!udp_socks[i].used) {
            udp_socks[i].used = true;
            udp_socks[i].dport = dport;
            udp_socks[i].cb = cb;
            return i;
        }
    return -1;
}

void udp_sock_remove(int idx) {
    if (idx >= 0 && idx < 8) udp_socks[idx].used = false;
}

void handle_udp(const uint8_t* ip, uint16_t len) {
    uint32_t ihl = (uint32_t)(ip[0] & 0x0F) * 4u;
    if (len < ihl + 8) return;
    const uint8_t* u = ip + ihl;
    uint16_t sport = rd16(u);
    uint16_t dport = rd16(u + 2);
    uint16_t ulen = rd16(u + 4);
    if (ulen < 8 || ulen > len - ihl) ulen = (uint16_t)(len - ihl);

    if (dport == 68 && dhcp_waiting && ulen >= 244) {      /* bootpc: DHCP */
        handle_dhcp(u + 8, (uint16_t)(ulen - 8));
        return;
    }
    for (int i = 0; i < 8; i++)
        if (udp_socks[i].used && udp_socks[i].dport == dport) {
            udp_socks[i].cb(rd32(ip + 12), sport, u + 8, (uint16_t)(ulen - 8));
            return;
        }
}

/* ---- DNS (RFC 1035) ---- */
constexpr uint16_t DNS_SPORT = 5300;    /* gecici kaynak portu */
volatile bool     dns_waiting = false;
volatile bool     dns_done = false;
volatile uint16_t dns_id = 0;
bool     dns_ok = false;
uint32_t dns_result = 0;

int dns_qname(uint8_t* out, const char* name) {
    int n = 0;
    while (*name && n < 250) {
        const char* p = name;
        while (*p && *p != '.') p++;
        int l = (int)(p - name);
        if (l > 0 && l <= 63) {
            out[n++] = (uint8_t)l;
            memcpy(out + n, name, (size_t)l);
            n += l;
        }
        name = (*p == '.') ? p + 1 : p;
    }
    out[n++] = 0;
    return n;
}

void dns_skip_name(const uint8_t* d, int& pos, int limit) {
    for (;;) {
        if (pos < 0 || pos >= limit) { pos = -1; return; }
        uint8_t b = d[pos];
        if (b & 0xC0) { pos += 2; return; }        /* sikistirma isaretcisi */
        if (b == 0)   { pos += 1; return; }
        pos += 1 + b;
    }
}

int dns_query(uint8_t* b, uint16_t qid, const char* name) {
    wr16(b, qid);
    wr16(b + 2, 0x0100);                            /* RD istendi */
    wr16(b + 4, 1);                                 /* 1 soru */
    wr16(b + 6, 0); wr16(b + 8, 0); wr16(b + 10, 0);
    int n = dns_qname(b + 12, name);
    wr16(b + 12 + n, 1);                            /* A */
    wr16(b + 14 + n, 1);                            /* IN */
    return 12 + n + 4;
}

void dns_cb(uint32_t src_ip, uint16_t src_port, const uint8_t* data, uint16_t len) {
    (void)src_ip; (void)src_port;
    if (!dns_waiting || len < 12) return;
    if (rd16(data) != dns_id) return;               /* eslesen sorgu id */
    uint16_t flags = rd16(data + 2);
    if (!(flags & 0x8000)) return;                  /* yanit degil */
    uint16_t qd = rd16(data + 4);
    uint16_t an = rd16(data + 6);
    int pos = 12;
    int limit = (int)len;
    for (int i = 0; i < qd; i++) {
        dns_skip_name(data, pos, limit);
        if (pos < 0) return;
        pos += 4;
    }
    for (int i = 0; i < an; i++) {
        dns_skip_name(data, pos, limit);
        if (pos < 0) return;
        if (pos + 10 > limit) return;
        uint16_t type   = rd16(data + pos);
        uint16_t rdlen  = rd16(data + pos + 8);
        pos += 10;
        if (type == 1 && rdlen == 4 && pos + 4 <= limit) {  /* A kaydi */
            dns_result = rd32(data + pos);
            dns_ok = true;
            dns_done = true;
            return;
        }
        pos += rdlen;
    }
    dns_done = true;                                /* yanit geldi, A kaydi yok */
}

} /* namespace */

extern "C" void net_init(const uint8_t mac[6], uint32_t ip, uint32_t mask, uint32_t gw) {
    for (int i = 0; i < 6; i++) our_mac[i] = mac[i];
    our_ip = ip;
    our_mask = mask;
    gateway = gw;
    for (int i = 0; i < 8; i++) arp_cache[i].valid = false;
    stat_rx = stat_tx = stat_rx_bytes = 0;
    kslog("net: init ip=%u.%u.%u.%u mask=%u.%u.%u.%u gw=%u.%u.%u.%u\n",
          (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF,
          (mask >> 24) & 0xFF, (mask >> 16) & 0xFF, (mask >> 8) & 0xFF, mask & 0xFF,
          (gw >> 24) & 0xFF, (gw >> 16) & 0xFF, (gw >> 8) & 0xFF, gw & 0xFF);
}

extern "C" void net_handle_eth(const uint8_t* frame, uint16_t len) {
    stat_rx++;
    stat_rx_bytes += len;
    if (len < 14) return;

    uint16_t type = rd16(frame + 12);
    if (type == 0x0806) {
        handle_arp(frame, len);
    } else if (type == 0x0800) {
        if (len < 34) return;
        const uint8_t* ip = frame + 14;
        uint32_t dst = rd32(ip + 16);
        uint32_t bc = our_ip | (~our_mask);
        if (!dhcp_waiting && dst != our_ip && dst != bc && dst != 0xFFFFFFFFu) return;
        if (ip[9] == 1) {
            handle_icmp(ip, (uint16_t)(len - 14), frame);
        } else if (ip[9] == 17) {
            handle_udp(ip, (uint16_t)(len - 14));
        }
    }
}

extern "C" bool net_ping(uint32_t ip) {
    uint8_t dmac[6];
    if (!arp_resolve(ip, dmac)) return false;

    uint8_t pkt[16];
    pkt[0] = 8; pkt[1] = 0;
    pkt[2] = pkt[3] = 0;
    wr16(pkt + 4, ++ping_ident);
    wr16(pkt + 6, 1);
    memcpy(pkt + 8, "COFEUOS", 8);
    wr16(pkt + 2, ip_checksum(pkt, 16));

    ping_active = true; ping_done = false;
    ip_send(ip, dmac, 1, pkt, 16);

    uint64_t deadline = timer_get_ticks() + 100;      /* 1 sn */
    while (!ping_done && timer_get_ticks() < deadline) cpu_hlt();
    ping_active = false;

    if (!ping_done) return false;
    if (ping_reply_src != ip) return (ping_reply_src != 0);
    return true;
}

extern "C" bool net_dhcp(void) {
    dhcp_txid = (uint32_t)(timer_get_ticks() * 2654435761u) ^ 0xE17A11;
    uint64_t wall = timer_get_ticks() + 300;         /* ~3 sn toplam sure */
    bool got_offer = false;

    while (timer_get_ticks() < wall && !got_offer) {
        dhcp_waiting = true;
        dhcp_phase = 1;
        dhcp_done = false;
        uint8_t b[272];
        uint8_t* e = dhcp_build(b, 1);               /* DISCOVER */
        udp_send(0xFFFFFFFFu, 67, 68, b, (uint16_t)(e - b));
        uint64_t t = timer_get_ticks() + 30;         /* 300ms OFFER bekle */
        while (!dhcp_done && timer_get_ticks() < t) cpu_hlt();
        got_offer = dhcp_done;
    }
    if (!got_offer) { dhcp_waiting = false; return false; }

    wall = timer_get_ticks() + 100;                  /* ~1 sn ACK bekle */
    while (timer_get_ticks() < wall && !dhcp_done) {
        dhcp_phase = 3;
        dhcp_done = false;
        uint8_t b[272];
        uint8_t* e = dhcp_build(b, 3);               /* REQUEST */
        udp_send(0xFFFFFFFFu, 67, 68, b, (uint16_t)(e - b));
        uint64_t t = timer_get_ticks() + 30;
        while (!dhcp_done && timer_get_ticks() < t) cpu_hlt();
    }
    dhcp_waiting = false;
    if (!dhcp_done) return false;

    our_ip    = dhcp_offer_ip;
    our_mask  = dhcp_offer_mask ? dhcp_offer_mask : 0xFFFFFF00u;
    gateway   = dhcp_offer_router;
    dns_server = dhcp_offer_dns;
    for (int i = 0; i < 8; i++) arp_cache[i].valid = false;
    return true;
}

extern "C" bool net_dns_resolve(const char* name, uint32_t* out_ip) {
    if (!rtl8139_active()) return false;
    if (!name || !*name) return false;
    uint32_t server = dns_server ? dns_server : 0x0A000203u;

    for (int attempt = 0; attempt < 3; attempt++) {
        dns_id = (uint16_t)((timer_get_ticks() + (uint64_t)attempt) * 0x9E37u) | 0x8000u;
        uint8_t q[280];
        int qlen = dns_query(q, dns_id, name);
        if (qlen < 32) { memset(q + qlen, 0, 32 - qlen); qlen = 32; }

        int sock = udp_sock_add(DNS_SPORT, dns_cb);
        if (sock < 0) return false;
        dns_waiting = true; dns_done = false; dns_ok = false;
        udp_send(server, 53, DNS_SPORT, q, (uint16_t)qlen);

        uint64_t t = timer_get_ticks() + 100;        /* 1 sn bekleyis */
        while (!dns_done && timer_get_ticks() < t) cpu_hlt();
        dns_waiting = false;
        udp_sock_remove(sock);

        if (dns_done) {
            if (out_ip && dns_ok) *out_ip = dns_result;
            return dns_ok;
        }
    }
    return false;
}

extern "C" void net_ifconfig(void) {
    kprintf("eth0     IP : %u.%u.%u.%u\n",
            (our_ip >> 24) & 0xFF, (our_ip >> 16) & 0xFF,
            (our_ip >> 8) & 0xFF, our_ip & 0xFF);
    kprintf("eth0  Maske : %u.%u.%u.%u\n",
            (our_mask >> 24) & 0xFF, (our_mask >> 16) & 0xFF,
            (our_mask >> 8) & 0xFF, our_mask & 0xFF);
    kprintf("eth0  Ag   : %u.%u.%u.%u\n",
            ((our_ip & our_mask) >> 24) & 0xFF, ((our_ip & our_mask) >> 16) & 0xFF,
            ((our_ip & our_mask) >> 8) & 0xFF, (our_ip & our_mask) & 0xFF);
    kprintf("eth0  Yol  : %u.%u.%u.%u\n",
            (gateway >> 24) & 0xFF, (gateway >> 16) & 0xFF,
            (gateway >> 8) & 0xFF, gateway & 0xFF);
    kprintf("eth0  DNS  : %u.%u.%u.%u\n",
            (dns_server >> 24) & 0xFF, (dns_server >> 16) & 0xFF,
            (dns_server >> 8) & 0xFF, dns_server & 0xFF);
    kprintf("eth0  MAC  : %02x:%02x:%02x:%02x:%02x:%02x\n",
            our_mac[0], our_mac[1], our_mac[2], our_mac[3], our_mac[4], our_mac[5]);
    kprintf("istatistik  : rx=%llu tx=%llu rx-bayt=%llu\n",
            (unsigned long long)stat_rx, (unsigned long long)stat_tx,
            (unsigned long long)stat_rx_bytes);
}

extern "C" uint32_t net_get_dns(void) { return dns_server; }
extern "C" uint32_t net_get_ip(void) { return our_ip; }
extern "C" uint32_t net_get_mask(void) { return our_mask; }
extern "C" uint32_t net_get_gw(void) { return gateway; }

extern "C" bool net_active(void) { return rtl8139_active(); }

extern "C" uint32_t net_parse_ip(const char* s, bool* ok) {
    uint32_t ip = 0;
    int segs = 0;
    const char* p = s;
    *ok = false;
    while (*p) {
        if (!(*p >= '0' && *p <= '9')) return 0;
        int v = 0;
        while (*p >= '0' && *p <= '9') {
            v = v * 10 + (*p - '0');
            if (v > 255) return 0;
            p++;
        }
        ip = (ip << 8) | (uint32_t)v;
        segs++;
        if (*p == '.') p++;
        else break;
    }
    if (segs == 4 && *p == 0) { *ok = true; return ip; }
    return 0;
}