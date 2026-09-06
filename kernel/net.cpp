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
        if (dst != our_ip && dst != bc && dst != 0xFFFFFFFFu) return;
        if (ip[9] == 1) handle_icmp(ip, (uint16_t)(len - 14), frame);
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
    kprintf("eth0  MAC  : %02x:%02x:%02x:%02x:%02x:%02x\n",
            our_mac[0], our_mac[1], our_mac[2], our_mac[3], our_mac[4], our_mac[5]);
    kprintf("istatistik  : rx=%llu tx=%llu rx-bayt=%llu\n",
            (unsigned long long)stat_rx, (unsigned long long)stat_tx,
            (unsigned long long)stat_rx_bytes);
}

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