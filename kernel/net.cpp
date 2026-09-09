#include "kernel.h"
#include "x86.h"
#include "nic.h"
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

/* ---- ICMP destination-unreachable -> soket notu (handle_icmp doldurur, poll isler) ---- */
struct IcmpUr { volatile bool pend; volatile bool tcp;
                volatile uint32_t ip; volatile uint16_t sport, dport; };
IcmpUr icmp_ur = { false, false, 0, 0, 0 };

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
volatile bool  ethsnoop = false;                  /* tx test yakalama */
volatile int   ethsnoop_n = 0;
volatile uint16_t ethsnoop_len[4];
uint8_t ethsnoop_frame[4][1500];
volatile bool  eth_mute = false;                  /* tx test: NIC'i atla (slirp RST'leri izole) */

void eth_send(const uint8_t* dmac, uint16_t type, const uint8_t* payload, uint16_t len) {
    uint8_t frame[1514];
    memcpy(frame, dmac, 6);
    memcpy(frame + 6, our_mac, 6);
    frame[12] = (uint8_t)(type >> 8);
    frame[13] = (uint8_t)(type & 0xFF);
    memcpy(frame + 14, payload, len);
    if (ethsnoop && ethsnoop_n < 4) {
        ethsnoop_len[ethsnoop_n] = (uint16_t)(len + 14);
        memcpy(ethsnoop_frame[ethsnoop_n], frame, (len + 14 > 1500) ? 1500 : (len + 14));
        ethsnoop_n++;
    }
    stat_tx++;
    if (eth_mute) return;                        /* sanal test: gercekte gonderme */
    nic_send(frame, (uint16_t)(len + 14));
}

/* ---- ARP ---- */
void arp_learn(uint32_t ip, const uint8_t* mac) {
    if (ip == 0xFFFFFFFFu) return;
    for (int i = 0; i < 8; i++) {
        if (arp_cache[i].valid && arp_cache[i].ip == ip) {
            memcpy(arp_cache[i].mac, mac, 6);
            return;
        }
    }
    for (int i = 0; i < 8; i++)
        if (!arp_cache[i].valid) {
            arp_cache[i].valid = true;
            arp_cache[i].ip = ip;
            memcpy(arp_cache[i].mac, mac, 6);
            return;
        }
}

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

    uint64_t fl;
    asm volatile("pushfq; pop %0" : "=r"(fl));
    if (!(fl & (1u << 9))) return false;               /* IRQ icinde (IF=0): bloke etme */

    arp_send(1, ip, bcast_mac);                       /* istek */
    arp_want_ip = ip; arp_waiting = true; arp_done = false;
    uint64_t deadline = timer_get_ticks() + 30;       /* 300ms */
    while (!arp_done && timer_get_ticks() < deadline && !sys_intr_pending()) { sys_intr_poll(); cpu_hlt(); }
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

    arp_learn(spa, sha);                         /* komusunu cache'e yaz/ekle */

    if (oper == 1 && tpa == our_ip) {
        arp_send(2, spa, sha);                        /* yanit */
    } else if (oper == 2 && arp_waiting && spa == arp_want_ip) {
        memcpy(arp_reply_mac, sha, 6);
        arp_done = true;
    }
}

/* ---- IPv4 ---- */
/* Max parca verisi: MTU(1500) - IP basligi(20) = 1480; 8 baytlk kata yuvarlanir. */
constexpr uint16_t IP_MF   = 0x2000;
constexpr uint16_t IP_FRAG_MAX = 1480;

void ip_send(uint32_t dst, const uint8_t* dmac, uint8_t proto,
             const uint8_t* payload, uint16_t len) {
    uint8_t tmpmac[6];
    if (!dmac) {
        uint32_t l2dst = dst;
        if ((dst & our_mask) != (our_ip & our_mask))   /* dis ag: gateway uzerinden */
            l2dst = gateway;
        if (!arp_resolve(l2dst, tmpmac)) return;
        dmac = tmpmac;
    }

    static uint16_t ip_id = 0x1000;
    uint16_t id = ++ip_id;

    if (len > IP_FRAG_MAX) {                     /* parcalamak gerekiyor (RFC 791) */
        uint16_t off = 0;
        while (off < len) {
            uint16_t chunk = len - off;
            bool last = true;
            if (chunk > IP_FRAG_MAX) {
                chunk = IP_FRAG_MAX;             /* 1480 zaten 8 hizali */
                last = false;
            }
            uint8_t buf[20 + IP_FRAG_MAX];
            buf[0] = 0x45; buf[1] = 0;
            wr16(buf + 2, (uint16_t)(20 + chunk));
            wr16(buf + 4, id);
            wr16(buf + 6, (uint16_t)((last ? 0 : IP_MF) | (off / 8)));
            buf[8] = 64; buf[9] = proto;
            wr16(buf + 10, 0);
            wr32(buf + 12, our_ip);
            wr32(buf + 16, dst);
            wr16(buf + 10, ip_checksum(buf, 20));
            memcpy(buf + 20, payload + off, chunk);
            eth_send(dmac, 0x0800, buf, (uint16_t)(20 + chunk));
            off = (uint16_t)(off + chunk);
        }
        return;
    }

    uint8_t buf[20 + 1500];
    buf[0] = 0x45; buf[1] = 0;
    uint16_t tot = (uint16_t)(20 + len);
    wr16(buf + 2, tot);
    wr16(buf + 4, id);
    wr16(buf + 6, 0);
    buf[8] = 64; buf[9] = proto;
    wr16(buf + 10, 0);                    /* checksum sonra */
    wr32(buf + 12, our_ip);
    wr32(buf + 16, dst);
    wr16(buf + 10, ip_checksum(buf, 20));
    memcpy(buf + 20, payload, len);
    eth_send(dmac, 0x0800, buf, tot);
}

void handle_icmp(const uint8_t* ip, uint16_t len, const uint8_t* eth_src) {
    uint32_t ihl = (uint32_t)(ip[0] & 0x0F) * 4u;
    if (ihl < 20 || len < ihl + 8) return;
    const uint8_t* icmp = ip + ihl;
    uint16_t iclen = (uint16_t)(len - ihl);
    if (ip_checksum(icmp, iclen) != 0) return;         /* hatali ICMP checksum: dusur */

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
    } else if (icmp[0] == 3) {                          /* destination unreachable -> TCP soket haberi */
        /* geri gonderim: orijinal IP basligi + en az 8 bayt TCP basligi */
        if (iclen < 8 + 20 + 8) return;
        const uint8_t* oip = icmp + 8;
        uint16_t oihl = (uint16_t)((oip[0] & 0x0F) * 4u);
        if (oihl < 20 || iclen < 8 + oihl + 8) return;
        icmp_ur.ip = rd32(oip + 12);
        icmp_ur.sport = rd16(oip + oihl);
        icmp_ur.dport = rd16(oip + oihl + 2);
        icmp_ur.tcp = (oip[9] == 6);
        icmp_ur.pend = true;
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
    uint8_t u[8 + 1480 + 512];
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

/* ---- UDP soketler (fd tabanli) ----
   Yerel port ile eslestirilir; gelen datagramlar soket kuyruguna yazilir.
   Kuyruk ISR/timer yolunda dolar (handle_udp), tuketim syscall/cekirdek
   baglaminda; tek CPU ilerlemesi + volatile kuyruk sayaci yeterli. */
enum { UDP_SOCKS = 8, UDP_QLEN = 4, UDP_DGRAM_MAX = 1500 };

struct UdpDgram {
    uint32_t src_ip;
    uint16_t src_port;
    uint16_t len;
    uint8_t  data[UDP_DGRAM_MAX];
};

struct UdpSock {
    bool              used;
    bool              bound;
    uint16_t          lport;
    int               qr, qw;
    volatile uint32_t qn;
    UdpDgram          q[UDP_QLEN];
};
UdpSock udp_socks[UDP_SOCKS];

int udp_sock_alloc(void) {
    for (int i = 0; i < UDP_SOCKS; i++)
        if (!udp_socks[i].used) {
            memset(&udp_socks[i], 0, sizeof(udp_socks[i]));
            udp_socks[i].used = true;
            return i;
        }
    return -1;
}

int udp_sock_bound(uint16_t port) {
    for (int i = 0; i < UDP_SOCKS; i++)
        if (udp_socks[i].used && udp_socks[i].bound && udp_socks[i].lport == port)
            return i;
    return -1;
}

uint16_t udp_auto_port(void) {
    for (int g = 0; g < 64; g++) {
        uint16_t p = (uint16_t)(0xC000 | (((timer_get_ticks() * 2654435761u) >> 16) & 0x3FFF));
        if (udp_sock_bound(p) < 0) return p;
    }
    return (uint16_t)(0xC000 + (timer_get_ticks() % 0x3FFF));
}

void handle_udp(const uint8_t* ip, uint16_t len, const uint8_t* eth_src) {
    uint32_t ihl = (uint32_t)(ip[0] & 0x0F) * 4u;
    if (len < ihl + 8) return;
    const uint8_t* u = ip + ihl;
    uint16_t sport = rd16(u);
    uint16_t dport = rd16(u + 2);
    uint16_t ulen = rd16(u + 4);
    if (ulen < 8 || ulen > len - ihl) ulen = (uint16_t)(len - ihl);

    if (rd16(u + 6) != 0 &&                           /* UDP checksum (IPv4'te 0 = yok) */
        udp_checksum(rd32(ip + 12), rd32(ip + 16), u, ulen) != 0)   /* alici degismezci: gecerli pakette 0 */
        return;

    if (eth_src) arp_learn(rd32(ip + 12), eth_src);       /* gondereni komsu olarak ogren */

    if (dport == 68 && dhcp_waiting && ulen >= 244) {      /* bootpc: DHCP */
        handle_dhcp(u + 8, (uint16_t)(ulen - 8));
        return;
    }
    int s = udp_sock_bound(dport);                         /* dinleyen soket var mi */
    if (s < 0) return;
    UdpSock& us = udp_socks[s];
    if (us.qn >= UDP_QLEN) return;                         /* kuyruk dolu: dusur */
    UdpDgram& d = us.q[us.qw];
    d.src_ip   = rd32(ip + 12);
    d.src_port = sport;
    d.len = (uint16_t)((ulen - 8 > UDP_DGRAM_MAX) ? UDP_DGRAM_MAX : ulen - 8);
    memcpy(d.data, u + 8, d.len);
    us.qw = (us.qw + 1) % UDP_QLEN;
    us.qn++;
}

/* ---- UDP fd API (kullanici syscall'lari icin) ---- */
extern "C" int net_udp_socket(void) {
    if (!nic_up()) return -1;
    return udp_sock_alloc();
}

extern "C" bool net_udp_bind(int s, uint16_t port) {
    if (s < 0 || s >= UDP_SOCKS || !udp_socks[s].used) return false;
    UdpSock& u = udp_socks[s];
    if (u.bound) return false;
    if (port == 0) port = udp_auto_port();
    if (udp_sock_bound(port) >= 0) return false;
    u.bound = true;
    u.lport = port;
    u.qn = 0; u.qr = 0; u.qw = 0;
    return true;
}

extern "C" int net_udp_send_to(int s, uint32_t dst, uint16_t dport,
                               const uint8_t* data, uint16_t len) {
    if (s < 0 || s >= UDP_SOCKS || !udp_socks[s].used) return -1;
    if (!nic_up()) return -1;
    if (!udp_socks[s].bound && !net_udp_bind(s, 0)) return -1;
    if (len > 1472) len = 1472;                    /* MTU1500 - IP20 - UDP8 */
    /* syscall icinde (IF=0) arp_resolve bloke edemez; frame gonderilmeden
       once ARP tamamlanmasi icin gecici IRQ penceresi ac. */
    uint64_t fl = 0;
    asm volatile("pushfq; pop %0" : "=r"(fl));
    asm volatile("sti");
    udp_send(dst, dport, udp_socks[s].lport, data, len);
    asm volatile("push %0; popfq" : : "r"(fl) : "cc", "memory");
    return (int)len;
}

extern "C" bool net_udp_wait(int s, uint32_t ticks) {
    if (s < 0 || s >= UDP_SOCKS || !udp_socks[s].used) return false;
    uint64_t dd = timer_get_ticks() + ticks;
    /* int 0x80 interrupt kapisi IF'i kapatir; beklenti timer/NIC IRQ'lari
       ister (tik ilerlesin, RX işlensin). Kalici IF=1 tehlikeli (syscall
       yeniden giris), bu yuzden sadece bu dongu boyunca gecici ac. */
    uint64_t fl = 0;
    asm volatile("pushfq; pop %0" : "=r"(fl));
    asm volatile("sti");
    while (!udp_socks[s].qn && timer_get_ticks() < dd && !sys_intr_pending()) { sys_intr_poll(); cpu_hlt(); }
    asm volatile("push %0; popfq" : : "r"(fl) : "cc", "memory");
    return udp_socks[s].qn > 0;
}

extern "C" int net_udp_recv_from(int s, uint8_t* out, uint32_t cap,
                                 uint32_t* src_ip, uint16_t* src_port) {
    if (s < 0 || s >= UDP_SOCKS || !udp_socks[s].used) return -1;
    UdpSock& u = udp_socks[s];
    if (!u.qn) return 0;
    UdpDgram& d = u.q[u.qr];
    uint16_t n = (uint16_t)((cap < d.len) ? cap : d.len);
    if (out && n) memcpy(out, d.data, n);
    if (src_ip)   *src_ip   = d.src_ip;
    if (src_port) *src_port = d.src_port;
    u.qr = (u.qr + 1) % UDP_QLEN;
    u.qn--;
    return (int)n;
}

extern "C" bool net_udp_close(int s) {
    if (s < 0 || s >= UDP_SOCKS || !udp_socks[s].used) return false;
    udp_socks[s].used  = false;
    udp_socks[s].bound = false;
    udp_socks[s].qn    = 0;
    return true;
}

/* ---- DNS (RFC 1035) ----
   Sorgu yapimi ve yanit cozumlemesi saf (state'siz) islevlerdir;
   ag isi fd tabanli UDP soketleri uzerinden yapilir (net_dns_resolve). */

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

/* DNS yanitindan A kaydini cikar; basarili olursa *out'u doldurup true doner. */
static bool dns_parse_a(const uint8_t* data, uint16_t len, uint32_t* out) {
    if (len < 12) return false;
    if (!(rd16(data + 2) & 0x8000)) return false;        /* yanit (QR) degil */
    uint16_t qd = rd16(data + 4);
    uint16_t an = rd16(data + 6);
    int pos = 12;
    int limit = (int)len;
    for (int i = 0; i < qd; i++) {
        dns_skip_name(data, pos, limit);
        if (pos < 0) return false;
        pos += 4;
    }
    for (int i = 0; i < an; i++) {
        dns_skip_name(data, pos, limit);
        if (pos < 0) return false;
        if (pos + 10 > limit) return false;
        uint16_t type  = rd16(data + pos);
        uint16_t rdlen = rd16(data + pos + 8);
        pos += 10;
        if (type == 1 && rdlen == 4 && pos + 4 <= limit) {   /* A kaydi */
            if (out) *out = rd32(data + pos);
            return true;
        }
        pos += rdlen;
    }
    return false;
}

/* ---- TCP (RFC 793/1122/6298): tam cekirdek, tek aktif baglanti ----
   Durum makinesi, kumulatif ACK, karsi MSS, pencere takibi, retransmisyon
   (RTO + ikileyerek geri cekilme), dupACK hizli yeniden gonderim,
   out-of-order yeniden siralamali RX, aktif/pasif FIN kapanisi.
   ISR (timer/NIC) cagirir: sadece volatile alanlar ISR'de yazilir. */

constexpr uint16_t TCP_FLAG_FIN  = 0x01;
constexpr uint16_t TCP_FLAG_SYN  = 0x02;
constexpr uint16_t TCP_FLAG_RST  = 0x04;
constexpr uint16_t TCP_FLAG_PSH  = 0x08;
constexpr uint16_t TCP_FLAG_ACK  = 0x10;

constexpr int    TCP_MSS     = 1460;        /* MTU1500 - IP20 - TCP20 */
constexpr int    TCP_RX_RING = 8192;        /* soket basina gelen veri tamponu */
constexpr int    TCP_OOO_MAX = 4;           /* soket basina siralamasi bekleyen segment kapi */
constexpr int    TCP_SOCKS   = 8;           /* eszamanli soket sayisi */
constexpr int    TCP_TXQ     = 8;           /* soket basina onaysiz (in-flight) segment kapi */
constexpr int    TCP_BACKLOG = 6;           /* LISTEN'de onaysiz (SYN_RECV) cocuk siniri */
constexpr uint32_t TCP_RTO0  = 500;         /* ilk RTO (ms) */
constexpr uint32_t TCP_RTO_MIN = 200;
constexpr uint32_t TCP_RTO_MAX = 3000;
constexpr uint32_t TCP_MAX_RETRANS = 12;    /* ardarda RTO'da vazgec (RST/err) */
constexpr uint32_t TCP_CWND_INIT = 4 * (uint32_t)TCP_MSS;     /* slow-start baslangic penceresi */
constexpr uint32_t TCP_SSTHRESH_INIT = 64 * (uint32_t)TCP_MSS;
constexpr int      TCP_SACK_BLK_MAX  = 3;   /* ACK basina iletilen SACK blogu */
constexpr uint32_t TCP_KA_IDLE = 600;       /* keepalive: bos kaldirac esigi (poll tick) */
constexpr uint32_t TCP_KA_RATE = 25;        /* keepalive: yoklama arasi (poll tick) */
constexpr uint32_t TCP_KA_CNT  = 6;         /* keepalive: dayanilmayan yoklama siniri */

struct OooSlice {
    bool     used;
    uint32_t seq;
    uint16_t len;
    uint8_t  data[TCP_MSS];
};

struct TxSlot {
    volatile bool      pend;      /* gonderildi, onay bekliyor */
    volatile bool      sacked;    /* peer SACK'lerde aldini bildirdi (retrans muaf) */
    uint32_t           seq;
    uint16_t           len;
    volatile uint64_t  sent_at;   /* gonderim anindaki tick (10ms) */
    uint8_t            data[TCP_MSS];
};

struct Tcb {
    int         used;        /* soket bos mu */
    bool        poll_busy;   /* bu tikte zaten poll isleniyor (IRQ/loop reentrancy) */
    uint8_t     st;          /* 0 KAPALI,1 SYNSENT,2 ESTAB,3 FINW1,4 FINW2,
                                5 CLOSEW,6 LASTACK,7 TIMEW,8 LISTEN,9 SYNRECV */
    int         lfd;         /* LISTEN ana soket (kabul edilen cocusu icin) */
    uint32_t    ip;          /* peer adres */
    uint16_t    sport, dport;
    uint32_t    iss;         /* bizim ilk seq */
    volatile uint64_t created_at; /* LISTEN cocugu olusma ani (accept sirasi) */
    volatile uint32_t snd_una;   /* onaysiz en eski seq */
    volatile uint32_t snd_nxt;   /* sonraki gonderilecek seq */
    volatile uint32_t rcv_nxt;   /* peer'dan beklenen seq */
    volatile uint32_t snd_wnd;   /* peer'in penceresi (window scaling uygulanmis) */
    volatile uint8_t  st_v;      /* ISR'den gorunen durum (st ile esit) */
    uint16_t  mss;
    uint32_t  rto;           /* ms (Jacobson) */
    uint32_t  srtt, rttvar;  /* yumusatilmis RTT ve sapma (ms) */
    uint32_t  cwnd, ssthresh;/* kongesyon kontrolu (bayt) */
    uint32_t  dupacks;
    bool      fr;           /* hizli kurtarma (RFC 5681) aktif */
    uint32_t  recover;      /* kurtarma bitis sekansi = giristeki snd_nxt */
    uint8_t   lt;           /* kalan sinirli-gonderim (RFC 3042) hakki */
    uint8_t   ws_peer;      /* peer'in istedigi pencere kaydirma (RFC 1323) */
    bool      ts_ok;        /* zaman damgasi (RFC 1323) anlasildi */
    uint32_t  ts_recent;    /* peer'in son TSval'i (TSecr olarak yansitilir) */
    uint32_t  ts_echo;      /* peer'in yansittigi bizim TSval (RTT ornegi) */
    uint8_t   tx_head, tx_tail;  /* onaysiz segment halkasi */
    TxSlot    txb[TCP_TXQ];
    uint8_t   nagle_buf[TCP_MSS];  /* Nagle (RFC 896): kucuk yazim birikimi */
    uint16_t  nagle_len;
    volatile uint64_t last_rx;      /* peer'dan son gelen paket ani (keepalive) */
    volatile uint64_t ka_at;        /* sonraki keepalive yoklama ani */
    volatile uint8_t  ka_probes;    /* karsiliksiz kalan keepalive yoklama sayaci */
    bool fin_tx, fin_rx;
    uint32_t  fin_seq;       /* FIN'imizin seq'i */
    volatile bool fin_pend;      /* FIN gonderildi henuz onaylanmadi */
    volatile uint64_t fin_sent_at;
    volatile uint64_t probe_at;  /* sonraki sifir-pencere probe ani */
    volatile uint32_t retries;   /* ardarda RTO retransmisyon sayaci */
    uint64_t  tw_at;         /* TIME_WAIT sayaci */
    uint64_t  close_at;      /* FINW1/FINW2 limit (aktif kapanis devam sureci) */
    volatile bool ok, done, err;
    volatile bool win_update;   /* pencere 0 kapi oldu; drenaj sonrasi ACK lazim */
    volatile bool ack_want;     /* biriktirilmis ACK bekliyor */
    volatile uint8_t  ack_inv;  /* ACK bekleyen segment sayisi */
    volatile uint64_t ack_at;
    volatile uint32_t last_ack;
    volatile uint32_t rlen;  /* rxr bekleyen bayt (ISR yazar) */
    volatile uint32_t rxr_w, rxr_fill;
    uint8_t  rxr[TCP_RX_RING];      /* ISR yazar / uygulama okur */
    OooSlice ooo[TCP_OOO_MAX];
};

static Tcb conns[TCP_SOCKS];

uint16_t tcp_checksum(uint32_t saddr, uint32_t daddr, const uint8_t* tt, uint16_t tlen) {
    uint32_t sum = 0;
    sum += (saddr >> 16) + (saddr & 0xFFFF);
    sum += (daddr >> 16) + (daddr & 0xFFFF);
    sum += 6;
    sum += tlen;
    int n = tlen;
    while (n > 1) { sum += ((uint32_t)tt[0] << 8) | tt[1]; tt += 2; n -= 2; }
    if (n) sum += (uint32_t)tt[0] << 8;
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)~sum;
}

/* seq ile beraber tek TCP segmenti gonderir; snd_nxt'e dokunmaz.
   mss_opt: SYN/MSS secenegi; sack: onceki veri ardiligi bildiren SACK bloklari. */
void tcp_emit(Tcb& t, uint32_t seq, uint16_t flags, const uint8_t* data, uint16_t len,
              bool mss_opt, bool sack) {
    uint8_t tt[TCP_MSS + 64];
    memset(tt, 0, TCP_MSS + 64);         /* secenek bolgesi once temizlenir */
    uint16_t off = 20;
    if (mss_opt) {                       /* SYN(ACK): MSS + WS (RFC 1323) + TS onerisi */
        tt[off] = 2; tt[off + 1] = 4;
        tt[off + 2] = (TCP_MSS >> 8) & 0xFF; tt[off + 3] = TCP_MSS & 0xFF;
        off += 4;
        tt[off] = 3; tt[off + 1] = 3; tt[off + 2] = 0;      /* kaydirma 0: penceremiz kucuk */
        off += 3;
    }
    if (mss_opt || t.ts_ok) {            /* zaman damgasi: SYN'de oner, sonra gerekliyse */
        tt[off] = 8; tt[off + 1] = 10;
        wr32(tt + off + 2, (uint32_t)timer_get_ticks());
        wr32(tt + off + 6, t.ts_recent);
        off += 10;
    }
    if (sack && !mss_opt) {
        uint8_t n = 0;
        for (int i = 0; i < TCP_OOO_MAX && n < TCP_SACK_BLK_MAX; i++)
            if (t.ooo[i].used && (uint32_t)(t.ooo[i].seq + t.ooo[i].len) > t.rcv_nxt) n++;
        if (n) {
            tt[off] = 5;
            tt[off + 1] = (uint8_t)(2 + 8 * n);
            uint32_t p = (uint32_t)(off + 2);
            uint8_t w = 0;
            for (int i = 0; i < TCP_OOO_MAX && w < n; i++) {
                if (!t.ooo[i].used || (uint32_t)(t.ooo[i].seq + t.ooo[i].len) <= t.rcv_nxt) continue;
                wr32(tt + p, t.ooo[i].seq);
                wr32(tt + p + 4, (uint32_t)(t.ooo[i].seq + t.ooo[i].len));
                p += 8; w++;
            }
            off = (uint16_t)(off + 2 + 8 * n);
        } else sack = false;
    }
    uint16_t hlen = (uint16_t)((off + 3) & ~3u);     /* 4 bayt hizalama */
    wr16(tt, t.sport);
    wr16(tt + 2, t.dport);
    wr32(tt + 4, seq);
    wr32(tt + 8, t.rcv_nxt);
    tt[12] = (uint8_t)((hlen / 4) << 4);
    tt[13] = (uint8_t)(flags & 0x3F);
    uint16_t free = (uint16_t)(TCP_RX_RING - t.rxr_fill);
    uint16_t adv = free > (TCP_RX_RING / 2) ? (TCP_RX_RING / 2) : free;  /* pencere <= halka/2 */
    wr16(tt + 14, adv);
    for (uint16_t k = off; k < hlen; k++) tt[k] = 1; /* bos secenek bolgu = NOP */
    wr16(tt + 16, 0);
    if (len) memcpy(tt + hlen, data, len);
    wr16(tt + 16, tcp_checksum(our_ip, t.ip, tt, (uint16_t)(len + hlen)));
    ip_send(t.ip, NULL, 6, tt, (uint16_t)(len + hlen));
}

void tcp_ack_now(Tcb& t) {
    t.last_ack = t.rcv_nxt;
    t.ack_want = false; t.ack_inv = 0; t.ack_at = 0;
    bool so = false;
    for (int i = 0; i < TCP_OOO_MAX; i++)
        if (t.ooo[i].used && (uint32_t)(t.ooo[i].seq + t.ooo[i].len) > t.rcv_nxt) { so = true; break; }
    tcp_emit(t, t.snd_nxt, TCP_FLAG_ACK, NULL, 0, false, so);
}

/* biriktirilmis ACK: her segmentte gonderim yerine 2 segmentte/1 tiki hizla gonder. */
static void ack_delayed(Tcb& t) {
    t.ack_want = true;
    if (++t.ack_inv >= 2 || t.win_update) tcp_ack_now(t);
    else if (!t.ack_at) t.ack_at = timer_get_ticks() + 2;
}

/* retransmisyon zamanlayicisi: her spin dongusunde cagir. */
static void rto_backoff(Tcb& t) {           /* zaman asimi: geri cekilme + pencereleri kir */
    uint32_t mss = t.mss ? t.mss : (uint32_t)TCP_MSS;
    uint32_t h = t.cwnd / 2;
    t.ssthresh = h > 2u * mss ? h : 2u * mss;
    t.cwnd = mss;                            /* RTO sonrasi dogrudan 1 MSS */
}

/* halkada en eski onaysiz slot; tercihen SACK'te bildirilmemis (kayip) olan.
   SACK sayesinde degilse de gorunmeyen en eskiye geri don (guvenlik). */
static int ts_pick(Tcb& t) {
    int fallback = -1;
    for (uint32_t i = 0; i < (uint32_t)TCP_TXQ; i++) {
        uint8_t j = (uint8_t)((t.tx_tail + i) % TCP_TXQ);
        if (!t.txb[j].pend) continue;
        if (fallback < 0) fallback = j;
        if (!t.txb[j].sacked) return j;      /* ilk dogrulanmamis aday */
    }
    return fallback;
}

/* vazgecme: gorunen baglantiyi hata ile kapat (RST almis gibi). */
static void tcp_abort(Tcb& t) {
    t.err = true; t.done = true; t.ok = false;
    t.used = 0; t.st = 0; t.st_v = 0;
}

/* IRQ (timer tick) ve engelleyici dongu tcp_poll'u ayni sokette icine icine girebilir
   (dongu tcp_poll calisirken timer IRQ tetiklenir). poll_busy bayragi yeniden giris kenarini
   sekar: IRQ altinda zaten islenen soket bu tikte atlanir. */
static void tcp_poll(Tcb& t);   /* asagida tanimli */
static void tcp_poll_guarded(Tcb& t) {
    if (!t.used || t.poll_busy) return;
    t.poll_busy = true;
    tcp_poll(t);
    t.poll_busy = false;
}

/* ICMP destination-unreachable notunu eslesen TCP sokete uygula. */
static void icmp_apply(void) {
    if (!icmp_ur.pend) return;
    if (icmp_ur.tcp) {
        for (int i = 0; i < TCP_SOCKS; i++) {
            Tcb& c = conns[i];
            if (c.used && c.st != 8 && c.sport == icmp_ur.sport &&
                c.dport == icmp_ur.dport && c.ip == icmp_ur.ip) { tcp_abort(c); break; }
        }
    }
    icmp_ur.pend = false;
}

void tcp_poll(Tcb& t) {
    if (!t.used || t.st == 0 || t.st == 1) return;
    icmp_apply();
    if (t.ack_want && t.rcv_nxt != t.last_ack && timer_get_ticks() >= t.ack_at) tcp_ack_now(t);
    if (t.st == 7) {                       /* TIME_WAIT sayaci */
        if (timer_get_ticks() >= t.tw_at) { t.used = 0; t.st = 0; t.ok = true; t.done = true; }
        return;
    }
    /* sifir-pencere persist probe (RFC 1122 4.2.2.17): penceresi kapaliyken 1 baytlk yoklama */
    if (t.snd_wnd == 0 && t.snd_una != t.snd_nxt &&
        timer_get_ticks() >= t.probe_at && !t.fin_pend) {
        uint8_t one = 0xAA;                                  /* sifir-pencere yoklama (pencere=0) */
        tcp_emit(t, t.snd_nxt, TCP_FLAG_ACK | TCP_FLAG_PSH, &one, 1, false, false);
        t.probe_at = timer_get_ticks() + ((t.rto + 49) / 50);
    }
    /* FIN retransmisyonu (FINW1 / LAST_ACK): veri slotuna girmedigi icin ayri izlenir */
    if (t.fin_pend &&
        timer_get_ticks() - t.fin_sent_at >= (uint64_t)((t.rto + 49) / 50)) {
        if (++t.retries > TCP_MAX_RETRANS) { tcp_abort(t); return; }
        tcp_emit(t, t.fin_seq, TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0, false, false);
        t.fin_sent_at = timer_get_ticks();
        if (t.rto < TCP_RTO_MAX) t.rto *= 2;
        if (t.rto > TCP_RTO_MAX) t.rto = TCP_RTO_MAX;
    }
    if (t.st == 3 || t.st == 4) {          /* aktif kapanis: peer FIN'i bekle; sure sinirli */
        if (timer_get_ticks() >= t.close_at) { t.used = 0; t.st = 0; }
        return;
    }
    /* en eski onaysiz (SACK ile dogrulanmamis) segmentin RTO'sunu kontrol et */
    int pi = ts_pick(t);
    if (pi >= 0 && t.snd_una == t.txb[pi].seq &&
        timer_get_ticks() - t.txb[pi].sent_at >= (uint64_t)((t.rto + 49) / 50)) {
        if (++t.retries > TCP_MAX_RETRANS) { tcp_abort(t); return; }
        TxSlot& sl = t.txb[pi];
        tcp_emit(t, sl.seq, TCP_FLAG_ACK | TCP_FLAG_PSH, sl.data, sl.len, false, false);
        sl.sent_at = timer_get_ticks();
        if (t.rto < TCP_RTO_MAX) t.rto *= 2;
        if (t.rto > TCP_RTO_MAX) t.rto = TCP_RTO_MAX;
        rto_backoff(t);
        t.fr = false; t.dupacks = 0; t.lt = 0;   /* RTO: hizli kurtarmadan cik, slow start */
    }
    /* keepalive (RFC 1122 4.2.3.6): bos ESTAB'da komsuyu yokla; yanit gelmezse kir. */
    if (t.st == 2) {
        uint64_t now = timer_get_ticks();
        if (t.ka_probes) {
            if (t.snd_una != t.snd_nxt) t.ka_probes = 0;   /* etkinlik var: sayaci sifirla */
            else if (now - t.ka_at >= TCP_KA_RATE) {
                if (++t.ka_probes > TCP_KA_CNT) { tcp_abort(t); return; }
                t.ka_at = now;
                tcp_emit(t, t.snd_una - 1, TCP_FLAG_ACK, NULL, 0, false, false);
            }
        } else if (t.snd_una == t.snd_nxt && now - t.last_rx >= TCP_KA_IDLE) {
            t.ka_probes = 1; t.ka_at = now;
            tcp_emit(t, t.snd_una - 1, TCP_FLAG_ACK, NULL, 0, false, false);
        }
    }
}

/* TCP secenekleri: MSS (2), WS (3), TS (8). TCB'ye yazar; SYN sonrasinda
   snd_wnd kaydirma ve RTT ornegi icin kullanilir. SACK ayri (sack_apply). */
static void tcp_opts_parse(Tcb& t, const uint8_t* tt, uint16_t offhdr) {
    uint32_t o = 20;
    while (o + 2 <= offhdr) {
        uint8_t kind = tt[o];
        if (kind == 0) break;
        if (kind == 1) { o++; continue; }
        uint8_t olen = tt[o + 1];
        if (olen < 2 || (uint32_t)(o + olen) > offhdr) break;
        if (kind == 2 && olen == 4) t.mss = rd16(tt + o + 2);
        else if (kind == 3 && olen == 3) {
            uint8_t s = tt[o + 2];
            if (s > 14) s = 0;
            t.ws_peer = s;
        }
        else if (kind == 8 && olen == 10) {
            t.ts_ok = true;
            t.ts_recent = rd32(tt + o + 2);      /* peer'in TSVal'i -> TSecr */
            t.ts_echo   = rd32(tt + o + 6);      /* peer'in yansittigi bizim TSVal -> RTT */
        }
        o += olen;
    }
}

/* RTT orneklemesi: en eski onaysiz slotun gonderim ani ile bu anin uzakligi.
   RFC 6298: her segmente degil, RTT boyunca tek ornek. */
static void rtt_apply_ms(Tcb& t, uint32_t rtt_ms) {
    if (rtt_ms == 0) rtt_ms = 1;
    if (!t.srtt) { t.srtt = rtt_ms; t.rttvar = rtt_ms / 2; }
    else {
        uint32_t dv = t.srtt > rtt_ms ? t.srtt - rtt_ms : rtt_ms - t.srtt;
        t.rttvar = (3u * t.rttvar + dv) / 4u;
        t.srtt   = (7u * t.srtt + rtt_ms) / 8u;
    }
    uint32_t v4 = t.rttvar * 4u; if (v4 < 50) v4 = 50;
    uint32_t rt = t.srtt + v4;
    if (rt < TCP_RTO_MIN) rt = TCP_RTO_MIN;
    if (rt > TCP_RTO_MAX) rt = TCP_RTO_MAX;
    t.rto = rt;
}

static void rtt_update(Tcb& t) {
    TxSlot& sl = t.txb[t.tx_tail];
    if (!sl.pend) return;
    rtt_apply_ms(t, (uint32_t)((timer_get_ticks() - sl.sent_at) * 10u));
}

/* kumulatif ACK: kapsanan onaysiz slotlari temizle (kaynaktan en eskiye dogru devamli). */
static void ack_slots(Tcb& t, uint32_t ack) {
    while (t.txb[t.tx_tail].pend &&
           (uint32_t)(t.txb[t.tx_tail].seq + t.txb[t.tx_tail].len) <= ack) {
        t.txb[t.tx_tail].pend = false;
        t.tx_tail = (t.tx_tail + 1) % TCP_TXQ;
    }
}

/* onay ilerledikce pencere buyume (slow-start -> congestion avoidance). */
static void cwnd_ack(Tcb& t) {
    uint32_t mss = t.mss ? t.mss : (uint32_t)TCP_MSS;
    if (t.cwnd < t.ssthresh) t.cwnd += mss;
    else t.cwnd += (mss * mss) / (t.cwnd ? t.cwnd : mss);
}

/* peer'in SACK bloklarini yorumla: kapsanan onaysiz slotlari 'sacked' isaretle,
   boylece retrans yalnizca gercekten ulasmamis segmenti hedefler (RFC 2018). */
static void sack_apply(Tcb& t, const uint8_t* tt, uint16_t offhdr) {
    uint32_t o = 20;
    while (o + 2 <= offhdr) {
        uint8_t kind = tt[o];
        if (kind == 0) break;
        if (kind == 1) { o++; continue; }
        uint8_t olen = tt[o + 1];
        if (olen < 2 || (uint32_t)(o + olen) > offhdr) break;
        if (kind == 5 && olen >= 10) {
            int blk = (olen - 2) / 8;
            for (int i = 0; i < blk; i++) {
                uint32_t l = rd32(tt + o + 2 + 8 * i);
                uint32_t r = rd32(tt + o + 6 + 8 * i);
                if (l >= r) continue;
                for (int j = 0; j < TCP_TXQ; j++) {
                    TxSlot& sl = t.txb[j];
                    if (!sl.pend) continue;
                    uint32_t e = sl.seq + sl.len;
                    if (l < e && r > sl.seq) sl.sacked = true;
                }
            }
            return;
        }
        o += olen;
    }
}

/* hizli yeniden gonderim + hizli kurtarma girisi (RFC 5681):
   3. tekrar-ACK'te kayip segmente geri donulur; ssthresh = FlightSize/2,
   cwnd = ssthresh + 3*MSS (pipeline'i sifirlamadan devam). Ekstra dup-ACK'ler
   cwnd + MSS ile siser, yeni kumulatif ACK cwnd'yi ssthresh'e indirir. */
static void fast_recovery(Tcb& t) {
    int pi = ts_pick(t);
    if (pi < 0) return;                       /* onaysiz segment yok: kurtarma gerekmez */
    TxSlot& sl = t.txb[pi];
    tcp_emit(t, sl.seq, TCP_FLAG_ACK | TCP_FLAG_PSH, sl.data, sl.len, false, false);
    sl.sent_at = timer_get_ticks();
    uint32_t mss = t.mss ? t.mss : (uint32_t)TCP_MSS;
    uint32_t flight = (uint32_t)(t.snd_nxt - t.snd_una);        /* FlightSize */
    uint32_t h = flight / 2;
    t.ssthresh = h > 2u * mss ? h : 2u * mss;
    t.cwnd = t.ssthresh + 3u * mss;
    t.recover = t.snd_nxt;
    t.fr = true;
    t.retries = 0;
}

/* Nagle (RFC 896) birikimini gonderme: akim bosken (veya dolan tam segmente,
   sinirsiz kucuk segment yerine) bekleyen baytlari tek segmente bosaltir. */
static void nagle_flush(Tcb& t) {
    if (!t.nagle_len || !t.snd_wnd) return;
    uint16_t len = t.nagle_len;
    bool fullseg = len >= t.mss;
    if (!fullseg && t.snd_una != t.snd_nxt) return;   /* bekleyen veri varken kucuk segment ertele */
    TxSlot& sl = t.txb[t.tx_head];
    if (t.tx_head == t.tx_tail && sl.pend) return;    /* halka dolu: bir sonraki ACK beklenir */
    sl.seq = t.snd_nxt;
    sl.len = len;
    sl.sacked = false;
    memcpy(sl.data, t.nagle_buf, len);
    sl.sent_at = timer_get_ticks();
    sl.pend = true;
    t.snd_nxt += len;
    t.tx_head = (uint8_t)((t.tx_head + 1) % TCP_TXQ);
    t.nagle_len = 0;
    tcp_emit(t, sl.seq, TCP_FLAG_ACK | TCP_FLAG_PSH, sl.data, len, false, false);
}

static uint32_t rxr_push(Tcb& t, const uint8_t* p, uint32_t n) {
    uint32_t w = t.rxr_w;
    uint32_t room = TCP_RX_RING - t.rxr_fill;
    if (n > room) n = room;                 /* sadece sigan alinir; fazla dusulur */
    for (uint32_t i = 0; i < n; i++) {
        t.rxr[w] = p[i];
        w = (w + 1) % TCP_RX_RING;
    }
    t.rxr_w = w;
    t.rxr_fill += n;
    t.rlen += n;
    return n;                               /* saklanan bayt sayisi */
}

static bool ooo_store(Tcb& t, uint32_t seq, const uint8_t* d, uint16_t len) {
    for (int i = 0; i < TCP_OOO_MAX; i++) {
        if (t.ooo[i].used && t.ooo[i].seq == seq && t.ooo[i].len == len) return true; /* kopya */
    }
    /* ust uste bineni/genis olani sec ve at */
    for (int i = 0; i < TCP_OOO_MAX; i++) {
        if (!t.ooo[i].used) {
            t.ooo[i].used = true; t.ooo[i].seq = seq; t.ooo[i].len = len;
            memcpy(t.ooo[i].data, d, len);
            return true;
        }
    }
    return false;                    /* dolu: dusur, peer yeniden gonderir */
}

static void ooo_drain(Tcb& t) {
    for (;;) {
        int pick = -1;
        for (int i = 0; i < TCP_OOO_MAX; i++)
            if (t.ooo[i].used && t.ooo[i].seq == t.rcv_nxt) { pick = i; break; }
        if (pick < 0) break;
        OooSlice& s = t.ooo[pick];
        uint32_t n = rxr_push(t, s.data, (uint32_t)s.len);
        t.rcv_nxt += n;                      /* sadece saklanan ilerler */
        if (n < (uint32_t)s.len) {           /* halka dolu: kalan parcayi basa al */
            if (n) { uint32_t rem = (uint32_t)s.len - n; memmove(s.data, s.data + n, rem); s.len = (uint16_t)rem; s.seq = t.rcv_nxt; }
            t.win_update = true;
            break;
        }
        s.used = false;
        if (n == 0) break;
    }
    ack_delayed(t);
}

void handle_tcp(const uint8_t* ip, uint16_t iplen, const uint8_t* eth_src) {
    uint32_t ihl = (uint32_t)(ip[0] & 0x0F) * 4u;
    if (iplen < ihl + 20) return;
    const uint8_t* tt = ip + ihl;

    uint32_t src_ip = rd32(ip + 12);
    uint16_t src_port = rd16(tt);
    uint16_t dst_port = rd16(tt + 2);

    uint16_t tlen = (uint16_t)(iplen - ihl);
    if (tcp_checksum(src_ip, rd32(ip + 16), tt, tlen) != 0) return;  /* alici degismezci: gecerli TCP'de 0 */

    /* paketin bagli oldugu soketi bul: once aktif (ESTAB/kapanis/el sikismasi) 4'lu eslesme,
       bulunamazsa LISTEN port eslesmesi. */
    int s = -1;
    for (int i = 0; i < TCP_SOCKS; i++)
        if (conns[i].used && conns[i].st != 8 &&
            conns[i].sport == dst_port && conns[i].ip == src_ip && conns[i].dport == src_port) {
            s = i; break;
        }
    if (s < 0)
        for (int i = 0; i < TCP_SOCKS; i++)
            if (conns[i].used && conns[i].st == 8 && conns[i].sport == dst_port) {
                s = i; break;
            }
    if (s < 0) return;
    if (eth_src) arp_learn(src_ip, eth_src);        /* gondereni komsu olarak ogren */
    Tcb& t = conns[s];
    t.last_rx = timer_get_ticks();              /* peer'dan sey: canlilik kaniti (keepalive) */

    uint32_t seq  = rd32(tt + 4);
    uint32_t ack  = rd32(tt + 8);
    uint8_t  off  = (uint8_t)((tt[12] & 0xF0) >> 2);
    if (off < 20 || (uint32_t)off > iplen - ihl) return;
    uint16_t flags = (uint16_t)(tt[13] & 0x3F);
    uint16_t dlen = (uint16_t)(iplen - ihl - off);
    const uint8_t* d = tt + off;

    if (flags & TCP_FLAG_RST) {
        if (t.st != 8 && t.st != 9) { t.err = true; t.done = true; t.used = 0; t.ok = false; t.st = 0; t.st_v = 0; }
        return;
    }

    if (t.st == 1) {                             /* SYNSENT */
        if ((flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK) &&
            ack == t.snd_nxt) {
            t.rcv_nxt = seq + 1;
            t.snd_una = ack;
            t.mss = TCP_MSS;
            tcp_opts_parse(t, tt, off);          /* peer MSS/WS/TS secenekleri */
            if (t.mss == 0 || t.mss > TCP_MSS) t.mss = TCP_MSS;
            t.snd_wnd = (uint32_t)rd16(tt + 14) << t.ws_peer;   /* olcekli pencere */
            t.st = 2; t.st_v = 2;
            t.done = true; t.ok = true;
        }
        return;
    }

    if (t.st == 8) {                             /* LISTEN: gelen SYN -> kiz soket */
        if ((flags & TCP_FLAG_SYN) && !(flags & TCP_FLAG_ACK)) {
            int pend = 0;                        /* onaysiz (SYN_RECV) cocuk sayisi = accept yigin boyutu */
            for (int i = 0; i < TCP_SOCKS; i++)
                if (conns[i].used && conns[i].lfd == s && conns[i].st == 9) pend++;
            if (pend >= TCP_BACKLOG) return;     /* yigin dolu: SYN'i yanitsiz birak (peer yineler) */
            int c = -1;
            for (int i = 0; i < TCP_SOCKS; i++) if (!conns[i].used) { c = i; break; }
            if (c < 0) {                             /* slot yok: en eski TIME_WAIT'i feda et */
                uint64_t best = ~0ull;
                for (int i = 0; i < TCP_SOCKS; i++)
                    if (conns[i].used && conns[i].st == 7 && conns[i].tw_at < best) { best = conns[i].tw_at; c = i; }
            }
            if (c >= 0) {
                Tcb& ch = conns[c];
                ch.used = 1; ch.lfd = s;
                ch.ip = src_ip;
                ch.sport = dst_port;
                ch.dport = src_port;
                ch.iss = (uint32_t)((timer_get_ticks() << 12) ^ (uint32_t)(uintptr_t)tt ^ 0x4D2BC3A1u);
                ch.created_at = timer_get_ticks();
                ch.snd_una = ch.snd_nxt = ch.iss + 1;
                ch.rcv_nxt = seq + 1;
                ch.snd_wnd = 65535;          /* peer penceresi ESTAB olurken okunur */
                ch.mss = TCP_MSS;
                ch.rto = TCP_RTO0; ch.srtt = 0; ch.rttvar = 0; ch.dupacks = 0;
                ch.fr = false; ch.recover = 0; ch.lt = 0;
                ch.ws_peer = 0; ch.ts_ok = false; ch.ts_recent = 0; ch.ts_echo = 0;
                ch.cwnd = TCP_CWND_INIT; ch.ssthresh = TCP_SSTHRESH_INIT;
                ch.tx_head = ch.tx_tail = 0;
                ch.nagle_len = 0;
                ch.last_rx = timer_get_ticks(); ch.ka_at = 0; ch.ka_probes = 0;
                ch.ok = false; ch.done = false; ch.err = false;
                ch.fin_tx = ch.fin_rx = false;
                ch.fin_pend = false; ch.fin_sent_at = 0; ch.probe_at = 0; ch.retries = 0;
                ch.close_at = 0;
                ch.win_update = false;
                ch.ack_want = false; ch.ack_inv = 0; ch.ack_at = 0; ch.last_ack = 0;
                ch.rxr_w = ch.rxr_fill = 0; ch.rlen = 0;
                tcp_opts_parse(ch, tt, off);           /* peer'in WS/TS istegi (SYN) */
                if (ch.mss == 0 || ch.mss > TCP_MSS) ch.mss = TCP_MSS;
                ch.st = 9; ch.st_v = 9;
                tcp_emit(ch, ch.iss, TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0, true, false);
            }
        }
        return;
    }

    if (t.st == 9) {                             /* SYN_RECV: ACK beklenir */
        if ((flags & TCP_FLAG_ACK) && seq == t.rcv_nxt - 1 + 1) {
            t.snd_una = ack;
            t.snd_wnd = (uint32_t)rd16(tt + 14) << t.ws_peer;   /* olcekli pencere */
            t.st = 2; t.st_v = 2;
            t.done = true; t.ok = true;
        }
        return;
    }

    /* ESTABLISHED ve kapanis durumlari */
    if (flags & TCP_FLAG_ACK) {
        t.snd_wnd = (uint32_t)rd16(tt + 14) << t.ws_peer;   /* olcekli pencere */
        tcp_opts_parse(t, tt, off);          /* TS (RTT ornegi) / WS / MSS gecmisi */
        sack_apply(t, tt, off);                  /* peer SACK bloklari -> slot isaretleri */
        if (ack > t.snd_una && ack <= t.snd_nxt) {
            t.ka_probes = 0;
            if (t.ts_ok && t.ts_echo && timer_get_ticks() >= t.ts_echo)
                rtt_apply_ms(t, (uint32_t)((timer_get_ticks() - t.ts_echo) * 10u)); /* TSecr */
            else
                rtt_update(t);                       /* veya en eski slotun sent_at'i */
            ack_slots(t, ack);                   /* kumulatif onayli slotlari bosalt */
            t.snd_una = ack;
            t.dupacks = 0;
            t.retries = 0;
            t.lt = 0;
            if (t.fr) {                          /* hizli kurtarmada: pencereyi indir, bitir */
                t.cwnd = t.ssthresh;
                if (ack >= t.recover) t.fr = false;
            } else {
                cwnd_ack(t);                     /* slow-start / congestion avoidance */
            }
            if (t.st == 3 && t.fin_tx && ack >= (uint32_t)(t.fin_seq + 1)) {
                t.st = 4; t.close_at = timer_get_ticks() + 200; t.fin_pend = false;   /* FINW1 -> FINW2 */
            }
            else if (t.st == 6 && t.fin_tx && ack >= (uint32_t)(t.fin_seq + 1)) {
                t.fin_pend = false; t.used = 0; t.st = 0; t.st_v = 0;                /* LAST_ACK -> KAPALI */
            }
            nagle_flush(t);                      /* akim bosaldi: Nagle birikimini gonder */
        } else if (ack == t.snd_una) {
            if (t.ka_probes) t.ka_probes = 0;    /* keepalive yoklama yaniti */
            else if (++t.dupacks == 3) fast_recovery(t);            /* 3. dup-ACK: retrans + kurtarma */
            else if (t.dupacks > 3 && t.fr) t.cwnd += (t.mss ? t.mss : (uint32_t)TCP_MSS); /* ekstra ACK: sises */
            else t.lt = 2;                       /* ilk iki dup-ACK: sinirli gonderim hakki (RFC 3042) */
        }
    }

    bool fin_now = (flags & TCP_FLAG_FIN) != 0;
    if (dlen) {
        uint32_t end = seq + dlen;
        if (end <= t.rcv_nxt) {                  /* tamamen eski/kopya */
            ack_delayed(t);
        } else if (seq >= t.rcv_nxt) {           /* gelecek (gap): ooo'ya */
            if (seq > t.rcv_nxt) { ooo_store(t, seq, d, dlen); ack_delayed(t); }
            else {
                uint32_t stored = rxr_push(t, d, dlen);
                t.rcv_nxt = seq + stored;
                if (stored < dlen) t.win_update = true;   /* halka dolu: kalan dusuldu */
                if (stored) ooo_drain(t);
            }
        } else {                                 /* kismi eski: islenmeyen kismi al */
            uint32_t skip = t.rcv_nxt - seq;
            const uint8_t* dd = d + skip;
            uint32_t take = end - t.rcv_nxt;
            uint32_t stored = rxr_push(t, dd, take);
            t.rcv_nxt = seq + skip + stored;
            if (stored < take) t.win_update = true;
            if (stored) ooo_drain(t);
        }
    } else if (fin_now && seq <= t.rcv_nxt) {
        tcp_ack_now(t);
    }

    if (fin_now) {
        /* FIN, seq+dlen degerinde bir seq tuketir. Kabul: (seq+dlen) <= rcv_nxt */
        if ((uint32_t)(seq + dlen) <= t.rcv_nxt) {
            t.rcv_nxt += 1;
            t.fin_rx = true;
            tcp_ack_now(t);
            if (t.st == 2)      t.st = 5;         /* ESTAB -> CLOSE_WAIT */
            else if (t.st == 4) { t.st = 7; t.tw_at = timer_get_ticks() + 300; } /* FINW2 -> TIMEW */
            else if (t.st == 3) t.st = 4;         /* FINW1 -> FINW2 (eszamanli) */
            t.done = true;
        }
    } else if (dlen) {
        ack_delayed(t);
    }
}

/* ---- IPv4 parcalama / birlestirme (RFC 791) ---- */
struct IpFrag {
    bool     used;
    uint32_t src;
    uint16_t id;
    uint8_t  proto;
    uint16_t got;
    uint16_t tot;
};
IpFrag ipfrags[2];
uint8_t ipf_buf[2][65556];
uint64_t ipf_expire = 0;

static void ipf_clear(int i) {
    ipfrags[i].used = false; ipfrags[i].got = 0; ipfrags[i].tot = 0;
}

static void ip_dispatch(const uint8_t* ip, uint16_t iplen, const uint8_t* eth_src) {
    if (ip[9] == 1) handle_icmp(ip, iplen, eth_src);
    else if (ip[9] == 17) handle_udp(ip, iplen, eth_src);
    else if (ip[9] == 6) handle_tcp(ip, iplen, eth_src);
}

/* IP secenek listesini yapi olarak yurur; bozuk listeyi ve LSRR/SSRR
   (kaynak rotasi) tasiyan paketleri reddeder. EOL/NOP sonrası biten
   secenekleri kabul eder, diger secenekleri (RR/TS/...) yok sayar. */
static bool ip_opts_ok(const uint8_t* ip, int ihl) {
    int o = 20;
    while (o < ihl) {
        uint8_t t = ip[o];
        if (t == 0) return true;                     /* EOOL */
        if (t == 1) { o++; continue; }               /* NOP */
        if (o + 1 >= ihl || ip[o + 1] < 2 || o + ip[o + 1] > ihl) return false;
        if (t == 0x83 || t == 0x89) return false;    /* LSRR / SSRR */
        o += ip[o + 1];
    }
    return true;
}

void handle_ipv4(const uint8_t* ip, uint16_t iplen, const uint8_t* eth_src) {
    /* ---- L3 dogrulama (RX hardening) ----
       Sadece IPv4; IHL ve toplam uzunluk tutarli; IP basligi checksum'u sag; 
       TTL=0 yol boyu tukenmis sayilir; malformed veya kaynak-rotali (LSRR/SSRR)
       secenekler sessizce dusurulur. Hatali paketler ust uygulamaya ulasmaz. */
    if (iplen < 20) return;
    if ((ip[0] >> 4) != 4) return;
    uint16_t ihl = (uint16_t)((ip[0] & 0x0F) * 4u);
    if (ihl < 20 || iplen < ihl) return;
    if (ip[8] == 0) return;
    if (ip_checksum(ip, ihl) != 0) return;
    if (ihl > 20 && !ip_opts_ok(ip, ihl)) return;

    uint16_t frag = rd16(ip + 6);
    bool mf = (frag & 0x2000) != 0;
    uint32_t off = (uint32_t)(frag & 0x1FFF) * 8u;
    if (!mf && !off) { ip_dispatch(ip, iplen, eth_src); return; }

    uint64_t now = timer_get_ticks();
    if (now >= ipf_expire) { ipf_expire = now + 200; for (int i = 0; i < 2; i++) ipf_clear(i); }

    uint16_t pl = (uint16_t)(iplen - ihl);
    if ((uint32_t)off + pl > 65535u - 20u) return;

    uint32_t src = rd32(ip + 12);
    uint16_t id = rd16(ip + 4);
    int s = -1;
    for (int i = 0; i < 2; i++)
        if (ipfrags[i].used && ipfrags[i].src == src && ipfrags[i].id == id && ipfrags[i].proto == ip[9]) { s = i; break; }
    if (s < 0)
        for (int i = 0; i < 2; i++)
            if (!ipfrags[i].used) { s = i; break; }
    if (s < 0) return;

    IpFrag& F = ipfrags[s];
    uint8_t* pb = ipf_buf[s] + 20;
    if (off == 0) {
        F.used = true; F.src = src; F.id = id; F.proto = ip[9]; F.got = 0; F.tot = 0;
        memcpy(ipf_buf[s], ip, 20);
        ipf_buf[s][0] = 0x45;                  /* IHL=20: secenekler parcaciklarda tasinmayabilir */
    }
    memcpy(pb + off, ip + ihl, pl);
    uint32_t end = off + (uint32_t)pl;
    if (end > F.got) F.got = (uint16_t)end;
    if (!mf) F.tot = (uint16_t)end;
    ipf_expire = now + 200;

    if (F.tot && F.got >= F.tot) {
        wr16(ipf_buf[s] + 2, (uint16_t)(20 + F.tot));
        wr16(ipf_buf[s] + 6, 0);
        wr16(ipf_buf[s] + 10, 0);                          /* alan once bosalt */
        wr16(ipf_buf[s] + 10, ip_checksum(ipf_buf[s], 20));  /* toplam uzunluk degisti */
        ip_dispatch(ipf_buf[s], (uint16_t)(20 + F.tot), eth_src);
        ipf_clear(s);
    }
}

/*
 * Yapay parcali ICMP istek ile birlestirmeyi dogrular.
 * iki parca birlestimce echo yanitini tetiklemeli (stat_tx +1).
 */
extern "C" bool net_frag_selftest(void) {
    if (!net_active()) return false;
    uint8_t f0[20 + 80], f1[20 + 40];
    memset(f0, 0, sizeof(f0));
    memset(f1, 0, sizeof(f1));

    uint8_t pay[120];
    memset(pay, 0, sizeof(pay));
    pay[0] = 8;                              /* echo istek */
    pay[1] = 0;
    wr16(pay + 4, 0x1234);                   /* identifier */
    wr16(pay + 6, 1);                        /* sequence */
    wr16(pay + 2, ip_checksum(pay, sizeof(pay)));

    uint32_t gw = net_get_gw();

    auto mk = [&](uint8_t* ip, uint16_t frag, uint16_t plen) {
        ip[0] = 0x45; ip[1] = 0;
        wr16(ip + 2, (uint16_t)(20 + plen));
        wr16(ip + 4, 0x4567);
        wr16(ip + 6, frag);
        ip[8] = 64; ip[9] = 1;
        wr32(ip + 12, gw);
        wr32(ip + 16, our_ip);
        wr16(ip + 10, ip_checksum(ip, 20));
    };

    mk(f0, 0x2000, 80);                  /* MF=1, offset 0 */
    mk(f1, 10,     40);                  /* MF=0, offset 80/8=10 */
    memcpy(f0 + 20, pay, 80);
    memcpy(f1 + 20, pay + 80, 40);

    uint64_t t0 = stat_tx;
    handle_ipv4(f0, sizeof(f0), NULL);
    handle_ipv4(f1, sizeof(f1), NULL);
    return stat_tx == t0 + 1;
}

/*
 * RX hardening testi: gecerli ICMP echo yanitlanmali; bozuk IP checksum,
 * bozuk ICMP checksum ve LSRR (kaynak rotasi) secenekli paketler sessizce
 * dusurulmeli (stat_tx artirmadan).
 */
extern "C" bool net_rx_harden_selftest(void) {
    if (!net_active()) return false;
    uint32_t gw = net_get_gw();
    uint8_t p[60];

    auto feed = [&](uint8_t* q, int iplen) { handle_ipv4(q, (uint16_t)iplen, NULL); };
    auto mk_ack = [&](bool good_ip, bool icmp_ok, uint8_t otype, bool valid_opt) {
        memset(p, 0, sizeof(p));
        uint16_t ihl = 20;
        if (otype) {
            ihl = 28;
            p[0] = 0x47;                          /* IHL=7 => secenek bolgesi */
            p[20] = otype;
            if (valid_opt && otype >= 2) { p[21] = 7; p[22] = 4; }
            else p[21] = 0;                       /* bozuk uzunluk */
        } else {
            p[0] = 0x45;
        }
        p[8] = 64; p[9] = 1;
        wr16(p + 2, ihl + 8);
        wr32(p + 12, gw);
        wr32(p + 16, our_ip);
        p[ihl] = 8;                               /* echo istek */
        p[ihl + 1] = 0;
        p[ihl + 2] = p[ihl + 3] = 0;
        wr16(p + ihl + 4, 0x1234);
        wr16(p + ihl + 6, 1);
        wr16(p + ihl + 2, ip_checksum(p + ihl, 8));
        if (!icmp_ok) p[ihl + 2] ^= 0xFF;
        wr16(p + 10, 0);
        wr16(p + 10, ip_checksum(p, (int)ihl));
        if (!good_ip) p[10] ^= 0xFF;
    };

    uint64_t t0 = stat_tx;
    mk_ack(true, true, 0, true);        /* gecerli echo -> yanitla */
    feed(p, 28);
    if (stat_tx != t0 + 1) return false;

    mk_ack(false, true, 0, true);       /* bozuk IP checksum -> dusur */
    feed(p, 28);
    if (stat_tx != t0 + 1) return false;

    mk_ack(true, false, 0, true);       /* bozuk ICMP checksum -> dusur */
    feed(p, 28);
    if (stat_tx != t0 + 1) return false;

    mk_ack(true, true, 0x83, true);     /* LSRR secenegi -> dusur */
    feed(p, 36);
    if (stat_tx != t0 + 1) return false;

    mk_ack(true, true, 0x07, true);     /* RR secenegi (zararsiz) -> yanitla */
    feed(p, 36);
    return stat_tx == t0 + 2;           /* yalniz RR'li paket ikinci yaniti uretir */
}

/* Hizli kurtarma + sinirli gonderim testi: sahte bir ESTAB baglanti kurulur
   (LISTEN->SYN-RECV->ESTAB), bir segment gonderilir; 1-2. tekrar-ACK yayin
   uretmemeli (sinirli gonderim hakki verir), 3. tekrar-ACK kayip segmentin
   yeniden gonderimini tetiklemeli, 4. tekrar-ACK sadece cwnd sisirmeli ve
   ileri ACK kurtarmayi bitirmeli (FTS: hicbir ek yayin yok). Duzgulen fd'ler
   sonunda kapatilir. */
extern "C" bool net_fast_recovery_selftest(void) {
    if (!net_active()) return false;

    uint32_t peer = 0x0A000263u;                 /* 10.0.2.99 (sanal komsu) */
    uint8_t  pmac[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
    arp_learn(peer, pmac);

    ethsnoop = true; ethsnoop_n = 0; eth_mute = true;   /* tx'leri NIC'e gonderme: slirp RST izolasyonu */

    int lfd = net_socket();
    if (lfd < 0) return false;
    uint16_t lport = (uint16_t)(0x8000 + (timer_get_ticks() % 0x4000));
    if (!net_tcp_listen(lfd, lport)) { net_tcp_close(lfd); return false; }

    uint16_t psport = 0x4B21;
    uint32_t pseq = 0x11112222u;

    auto mk = [&](uint8_t* b, uint32_t seq, uint32_t ack, uint16_t flags) {
        memset(b, 0, 40);
        b[0] = 0x45;
        wr16(b + 2, 40);
        b[8] = 64; b[9] = 6;
        wr32(b + 12, peer);
        wr32(b + 16, our_ip);
        wr16(b + 10, 0);
        wr16(b + 10, ip_checksum(b, 20));
        uint8_t* tt = b + 20;
        wr16(tt, psport);
        wr16(tt + 2, lport);
        wr32(tt + 4, seq);
        wr32(tt + 8, ack);
        tt[12] = 0x50;
        tt[13] = (uint8_t)flags;
        wr16(tt + 14, 65535);
        wr16(tt + 16, 0);
        wr16(tt + 16, tcp_checksum(peer, our_ip, tt, 20));
    };

    uint8_t p[40];
    int c = -1;
    auto fail = [&](void) { eth_mute = false; ethsnoop = false;
                            conns[c].used = 0; conns[c].st = 0;
                            conns[lfd].used = 0; conns[lfd].st = 0; return false; };
    auto dbg = [&](const char* m) {
        kslog("FRST dbg: %s stat_tx=%u fr=%d cwnd=%u ssthresh=%u dup=%u una=%u nxt=%u\n",
              m, (uint32_t)stat_tx, conns[c].fr, conns[c].cwnd, conns[c].ssthresh,
              (uint32_t)conns[c].dupacks, conns[c].snd_una, conns[c].snd_nxt);
    };

    /* el sikismasi: SYN -> cocuk st=9, SYN+ACK gonderilir */
    mk(p, pseq, 0, TCP_FLAG_SYN);
    handle_tcp(p, 40, NULL);
    for (int i = 0; i < TCP_SOCKS; i++)
        if (conns[i].used && conns[i].lfd == lfd && conns[i].st == 9) { c = i; break; }
    if (c < 0) { eth_mute = false; ethsnoop = false;
                 conns[lfd].used = 0; conns[lfd].st = 0; return false; }

    /* ACK -> ESTAB */
    mk(p, pseq + 1, conns[c].snd_una, TCP_FLAG_ACK);
    handle_tcp(p, 40, NULL);
    if (conns[c].st != 2 || !conns[c].ok) return fail();

    /* bir segment gonder */
    uint8_t data[64];
    for (int i = 0; i < 64; i++) data[i] = (uint8_t)i;
    uint64_t t0 = stat_tx;
    if (!net_tcp_send(c, data, 64) || stat_tx != t0 + 1) { dbg("send"); return fail(); }

    uint32_t ua = conns[c].snd_una;

    /* 1. ve 2. tekrar-ACK: yayin yok (sinirli gonderim hakki) */
    mk(p, pseq + 1, ua, TCP_FLAG_ACK);
    handle_tcp(p, 40, NULL);
    handle_tcp(p, 40, NULL);
    if (stat_tx != t0 + 1) { dbg("dup12"); return fail(); }

    /* 3. tekrar-ACK: hizli yeniden gonderim -> 1 ek yayin */
    handle_tcp(p, 40, NULL);
    if (stat_tx != t0 + 2) { dbg("dup3"); return fail(); }
    if (!conns[c].fr) { dbg("dup3 nfr"); return fail(); }

    /* 4. tekrar-ACK: cwnd siser, yayin yok */
    handle_tcp(p, 40, NULL);
    if (stat_tx != t0 + 2) { dbg("dup4"); return fail(); }

    /* ileri ACK: kurtarmayi bitir, yayin yok */
    mk(p, pseq + 1, conns[c].snd_nxt, TCP_FLAG_ACK);
    handle_tcp(p, 40, NULL);
    if (stat_tx != t0 + 2) { dbg("fwd"); return fail(); }
    if (conns[c].fr) { dbg("fwd nfr"); return fail(); }

    conns[c].used = 0; conns[c].st = 0;
    conns[lfd].used = 0; conns[lfd].st = 0;
    eth_mute = false; ethsnoop = false;
    return true;
}

/* ---- adim1f: window scaling + timestamps + Nagle + keepalive (RFC 1323/896/1122) ----
   Sanal komsu uzerinden: WS(7)/TS secenekli SYN anlasmasi, SYN-ACK secenekleri,
   olcekli pencere uygulanmasi, Nagle birikimi/erteleme/boşaltma, keepalive yoklama
   ve olum-kesimi. TX'ler eth_mute ile NIC'e gider, slirp RST'ynden izole. */
extern "C" bool net_tcp_ext_selftest(void) {
    if (!net_active()) return false;

    uint32_t peer = 0x0A000263u;                 /* 10.0.2.99 (sanal komsu) */
    uint8_t  pmac[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
    arp_learn(peer, pmac);
    ethsnoop = true; ethsnoop_n = 0; eth_mute = true;

    int lfd = net_socket();
    if (lfd < 0) return false;
    uint16_t lport = (uint16_t)(0x8000 + (timer_get_ticks() % 0x4000));
    if (!net_tcp_listen(lfd, lport)) { eth_mute = false; ethsnoop = false; net_tcp_close(lfd); return false; }

    uint16_t psport = 0x4B21;
    uint32_t pseq = 0x22223333u;
    int c = -1;

    auto cleanup = [&](void) { eth_mute = false; ethsnoop = false;
        conns[lfd].used = 0; conns[lfd].st = 0;
        if (c >= 0) { conns[c].used = 0; conns[c].st = 0; } };
    auto fail = [&](void) { cleanup(); return false; };
    auto ackpkt = [](uint8_t* b, uint32_t src, uint32_t dst, uint32_t seq, uint32_t ack, uint32_t peerip, uint32_t our, uint16_t wnd) {
        memset(b, 0, 40);
        b[0] = 0x45;
        wr16(b + 2, 40);
        b[8] = 64; b[9] = 6;
        wr32(b + 12, peerip);
        wr32(b + 16, our);
        wr16(b + 10, 0);
        wr16(b + 10, ip_checksum(b, 20));
        uint8_t* tt = b + 20;
        wr16(tt, src);
        wr16(tt + 2, dst);
        wr32(tt + 4, seq);
        wr32(tt + 8, ack);
        tt[12] = 0x50;
        tt[13] = 0x10;
        wr16(tt + 14, wnd);
        wr16(tt + 16, 0);
        wr16(tt + 16, tcp_checksum(peerip, our, tt, 20));
    };

    /* SYN (MSS 2048 + WS 7 + TS) -> cocuk st=9 */
    uint8_t p[60];
    memset(p, 0, 60);
    p[0] = 0x45; wr16(p + 2, 60); p[8] = 64; p[9] = 6;
    wr32(p + 12, peer); wr32(p + 16, our_ip);
    wr16(p + 10, 0);
    wr16(p + 10, ip_checksum(p, 20));
    uint8_t* tt = p + 20;
    wr16(tt, psport); wr16(tt + 2, lport);
    wr32(tt + 4, pseq);
    tt[12] = 0xA0;
    tt[13] = 0x02;
    wr16(tt + 14, 65535);
    tt[20] = 2; tt[21] = 4; tt[22] = (2048 >> 8); tt[23] = 2048 & 0xFF;
    tt[24] = 3; tt[25] = 3; tt[26] = 7;
    tt[27] = 8; tt[28] = 10;
    wr32(tt + 29, 0xCAFEBABEu); wr32(tt + 33, 0);
    wr16(tt + 16, 0);
    wr16(tt + 16, tcp_checksum(peer, our_ip, tt, 40));
    handle_tcp(p, 60, NULL);
    for (int i = 0; i < TCP_SOCKS; i++)
        if (conns[i].used && conns[i].lfd == lfd && conns[i].st == 9) { c = i; break; }
    if (c < 0) { return fail(); }

    /* WS/TS anlasilmasi + SYN-ACK secenekleri (MSS/WS/TS) */
    if (!conns[c].ts_ok || conns[c].ws_peer != 7) { return fail(); }
    if (ethsnoop_n < 1) { return fail(); }
    const uint8_t* sa = ethsnoop_frame[0] + 14 + 20;
    uint16_t shlen = (uint16_t)((sa[12] >> 4) * 4u);    bool has_mss = false, has_ws = false, has_ts = false;
    if (shlen >= 20 + 17) {
        uint16_t o = 20;
        while (o + 2 <= shlen) {
            uint8_t k = sa[o];
            if (k == 0) break;
            if (k == 1) { o++; continue; }
            uint8_t ol = sa[o + 1];
            if (ol < 2 || o + ol > shlen) break;
            if (k == 2) has_mss = true;
            else if (k == 3) has_ws = true;
            else if (k == 8) has_ts = true;
            o += ol;
        }
    }
    if (!has_mss || !has_ws || !has_ts) { return fail(); }

    /* el sikismasi ACK -> ESTAB */
    ackpkt(p, psport, lport, pseq + 1, conns[c].snd_una, peer, our_ip, 65535);
    handle_tcp(p, 40, NULL);
    if (conns[c].st != 2 || !conns[c].ok) { return fail(); }

    /* olcekli pencere: peer 1 birlik duyurur -> snd_wnd = 1 << 7 */
    ackpkt(p, psport, lport, pseq + 1, conns[c].snd_una, peer, our_ip, 1);
    handle_tcp(p, 40, NULL);
    if (conns[c].snd_wnd != (1u << 7)) { return fail(); }

    /* Nagle: flight=0 kucuk yazim hemen gider; akim varken kucuk yazim ertelenir */
    uint64_t t0 = stat_tx;
    uint8_t d1[100];  for (int i = 0; i < 100; i++) d1[i]  = 0x11;
    uint8_t d2[50];   for (int i = 0; i < 50;  i++) d2[i]  = 0x22;
    if (!net_tcp_send(c, d1, 100) || stat_tx != t0 + 1) { return fail(); }
    uint32_t na = conns[c].snd_nxt;
    if (!net_tcp_send(c, d2, 50) || stat_tx != t0 + 1 || conns[c].nagle_len != 50) { return fail(); }

    ackpkt(p, psport, lport, pseq + 1, na, peer, our_ip, 65535);
    handle_tcp(p, 40, NULL);
    if (stat_tx != t0 + 2 || conns[c].nagle_len != 0 || conns[c].snd_nxt != (uint32_t)(na + 50)) { return fail(); }

    /* onaysiz kalmadi: 50 baytlk flush edilen segmenti de onayla */
    ackpkt(p, psport, lport, pseq + 1, na + 50, peer, our_ip, 65535);
    handle_tcp(p, 40, NULL);
    if (conns[c].snd_una != conns[c].snd_nxt) { return fail(); }

    /* keepalive: eski last_rx -> yoklama; yanit yoksa baglanti kirilir */
    uint64_t k0 = stat_tx;
    conns[c].last_rx = timer_get_ticks() - TCP_KA_IDLE - 1;
    net_tcp_poll(c);
    if (!conns[c].used || conns[c].ka_probes != 1 || stat_tx != k0 + 1) { return fail(); }
    for (int i = 0; i < TCP_KA_CNT; i++) {
        conns[c].ka_at = timer_get_ticks() - TCP_KA_RATE;
        net_tcp_poll(c);
        if (!conns[c].used) break;
    }
    if (conns[c].used || !conns[c].err) { return fail(); }

    cleanup();
    return true;
}

/*
 * Gonderim parcalama testi: 1700 bayt UDP payloadi 1480+... seklinde
 * tek id ile parcalanmali; etik yakalayici switch etkisi olmadan
 * rtl8139'e gider. ethsnoop ile parcalari inceleriz.
 */
extern "C" bool net_frag_send_selftest(void) {
    if (!net_active()) return false;

    static uint8_t big[1700];
    for (int i = 0; i < 1700; i++) big[i] = (uint8_t)(i & 0xFF);

    /* ARP yok: dogrudan mac vererek ip_send'e tek parcali ver, parcalar boyle olusur */
    uint8_t dummy_mac[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
    uint32_t dst = net_get_gw();

    ethsnoop = true;                 /* onceki snop temizle */
    ethsnoop_n = 0;
    ip_send(dst, dummy_mac, 17, big, sizeof(big));
    ethsnoop = false;

    if (ethsnoop_n != 2) return false;          /* 1700 -> 1480 + 220 */

    /* her IKisi: ethertype IP, ip id ayni, MF/offset dogru, total <= MTU */
    const uint8_t* f0 = ethsnoop_frame[0] + 14;        /* ip + 14 = eth payload */
    const uint8_t* f1 = ethsnoop_frame[1] + 14;
    if (rd16(ethsnoop_frame[0] + 12) != 0x0800) return false;
    if (rd16(ethsnoop_frame[1] + 12) != 0x0800) return false;
    if (rd16(f0 + 4) != rd16(f1 + 4))          return false;   /* ayni id */
    if (rd16(f0 + 6) != 0x2000)                return false;   /* MF=1, off=0 */
    if (rd16(f1 + 6) != (1480 / 8))            return false;   /* MF=0, off=185 */
    if (ethsnoop_len[0] > 1514)                return false;
    if (ethsnoop_len[1] > 1514)                return false;
    return true;
}

/* --- soket katmani: fd = conns[] indeksi --- */
static void sock_reset(int s) {
    Tcb& t = conns[s];
    t.used = 1; t.st = 0; t.st_v = 0;
    t.poll_busy = false;
    t.lfd = -1;
    t.ok = t.done = t.err = false;
    t.fin_tx = t.fin_rx = false;
    t.snd_una = t.snd_nxt = 0;
    t.rcv_nxt = 0;
    t.fin_pend = false; t.fin_sent_at = 0; t.probe_at = 0; t.retries = 0;
    t.snd_wnd = TCP_MSS;
    t.mss = TCP_MSS;
    t.rto = TCP_RTO0; t.srtt = 0; t.rttvar = 0; t.dupacks = 0;
    t.fr = false; t.recover = 0; t.lt = 0;
    t.ws_peer = 0; t.ts_ok = false; t.ts_recent = 0; t.ts_echo = 0;
    t.nagle_len = 0;
    t.last_rx = timer_get_ticks(); t.ka_at = 0; t.ka_probes = 0;
    t.cwnd = TCP_CWND_INIT; t.ssthresh = TCP_SSTHRESH_INIT;
    t.tx_head = t.tx_tail = 0;
    t.win_update = false;
    t.created_at = 0;
    t.tw_at = t.close_at = 0;
    t.ack_want = false; t.ack_inv = 0; t.ack_at = 0; t.last_ack = 0;
    t.rxr_w = t.rxr_fill = 0; t.rlen = 0;
}

/* yeni (bos) soket: fd veya -1 */
extern "C" int net_socket(void) {
    if (!nic_up()) return -1;
    for (int i = 0; i < TCP_SOCKS; i++)
        if (!conns[i].used) { sock_reset(i); return i; }
    uint64_t best = ~0ull; int c = -1;              /* dolu: en eski TIME_WAIT'i feda et */
    for (int i = 0; i < TCP_SOCKS; i++)
        if (conns[i].used && conns[i].st == 7 && conns[i].tw_at < best) { best = conns[i].tw_at; c = i; }
    if (c >= 0) { sock_reset(c); return c; }
    return -1;
}

/* fd ile bekleyen/acik soket icin sinyal bekleme (hepsi iptal duyarli). */
static bool sock_ok(int s, uint32_t ticks) {
    if (s < 0 || s >= TCP_SOCKS || !conns[s].used) return false;
    Tcb& t = conns[s];
    uint64_t dd = timer_get_ticks() + ticks;
    while (timer_get_ticks() < dd && !t.done && !t.err && !sys_intr_pending()) { sys_intr_poll(); tcp_poll_guarded(t); cpu_hlt(); }
    return true;
}

/* actif baglanti kur: SYN + el sikismasi (engelleyici). */
extern "C" bool net_tcp_connect(int s, uint32_t ip, uint16_t port) {
    if (s < 0 || s >= TCP_SOCKS || !conns[s].used) return false;
    Tcb& t = conns[s];
    t.ip = ip;
    t.dport = port;
    t.sport = (uint16_t)(0xC000 | (((timer_get_ticks() * 2654435761u) >> 16) & 0x3FFF));
    t.iss = (uint32_t)((timer_get_ticks() << 12) ^ (timer_get_ticks() * 2654435761u) ^ 0x0D1D2E3Fu);
    t.snd_nxt = t.snd_una = t.iss + 1;
    t.st = 1; t.st_v = 1;

    for (int r = 0; r < 5 && !t.done; r++) {
        tcp_emit(t, t.iss, TCP_FLAG_SYN, NULL, 0, true, false);
        uint64_t dd = timer_get_ticks() + 50;      /* 500ms */
        while (!t.done && timer_get_ticks() < dd && !sys_intr_pending()) { sys_intr_poll(); tcp_poll_guarded(t); cpu_hlt(); }
        if (!t.done) continue;
    }
    if (!t.ok) { t.used = 0; t.st = 0; t.st_v = 0; return false; }
    t.done = false; t.err = false;         /* okuma fazi icin bekleme sinyallerini temizle */
    return true;
}

extern "C" bool net_tcp_send(int s, const uint8_t* data, uint16_t len) {
    if (s < 0 || s >= TCP_SOCKS) return false;
    Tcb& t = conns[s];
    if (!t.used || (t.st != 2 && t.st != 3 && t.st != 5)) return false;
    if (len > TCP_MSS) len = TCP_MSS;
    if (len > t.mss) len = t.mss;
    if (!len) return false;

    uint32_t inflight = (uint32_t)(t.snd_nxt - t.snd_una);
    uint32_t pos = 0;
    while (pos < len) {
        /* Nagle (RFC 896): akimda veri varken kucuk yazim ertele; onceki birikime ekle. */
        if (t.nagle_len) {
            uint16_t room = (uint16_t)(TCP_MSS - t.nagle_len);
            uint16_t add = (uint16_t)((uint32_t)(len - pos) > room ? room : len - pos);
            if (add) { memcpy(t.nagle_buf + t.nagle_len, data + pos, add); t.nagle_len = (uint16_t)(t.nagle_len + add); pos += add; }
            nagle_flush(t);                 /* akim bosaldiysa veya tampon dolduysa gonder */
            if (t.nagle_len) return true;   /* bekliyor: kabul edildi (data kaybedilmez) */
            continue;
        }
        uint16_t rem = (uint16_t)(len - pos);
        if (rem < t.mss && inflight) {      /* kucuk parca ve onaysiz veri var: tamponla */
            memcpy(t.nagle_buf, data + pos, rem);
            t.nagle_len = rem;
            return true;
        }

        /* sender penceresi: min(peer kabulu, cwnd) asilmaz; slot sistemi onaysizlari tutar.
           Pencere kapaliysa ACK gelene kadar beklenir (iptal duyarli).
           lt hakki (ilk iki tekrar-ACK, RFC 3042): cwnd sinirini asip yeni veriyi
           peer penceresi yetiyorsa gonderir. */
        uint64_t wdd = timer_get_ticks() + 2000;         /* ~20 sn tavan */
        while (true) {
            uint32_t i2 = (uint32_t)(t.snd_nxt - t.snd_una);
            uint32_t win = t.snd_wnd;
            uint32_t cw  = t.cwnd;
            if (cw < win) win = cw;
            bool full = (t.tx_head == t.tx_tail && t.txb[t.tx_head].pend);
            if (!full) {
                bool okwin = i2 + (uint32_t)rem <= win;
                bool oklt  = t.lt > 0 && i2 + (uint32_t)rem <= (uint32_t)t.snd_wnd;
                if (okwin || oklt) break;
            }
            if (t.err || t.done || sys_intr_pending() || timer_get_ticks() >= wdd) return false;
            net_tcp_wait(s, 1);
        }
        TxSlot& sl = t.txb[t.tx_head];
        sl.seq = t.snd_nxt;
        sl.len = rem;
        sl.sacked = false;
        memcpy(sl.data, data + pos, rem);
        sl.sent_at = timer_get_ticks();
        sl.pend = true;
        t.snd_nxt += rem;
        t.tx_head = (uint8_t)((t.tx_head + 1) % TCP_TXQ);
        tcp_emit(t, sl.seq, TCP_FLAG_ACK | TCP_FLAG_PSH, data + pos, rem, false, false);
        if (t.lt) t.lt--;                          /* sinirli gonderim hakki tuhketildi */
        pos += rem;
    }
    return true;
}

/* Son kurulus/veri bekleme: zaman asimi (ticks birimi 10ms) icinde done/err/veri. */
extern "C" void net_tcp_wait(int s, uint32_t ticks) {
    sock_ok(s, ticks);
}

extern "C" bool net_tcp_active(int s) {
    if (s < 0 || s >= TCP_SOCKS) return false;
    Tcb& t = conns[s];
    return t.used && (t.st == 2 || t.st == 5);
}

extern "C" bool net_tcp_done(int s) {
    if (s < 0 || s >= TCP_SOCKS) return false;
    return conns[s].done;
}

extern "C" bool net_tcp_err(int s) {
    if (s < 0 || s >= TCP_SOCKS) return false;
    return conns[s].err;
}

extern "C" void net_tcp_poll(int s) {
    if (s < 0 || s >= TCP_SOCKS) return;
    if (conns[s].used) tcp_poll_guarded(conns[s]);
}

/* tum soketleri zamanlayici tarafiyla calistir (accept/recv disi). */
extern "C" void net_tcp_poll_all(void) {
    for (int i = 0; i < TCP_SOCKS; i++)
        if (conns[i].used) tcp_poll_guarded(conns[i]);
}

extern "C" uint32_t net_tcp_pending(int s) {
    if (s < 0 || s >= TCP_SOCKS) return 0;
    return conns[s].rlen;
}

extern "C" bool net_tcp_listen(int s, uint16_t port) {
    if (s < 0 || s >= TCP_SOCKS || !conns[s].used) return false;
    if (!nic_up()) return false;
    Tcb& t = conns[s];
    t.st = 8; t.st_v = 8;
    t.dport = 0;                 /* peer henuz bilinmiyor */
    t.sport = port;
    t.ip = our_ip;
    t.ok = t.done = t.err = false;
    return true;
}

/* LISTEN soketinde bekleyen ilk ESTABLISHED cocugu dondurur (fd veya -1).
   ticks ms cinsinden zaman asimi; 0 = sonsuz. */
extern "C" int net_tcp_accept(int s, uint32_t ticks) {
    if (s < 0 || s >= TCP_SOCKS || !conns[s].used) return -1;
    uint64_t dead = ticks ? timer_get_ticks() + ticks : 0;
    for (;;) {
        int best = -1;
        uint64_t bt = ~0ull;
        for (int i = 0; i < TCP_SOCKS; i++) {
            if (i == s) continue;
            if (conns[i].used && conns[i].lfd == s && conns[i].st == 2) {
                if (conns[i].created_at < bt) { bt = conns[i].created_at; best = i; }
            }
        }
        if (best >= 0) {
            conns[best].done = false; conns[best].err = false;
            return best;                       /* kabul edilecek soket (ilk gelen) */
        }
        if (dead && timer_get_ticks() >= dead) return -1;
        if (sys_intr_pending()) return -1;
        net_tcp_poll_all();
        uint64_t dd = timer_get_ticks() + 20;   /* ~200ms dilim */
        while (timer_get_ticks() < dd && !sys_intr_pending()) { sys_intr_poll(); cpu_hlt(); }
    }
}

/* Veri gelene kadar (veya zaman asimi) bekle; gelen baytlari dondur. */
extern "C" uint32_t net_tcp_recv_some(int s, uint8_t* out, uint32_t cap, uint32_t ticks) {
    if (s < 0 || s >= TCP_SOCKS) return 0;
    Tcb& t = conns[s];
    uint64_t dd = timer_get_ticks() + ticks;
    while (timer_get_ticks() < dd && t.rlen == 0 && !t.err && !t.done && !sys_intr_pending()) { sys_intr_poll(); tcp_poll_guarded(t); cpu_hlt(); }
    return net_tcp_recv(s, out, cap);
}

/* rxr'deki ilk veriyi disari kopyala (uygulama). */
extern "C" uint32_t net_tcp_recv(int s, uint8_t* out, uint32_t cap) {
    if (s < 0 || s >= TCP_SOCKS) return 0;
    Tcb& t = conns[s];
    uint32_t n = 0;
    uint32_t r = (t.rxr_w + TCP_RX_RING - t.rxr_fill) % TCP_RX_RING;
    while (n < cap && t.rxr_fill) {
        out[n++] = t.rxr[r];
        r = (r + 1) % TCP_RX_RING;
        t.rxr_fill--;
        t.rlen--;
    }
    /* pencere daralmistiysa (win_update) ve ring yariya indiyse acildigini peer'e bildir.
       Normal akista her segment zaten ack_delayed ile onaylanir; ekstra ACK spam yok. */
    if (n && t.win_update && t.rxr_fill < (TCP_RX_RING / 2)) {
        t.win_update = false;
        tcp_ack_now(t);
    }
    return n;
}

/* Kapatiş (aktif FIN): gerekli el sikisini kisaca bekler. */
extern "C" void net_tcp_close(int s) {
    if (s < 0 || s >= TCP_SOCKS) return;
    Tcb& t = conns[s];
    if (!t.used) return;
    if (t.st == 2) {                                /* aktif kapanis */
        t.fin_tx = true;
        t.fin_seq = t.snd_nxt;
        t.snd_nxt += 1;
        t.st = 3;
        t.close_at = timer_get_ticks() + 200;       /* ~2sn peer FIN bekle */
        t.fin_pend = true; t.fin_sent_at = timer_get_ticks();
        tcp_emit(t, t.fin_seq, TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0, false, false);
        net_tcp_wait(s, 120);                       /* ~1.2s FINW1/FINW2/CLOSE beklenir */
    } else if (t.st == 5) {                         /* pasif taraf: LAST_ACK */
        t.fin_tx = true;
        t.fin_seq = t.snd_nxt;
        t.snd_nxt += 1;
        t.st = 6;
        t.fin_pend = true; t.fin_sent_at = timer_get_ticks();
        tcp_emit(t, t.fin_seq, TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0, false, false);
        net_tcp_wait(s, 60);
    }
    if (t.st == 7) { }
    /* TIME_WAIT: tcp_poll sayaci birakir; slot baski altindaysa SYN/net_socket feda eder */
    else if (t.st == 3 || t.st == 4) { }
    /* aktif kapanis bebegi: peer FIN'i close_at sinirina kadar beklenir */
    else if (t.ok || t.fin_rx || t.err) { t.used = 0; t.st = 0; t.st_v = 0; }
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
        uint16_t iplen = rd16(ip + 2);           /* IP toplam uzunlugu (FCS/padding yok) */
        uint16_t avail = (uint16_t)(len - 14);
        if (iplen > avail) iplen = avail;         /* kaynaga guvenme */
        handle_ipv4(ip, iplen, frame + 6);
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
    while (!ping_done && timer_get_ticks() < deadline && !sys_intr_pending()) { sys_intr_poll(); cpu_hlt(); }
    ping_active = false;

    if (!ping_done) return false;
    if (ping_reply_src != ip) return (ping_reply_src != 0);
    return true;
}

extern "C" bool net_dhcp(void) {
    dhcp_txid = (uint32_t)(timer_get_ticks() * 2654435761u) ^ 0xE17A11;
    uint64_t wall = timer_get_ticks() + 300;         /* ~3 sn toplam sure */
    bool got_offer = false;

    while (timer_get_ticks() < wall && !got_offer && !sys_intr_pending()) {
        dhcp_waiting = true;
        dhcp_phase = 1;
        dhcp_done = false;
        uint8_t b[272];
        uint8_t* e = dhcp_build(b, 1);               /* DISCOVER */
        udp_send(0xFFFFFFFFu, 67, 68, b, (uint16_t)(e - b));
        uint64_t t = timer_get_ticks() + 30;         /* 300ms OFFER bekle */
        while (!dhcp_done && timer_get_ticks() < t && !sys_intr_pending()) { sys_intr_poll(); cpu_hlt(); }
        got_offer = dhcp_done;
    }
    if (!got_offer) { dhcp_waiting = false; return false; }

    wall = timer_get_ticks() + 100;                  /* ~1 sn ACK bekle */
    while (timer_get_ticks() < wall && !dhcp_done && !sys_intr_pending()) {
        dhcp_phase = 3;
        dhcp_done = false;
        uint8_t b[272];
        uint8_t* e = dhcp_build(b, 3);               /* REQUEST */
        udp_send(0xFFFFFFFFu, 67, 68, b, (uint16_t)(e - b));
        uint64_t t = timer_get_ticks() + 30;
        while (!dhcp_done && timer_get_ticks() < t && !sys_intr_pending()) { sys_intr_poll(); cpu_hlt(); }
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
    if (!nic_up()) return false;
    if (!name || !*name) return false;
    uint32_t server = dns_server ? dns_server : 0x0A000203u;

    int s = net_udp_socket();
    if (s < 0) return false;
    if (!net_udp_bind(s, 0)) { net_udp_close(s); return false; }

    bool ok = false;
    uint32_t result = 0;
    for (int attempt = 0; attempt < 3 && !ok; attempt++) {
        uint16_t id = (uint16_t)((timer_get_ticks() + (uint64_t)attempt) * 0x9E37u) | 0x8000u;
        uint8_t q[280];
        int qlen = dns_query(q, id, name);
        if (qlen < 32) { memset(q + qlen, 0, 32 - qlen); qlen = 32; }
        net_udp_send_to(s, server, 53, q, (uint16_t)qlen);

        uint8_t r[512];
        uint64_t t = timer_get_ticks() + 100;        /* 1 sn bekleyis */
        while (!ok && timer_get_ticks() < t && !sys_intr_pending()) {
            sys_intr_poll();
            int got = net_udp_recv_from(s, r, sizeof(r), NULL, NULL);
            if (got > 0) {
                if (got >= 12 && rd16(r) == id)      /* gecikmis/yanlis id dusur */
                    ok = dns_parse_a(r, (uint16_t)got, &result);
            }
            cpu_hlt();
        }
    }
    net_udp_close(s);
    if (out_ip && ok) *out_ip = result;
    return ok;
}

extern "C" bool net_http_get(uint32_t ip, uint16_t port, const char* host,
                             const char* path, char* out, int out_cap) {
    if (!nic_up()) return false;
    if (!out || out_cap <= 0) return false;
    if (!host || !*host) host = "10.0.2.2";
    if (!path || !*path) path = "/";

    int s = net_socket();
    if (s < 0) return false;

    if (!net_tcp_connect(s, ip, port)) return false;

    uint8_t req[512];
    int rl = 0;
    const char* hpre = host;
    memcpy(req + rl, "GET ", 4); rl += 4;
    int pl = 0; while (path[pl]) pl++;
    if (pl > 200) pl = 200;
    memcpy(req + rl, path, (size_t)pl); rl += pl;
    memcpy(req + rl, " HTTP/1.0\r\nHost: ", 17); rl += 17;
    while (*hpre && rl < 500) req[rl++] = (uint8_t)*hpre++;
    if (port != 80) {
        req[rl++] = ':';
        char pb[8]; int pn = 0;
        uint32_t pv = port;
        do { pb[pn++] = (char)('0' + (pv % 10)); pv /= 10; } while (pv && pn < 7);
        while (pn) req[rl++] = (uint8_t)pb[--pn];
    }
    memcpy(req + rl, "\r\nUser-Agent: cofeuos-http/0.1\r\nConnection: close\r\n\r\n", 58); rl += 58;

    if (!net_tcp_send(s, req, (uint16_t)rl)) { net_tcp_close(s); return false; }

    int    total = 0;
    uint64_t wall = timer_get_ticks() + 4000;        /* ~40 sn (buyuk govdeler) */
    while (timer_get_ticks() < wall && !net_tcp_done(s) && !net_tcp_err(s) && !sys_intr_pending()) {
        sys_intr_poll();
        total += (int)net_tcp_recv(s, (uint8_t*)out + total, (uint32_t)(out_cap - 1 - total));
        net_tcp_poll(s);
        cpu_hlt();
    }
    total += (int)net_tcp_recv(s, (uint8_t*)out + total, (uint32_t)(out_cap - 1 - total));

    bool ok = !net_tcp_err(s) && total > 0;
    out[total < out_cap ? total : out_cap - 1] = 0;
    net_tcp_close(s);
    return ok;
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

extern "C" bool net_active(void) { return nic_up(); }

extern "C" void net_sockdump(void) {
    net_tcp_poll_all();                /* once suresi dolan TIME_WAIT'lari topla */
    static const char* stn[] = { "-", "SYNS", "ESTB", "FIN1", "FIN2",
                                 "CLSW", "LAK", "TIMW", "LIST", "SYNR" };
    for (int i = 0; i < TCP_SOCKS; i++) {
        Tcb& t = conns[i];
        if (!t.used) continue;
        kprintf(" sock %d st=%s port=%u peer=%u.%u.%u.%u:%u lfd=%d r=%u d=%d e=%d\n",
                i, stn[t.st > 9 ? 0 : t.st], t.sport,
                (t.ip >> 24) & 0xFF, (t.ip >> 16) & 0xFF,
                (t.ip >> 8) & 0xFF, t.ip & 0xFF, t.dport, t.lfd,
                t.rlen, t.done ? 1 : 0, t.err ? 1 : 0);
    }
}

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