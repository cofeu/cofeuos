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
        uint32_t l2dst = dst;
        if ((dst & our_mask) != (our_ip & our_mask))   /* dis ag: gateway uzerinden */
            l2dst = gateway;
        if (!arp_resolve(l2dst, tmpmac)) return;
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

void handle_udp(const uint8_t* ip, uint16_t len, const uint8_t* eth_src) {
    uint32_t ihl = (uint32_t)(ip[0] & 0x0F) * 4u;
    if (len < ihl + 8) return;
    const uint8_t* u = ip + ihl;
    uint16_t sport = rd16(u);
    uint16_t dport = rd16(u + 2);
    uint16_t ulen = rd16(u + 4);
    if (ulen < 8 || ulen > len - ihl) ulen = (uint16_t)(len - ihl);

    if (eth_src) arp_learn(rd32(ip + 12), eth_src);       /* gondereni komsu olarak ogren */

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
constexpr uint32_t TCP_RTO0  = 500;         /* ilk RTO (ms) */
constexpr uint32_t TCP_RTO_MIN = 200;
constexpr uint32_t TCP_RTO_MAX = 3000;
constexpr uint32_t TCP_CWND_INIT = 4 * (uint32_t)TCP_MSS;     /* slow-start baslangic penceresi */
constexpr uint32_t TCP_SSTHRESH_INIT = 64 * (uint32_t)TCP_MSS;
constexpr int      TCP_SACK_BLK_MAX  = 3;   /* ACK basina iletilen SACK blogu */

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
    uint8_t     st;          /* 0 KAPALI,1 SYNSENT,2 ESTAB,3 FINW1,4 FINW2,
                                5 CLOSEW,6 LASTACK,7 TIMEW,8 LISTEN,9 SYNRECV */
    int         lfd;         /* LISTEN ana soket (kabul edilen cocusu icin) */
    uint32_t    ip;          /* peer adres */
    uint16_t    sport, dport;
    uint32_t    iss;         /* bizim ilk seq */
    volatile uint32_t snd_una;   /* onaysiz en eski seq */
    volatile uint32_t snd_nxt;   /* sonraki gonderilecek seq */
    volatile uint32_t rcv_nxt;   /* peer'dan beklenen seq */
    volatile uint16_t snd_wnd;   /* peer'in penceresi */
    volatile uint8_t  st_v;      /* ISR'den gorunen durum (st ile esit) */
    uint16_t  mss;
    uint32_t  rto;           /* ms (Jacobson) */
    uint32_t  srtt, rttvar;  /* yumusatilmis RTT ve sapma (ms) */
    uint32_t  cwnd, ssthresh;/* kongesyon kontrolu (bayt) */
    uint32_t  dupacks;
    uint8_t   tx_head, tx_tail;  /* onaysiz segment halkasi */
    TxSlot    txb[TCP_TXQ];
    bool fin_tx, fin_rx;
    uint32_t  fin_seq;       /* FIN'imizin seq'i */
    uint64_t  tw_at;         /* TIME_WAIT sayaci */
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
    uint8_t tt[TCP_MSS + 60];
    uint16_t off = 20;
    if (mss_opt) {
        tt[off] = 2; tt[off + 1] = 4;
        tt[off + 2] = (TCP_MSS >> 8) & 0xFF; tt[off + 3] = TCP_MSS & 0xFF;
        off += 4;
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
    memset(tt, 0, hlen);
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

void tcp_poll(Tcb& t) {
    if (!t.used || t.st == 0 || t.st == 1) return;
    if (t.ack_want && t.rcv_nxt != t.last_ack && timer_get_ticks() >= t.ack_at) tcp_ack_now(t);
    if (t.st == 7) {                       /* TIME_WAIT sayaci */
        if (timer_get_ticks() >= t.tw_at) { t.used = 0; t.st = 0; t.ok = true; t.done = true; }
        return;
    }
    /* en eski onaysiz (SACK ile dogrulanmamis) segmentin RTO'sunu kontrol et */
    int pi = ts_pick(t);
    if (pi >= 0 && t.snd_una == t.txb[pi].seq &&
        timer_get_ticks() - t.txb[pi].sent_at >= (uint64_t)((t.rto + 49) / 50)) {
        TxSlot& sl = t.txb[pi];
        tcp_emit(t, sl.seq, TCP_FLAG_ACK | TCP_FLAG_PSH, sl.data, sl.len, false, false);
        sl.sent_at = timer_get_ticks();
        if (t.rto < TCP_RTO_MAX) t.rto *= 2;
        if (t.rto > TCP_RTO_MAX) t.rto = TCP_RTO_MAX;
        rto_backoff(t);
    }
}

/* RTT orneklemesi: en eski onaysiz slotun gonderim ani ile bu anin uzakligi.
   RFC 6298: her segmente degil, RTT boyunca tek ornek. */
static void rtt_update(Tcb& t) {
    TxSlot& sl = t.txb[t.tx_tail];
    if (!sl.pend) return;
    uint32_t rtt_ms = (uint32_t)((timer_get_ticks() - sl.sent_at) * 10u);
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

/* hizli yeniden gonderim: SACK ile dogrulanmamis en eski segment + pencere kirma. */
static void fast_retrans(Tcb& t) {
    int pi = ts_pick(t);
    if (pi < 0) return;
    TxSlot& sl = t.txb[pi];
    tcp_emit(t, sl.seq, TCP_FLAG_ACK | TCP_FLAG_PSH, sl.data, sl.len, false, false);
    sl.sent_at = timer_get_ticks();
    uint32_t mss = t.mss ? t.mss : (uint32_t)TCP_MSS;
    uint32_t h = t.cwnd / 2;
    t.ssthresh = h > 2u * mss ? h : 2u * mss;
    t.cwnd = t.ssthresh;
    t.dupacks = 0;
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
            uint32_t o = 20;
            while (o + 2 <= off) {
                uint8_t kind = tt[o];
                if (kind == 0) break;
                if (kind == 1) { o++; continue; }
                if (o + 2 > off) break;
                uint8_t olen = tt[o + 1];
                if (olen < 2 || o + olen > off) break;
                if (kind == 2 && olen == 4) t.mss = (uint16_t)((tt[o + 2] << 8) | tt[o + 3]);
                o += olen;
            }
            if (t.mss == 0 || t.mss > TCP_MSS) t.mss = TCP_MSS;
            t.snd_wnd = rd16(tt + 14);                /* peer penceresi */
            t.st = 2; t.st_v = 2;
            t.done = true; t.ok = true;
        }
        return;
    }

    if (t.st == 8) {                             /* LISTEN: gelen SYN -> kiz soket */
        if ((flags & TCP_FLAG_SYN) && !(flags & TCP_FLAG_ACK)) {
            int c = -1;
            for (int i = 0; i < TCP_SOCKS; i++) if (!conns[i].used) { c = i; break; }
            if (c >= 0) {
                Tcb& ch = conns[c];
                ch.used = 1; ch.lfd = s;
                ch.ip = src_ip;
                ch.sport = dst_port;
                ch.dport = src_port;
                ch.iss = (uint32_t)((timer_get_ticks() << 12) ^ (uint32_t)(uintptr_t)tt ^ 0x4D2BC3A1u);
                ch.snd_una = ch.snd_nxt = ch.iss + 1;
                ch.rcv_nxt = seq + 1;
                ch.snd_wnd = 65535;          /* peer penceresi ESTAB olurken okunur */
                ch.mss = TCP_MSS;
                ch.rto = TCP_RTO0; ch.srtt = 0; ch.rttvar = 0; ch.dupacks = 0;
                ch.cwnd = TCP_CWND_INIT; ch.ssthresh = TCP_SSTHRESH_INIT;
                ch.tx_head = ch.tx_tail = 0;
                ch.ok = false; ch.done = false; ch.err = false;
                ch.fin_tx = ch.fin_rx = false;
                ch.win_update = false;
                ch.ack_want = false; ch.ack_inv = 0; ch.ack_at = 0; ch.last_ack = 0;
                ch.rxr_w = ch.rxr_fill = 0; ch.rlen = 0;
                ch.st = 9; ch.st_v = 9;
                tcp_emit(ch, ch.iss, TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0, true, false);
            }
        }
        return;
    }

    if (t.st == 9) {                             /* SYN_RECV: ACK beklenir */
        if ((flags & TCP_FLAG_ACK) && seq == t.rcv_nxt - 1 + 1) {
            t.snd_una = ack;
            t.snd_wnd = rd16(tt + 14);                /* peer penceresi */
            t.st = 2; t.st_v = 2;
            t.done = true; t.ok = true;
        }
        return;
    }

    /* ESTABLISHED ve kapanis durumlari */
    if (flags & TCP_FLAG_ACK) {
        t.snd_wnd = rd16(tt + 14);
        sack_apply(t, tt, off);                  /* peer SACK bloklari -> slot isaretleri */
        if (ack > t.snd_una && ack <= t.snd_nxt) {
            rtt_update(t);                       /* en eski onaysiz slotun sent_at'indan */
            ack_slots(t, ack);                   /* kumulatif onayli slotlari bosalt */
            t.snd_una = ack;
            t.dupacks = 0;
            cwnd_ack(t);                         /* slow-start / congestion avoidance */
            if (t.st == 3 && t.fin_tx && ack >= (uint32_t)(t.fin_seq + 1)) t.st = 4;   /* FINW1 -> FINW2 */
        } else if (ack == t.snd_una) {
            if (++t.dupacks == 3) fast_retrans(t);   /* hizli yeniden gonderim */
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

/* --- soket katmani: fd = conns[] indeksi --- */
static void sock_reset(int s) {
    Tcb& t = conns[s];
    t.used = 1; t.st = 0; t.st_v = 0;
    t.lfd = -1;
    t.ok = t.done = t.err = false;
    t.fin_tx = t.fin_rx = false;
    t.snd_una = t.snd_nxt = 0;
    t.rcv_nxt = 0;
    t.snd_wnd = TCP_MSS;
    t.mss = TCP_MSS;
    t.rto = TCP_RTO0; t.srtt = 0; t.rttvar = 0; t.dupacks = 0;
    t.cwnd = TCP_CWND_INIT; t.ssthresh = TCP_SSTHRESH_INIT;
    t.tx_head = t.tx_tail = 0;
    t.win_update = false;
    t.ack_want = false; t.ack_inv = 0; t.ack_at = 0; t.last_ack = 0;
    t.rxr_w = t.rxr_fill = 0; t.rlen = 0;
}

/* yeni (bos) soket: fd veya -1 */
extern "C" int net_socket(void) {
    if (!rtl8139_active()) return -1;
    for (int i = 0; i < TCP_SOCKS; i++)
        if (!conns[i].used) { sock_reset(i); return i; }
    return -1;
}

/* fd ile bekleyen/acik soket icin sinyal bekleme (hepsi iptal duyarli). */
static bool sock_ok(int s, uint32_t ticks) {
    if (s < 0 || s >= TCP_SOCKS || !conns[s].used) return false;
    Tcb& t = conns[s];
    uint64_t dd = timer_get_ticks() + ticks;
    while (timer_get_ticks() < dd && !t.done && !t.err && !sys_intr_pending()) { sys_intr_poll(); tcp_poll(t); cpu_hlt(); }
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
        while (!t.done && timer_get_ticks() < dd && !sys_intr_pending()) { sys_intr_poll(); tcp_poll(t); cpu_hlt(); }
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

    /* sender penceresi: min(peer kabulu, cwnd) asilmaz; slot sistemi onaysizlari tutar.
       Pencere kapaliysa ACK gelene kadar beklenir (iptal duyarli). */
    uint64_t wdd = timer_get_ticks() + 2000;         /* ~20 sn tavan */
    while (true) {
        uint32_t inflight = (uint32_t)(t.snd_nxt - t.snd_una);
        uint32_t win = t.snd_wnd;
        uint32_t cw  = t.cwnd;
        if (cw < win) win = cw;
        bool full = (t.tx_head == t.tx_tail && t.txb[t.tx_head].pend);
        if (!full && inflight + (uint32_t)len <= win) break;
        if (t.err || t.done || sys_intr_pending() || timer_get_ticks() >= wdd) return false;
        net_tcp_wait(s, 1);
    }
    TxSlot& sl = t.txb[t.tx_head];
    sl.seq = t.snd_nxt;
    sl.len = len;
    sl.sacked = false;
    memcpy(sl.data, data, len);
    sl.sent_at = timer_get_ticks();
    sl.pend = true;
    t.snd_nxt += len;
    t.tx_head = (uint8_t)((t.tx_head + 1) % TCP_TXQ);
    tcp_emit(t, sl.seq, TCP_FLAG_ACK | TCP_FLAG_PSH, data, len, false, false);
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
    if (conns[s].used) tcp_poll(conns[s]);
}

/* tum soketleri zamanlayici tarafiyla calistir (accept/recv disi). */
extern "C" void net_tcp_poll_all(void) {
    for (int i = 0; i < TCP_SOCKS; i++)
        if (conns[i].used) tcp_poll(conns[i]);
}

extern "C" uint32_t net_tcp_pending(int s) {
    if (s < 0 || s >= TCP_SOCKS) return 0;
    return conns[s].rlen;
}

extern "C" bool net_tcp_listen(int s, uint16_t port) {
    if (s < 0 || s >= TCP_SOCKS || !conns[s].used) return false;
    if (!rtl8139_active()) return false;
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
        for (int i = 0; i < TCP_SOCKS; i++) {
            if (i == s) continue;
            if (conns[i].used && conns[i].lfd == s && conns[i].st == 2) {
                conns[i].done = false; conns[i].err = false;
                return i;                       /* kabul edilecek soket */
            }
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
    while (timer_get_ticks() < dd && t.rlen == 0 && !t.err && !t.done && !sys_intr_pending()) { sys_intr_poll(); tcp_poll(t); cpu_hlt(); }
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
        tcp_emit(t, t.fin_seq, TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0, false, false);
        net_tcp_wait(s, 120);                       /* ~1.2s FINW1/FINW2/CLOSE beklenir */
    } else if (t.st == 5) {                         /* pasif taraf: LAST_ACK */
        t.fin_tx = true;
        t.fin_seq = t.snd_nxt;
        t.snd_nxt += 1;
        t.st = 6;
        tcp_emit(t, t.fin_seq, TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0, false, false);
        net_tcp_wait(s, 60);
    }
    if (t.ok || t.fin_rx || t.err) { t.used = 0; t.st = 0; t.st_v = 0; }
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
        if (ip[9] == 1) {
            handle_icmp(ip, iplen, frame);
        } else if (ip[9] == 17) {
            handle_udp(ip, iplen, frame + 6);
        } else if (ip[9] == 6) {
            handle_tcp(ip, iplen, frame + 6);
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
        while (!dns_done && timer_get_ticks() < t && !sys_intr_pending()) { sys_intr_poll(); cpu_hlt(); }
        dns_waiting = false;
        udp_sock_remove(sock);

        if (dns_done) {
            if (out_ip && dns_ok) *out_ip = dns_result;
            return dns_ok;
        }
    }
    return false;
}

extern "C" bool net_http_get(uint32_t ip, uint16_t port, const char* host,
                             const char* path, char* out, int out_cap) {
    if (!rtl8139_active()) return false;
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