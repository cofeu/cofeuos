/* udp_dns.cexe: UDP fd soket syscall'larini (SYS_UDPSOCK..) kullanarak
   DNS (RFC 1035) cozumleme. 10.0.2.3:53'e sorgu atar, yaniti ring3'te
   kendisi ayristirir ve A kaydini basar. Ayni sorgu akisi net_dns_resolve'un
   cekirdek tarafindaki fd tabanli yoluyla birebir aynidir. */

typedef unsigned long ul;

static ul sc(ul n, ul a0, ul a1, ul a2, ul a3) {
    ul r;
    asm volatile("int $0x80"
                 : "=a"(r)
                 : "a"(n), "D"(a0), "S"(a1), "d"(a2), "c"(a3)
                 : "r11", "memory");   /* int $0x80 cevap gelince c=getirdi (xonum) */
    return r;
}

static void put(const char* s, ul n) { sc(7, (ul)s, n, 0, 0); }

static ul w16(const unsigned char* p) { return (ul)p[0] << 8 | p[1]; }

static int qname(unsigned char* o, const char* name) {
    int n = 0;
    while (*name && n < 250) {
        const char* p = name;
        while (*p && *p != '.') p++;
        int l = (int)(p - name);
        if (l >= 1 && l <= 63) {
            o[n++] = (unsigned char)l;
            for (int i = 0; i < l && n < 250; i++) o[n++] = (unsigned char)name[i];
        }
        name = (*p == '.') ? p + 1 : p;
    }
    o[n++] = 0;
    return n;
}

static void skipname(const unsigned char* d, int* pos, int limit) {
    for (;;) {
        if (*pos < 0 || *pos >= limit) { *pos = -1; return; }
        unsigned char b = d[*pos];
        if (b & 0xC0) { *pos += 2; return; }          /* sikistirma isaretcisi */
        if (b == 0)   { *pos += 1; return; }
        *pos += 1 + b;
    }
}

static int parse_a(const unsigned char* d, int len, ul* ip) {
    if (len < 12 || (w16(d + 2) & 0x8000) == 0) return 0;   /* QR yanit olmali */
    int qd = (int)w16(d + 4), an = (int)w16(d + 6);
    int pos = 12;
    for (int i = 0; i < qd; i++) { skipname(d, &pos, len); if (pos < 0) return 0; pos += 4; }
    for (int i = 0; i < an; i++) {
        skipname(d, &pos, len); if (pos < 0) return 0;
        int type = (int)w16(d + pos), rdlen = (int)w16(d + pos + 8);
        pos += 10;
        if (type == 1 && rdlen == 4 && pos + 4 <= len) {
            *ip = (ul)d[pos] << 24 | (ul)d[pos + 1] << 16 |
                  (ul)d[pos + 2] << 8 | (ul)d[pos + 3];
            return 1;
        }
        pos += rdlen;
    }
    return 0;
}

static void print_ip(ul ip) {
    char b[40];
    int n = 0;
    static const char digits[] = "0123456789";
    for (int oct = 3; oct >= 0; oct--) {
        ul v = (ip >> (oct * 8)) & 0xFF;
        char t[4]; int m = 0;
        do { t[m++] = digits[v % 10]; v /= 10; } while (v);
        while (m) b[n++] = t[--m];
        if (oct) b[n++] = '.';
    }
    b[n++] = '\n';
    sc(7, (ul)b, (ul)n, 0, 0);
}

void _start(void) {
    const char* host = "example.com";
    const char* hdr = "udp_dns: example.com 10.0.2.3:53 uzerinden cozuluyor...\n";
    put(hdr, 60);

    int fd = (int)sc(18, 0, 0, 0, 0);                       /* SYS_UDPSOCK */
    if (fd < 0) { put("udp_dns: soket yok\n", 16); sc(1, 1, 0, 0, 0); return; }
    if (sc(19, (ul)fd, 0, 0, 0) != 0) {                     /* SYS_UDPBIND (0=otomatik port) */
        put("udp_dns: bind hatasi\n", 19);
        sc(1, 1, 0, 0, 0); return;
    }

    unsigned char q[300];
    ul qid = 0xAA55;
    q[0] = (unsigned char)(qid >> 8); q[1] = (unsigned char)qid;
    q[2] = 1; q[3] = 0;                                  /* RD isteniyor */
    q[4] = 0; q[5] = 1;                                  /* 1 soru (QDCOUNT) */
    q[6] = q[7] = q[8] = q[9] = q[10] = q[11] = 0;       /* AN/NS/AR sayaclari */
    int n = qname(q + 12, host);
    q[12 + n] = 0; q[13 + n] = 1;                        /* A */
    q[14 + n] = 0; q[15 + n] = 1;                        /* IN */
    int qlen = 12 + n + 4;
    ul dns = 0x0A000203u;                                /* 10.0.2.3 (slirp) */

    unsigned char b[512];
    ul ip = 0;
    int ok = 0;
    for (int att = 0; att < 3 && !ok; att++) {
        sc(20, (ul)fd, dns, 53 | ((ul)qlen << 16), (ul)q); /* SYS_UDPSENDTO */
        for (int w = 0; w < 100 && !ok; w++) {           /* ~1 sn pencere */
            if (sc(21, (ul)fd, 10, 0, 0) != 1) continue;    /* SYS_UDPWAIT (10 tick) */
            int got = (int)sc(22, (ul)fd, (ul)b, (ul)sizeof(b), 0); /* SYS_UDPRECVFROM */
            if (got >= 12 && w16(b) == qid)              /* eslesen sorgu id */
                ok = parse_a(b, got, &ip);
        }
    }
    if (ok) {
        put("udp_dns: SONUC ", 13);
        print_ip(ip);
    } else {
        put("udp_dns: cozulemedi\n", 19);
    }
    sc(23, (ul)fd, 0, 0, 0);                                /* SYS_UDPCLOSE */
    sc(1, (ul)(ok ? 0 : 1), 0, 0, 0);                       /* EXIT */
}