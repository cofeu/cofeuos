/* tcp_http.cexe: ring3 TCP syscall'lari (SYS_TCPSOCK..) ile example.com:80'e
   baglanip HTTP/1.0 GET ceker. DNS cozumlemesi UDP syscall'lariyla ring3'te
   yapilir (udp_dns.cexe ile ayni akis). Sonuc: HTTP durum satiri ve toplam
   okunan bayt. */

typedef unsigned long ul;

static ul sc(ul n, ul a0, ul a1, ul a2, ul a3) {
    ul r;
    asm volatile("int $0x80"
                 : "=a"(r)
                 : "a"(n), "D"(a0), "S"(a1), "d"(a2), "c"(a3)
                 : "r11", "memory");
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
        if (b & 0xC0) { *pos += 2; return; }
        if (b == 0)   { *pos += 1; return; }
        *pos += 1 + b;
    }
}

static int parse_a(const unsigned char* d, int len, ul* ip) {
    if (len < 12 || (w16(d + 2) & 0x8000) == 0) return 0;
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

static int resolve(const char* host, ul* ip) {
    int fd = (int)sc(18, 0, 0, 0, 0);               /* SYS_UDPSOCK */
    if (fd < 0) return 0;
    if (sc(19, (ul)fd, 0, 0, 0) != 0) { sc(23, (ul)fd, 0, 0, 0); return 0; }
    unsigned char q[300];
    q[0] = 0xAA; q[1] = 0x55;
    q[2] = 1; q[3] = 0;
    q[4] = 0; q[5] = 1;
    for (int i = 6; i <= 11; i++) q[i] = 0;
    int n = qname(q + 12, host);
    q[12 + n] = 0; q[13 + n] = 1; q[14 + n] = 0; q[15 + n] = 1;
    int qlen = 12 + n + 4;
    ul dns = 0x0A000203u;                           /* 10.0.2.3 (slirp) */
    unsigned char b[512];
    int ok = 0;
    for (int att = 0; att < 3 && !ok; att++) {
        sc(20, (ul)fd, dns, 53 | ((ul)qlen << 16), (ul)q);
        for (int w = 0; w < 100 && !ok; w++) {
            if (sc(21, (ul)fd, 10, 0, 0) != 1) continue;
            int got = (int)sc(22, (ul)fd, (ul)b, (ul)sizeof(b), 0);
            if (got >= 12 && w16(b) == 0xAA55) ok = parse_a(b, got, ip);
        }
    }
    sc(23, (ul)fd, 0, 0, 0);
    return ok;
}

static void print_ul(ul v) {
    char b[40]; int n = 0;
    static const char digits[] = "0123456789";
    do { b[n++] = digits[v % 10]; v /= 10; } while (v);
    for (int i = 0, j = n - 1; i < j; i++, j--) { char t = b[i]; b[i] = b[j]; b[j] = t; }
    b[n++] = '\n';
    sc(7, (ul)b, (ul)n, 0, 0);
}

static void print_line(const unsigned char* p, int n) {
    int e = 0;
    while (e < n && p[e] != '\n') e++;
    if (e) sc(7, (ul)p, (ul)e, 0, 0);
    sc(7, (ul)"\n", 1, 0, 0);
}

void _start(void) {
    const char* host = "example.com";
    const char* hdr = "tcp_http: example.com:80 TCP/HTTP testi...\n";
    int hlen;
    for (hlen = 0; hdr[hlen]; hlen++) ;
    put(hdr, (ul)hlen);

    ul ip = 0;
    if (!resolve(host, &ip)) { put("tcp_http: DNS cozulemedi (%u)\n", 27); sc(1, 1, 0, 0, 0); return; }

    int fd = (int)sc(24, 0, 0, 0, 0);               /* SYS_TCPSOCK */
    if (fd < 0) { put("tcp_http: soket yok\n", 19); sc(1, 1, 0, 0, 0); return; }

    if (sc(25, (ul)fd, ip, 80, 0) != 0) {           /* SYS_TCPCONNECT */
        put("tcp_http: baglanti kurulamadi\n", 28);
        sc(32, (ul)fd, 0, 0, 0);
        sc(1, 1, 0, 0, 0); return;
    }

    static const char req[] =
        "GET / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    int rlen = 0;
    while (req[rlen]) rlen++;

    if (sc(28, (ul)fd, (ul)req, (ul)rlen, 0) != (ul)rlen) {   /* SYS_TCPSEND */
        put("tcp_http: gonderim hatasi\n", 25);
        sc(32, (ul)fd, 0, 0, 0);
        sc(1, 1, 0, 0, 0); return;
    }

    ul total = 0;
    int firstline = 0;
    unsigned char buf[512];
    for (;;) {
        if (sc(29, (ul)fd, 20, 0, 0) == 0) {        /* SYS_TCPWAIT (20 tick) */
            if (sc(30, (ul)fd, 0, 0, 0) == 0) {     /* SYS_TCPPENDING */
                if (sc(31, (ul)fd, (ul)buf, 1, 0) < 0) break;  /* SYS_TCPRECV */
                if (sc(30, (ul)fd, 0, 0, 0) == 0) break;
            }
        }
        long n = (long)sc(31, (ul)fd, (ul)buf, (ul)sizeof(buf), 0);
        if (n <= 0) break;                          /* -1 hata, -2 kapanis */
        total += (ul)n;
        if (!firstline) { print_line(buf, (int)n); firstline = 1; }
    }

    put("tcp_http: TOPLAM ", 18);
    print_ul(total);
    sc(32, (ul)fd, 0, 0, 0);                        /* SYS_TCPCLOSE (FIN bekler) */
    sc(1, 0, 0, 0, 0);
}