/* cofeuos kullanici deneme programi
   Bagimsiz ring3 ikilisi: sadece int $0x80 kullanir, libc yok.
   SYS: EXIT=1 SLEEP=2 GETPID=4 GETTICKS=5 PUTSN=7 FORK=8 GETNAME=9
        FSWRITE=10 FSREAD=12 */

typedef unsigned long ul;

static ul sys6(ul n, ul a, ul b, ul c) {
    ul r;
    asm volatile("int $0x80"
                 : "=a"(r)
                 : "a"(n), "D"(a), "S"(b), "d"(c)
                 : "rcx", "r11", "memory");
    return r;
}

static ul sys3(ul n)            { return sys6(n, 0, 0, 0); }
static ul fork_id(void)         { return sys3(8); }
static void sleep_ms(ul ms)     { sys6(2, ms, 0, 0); }

static void out(const char* s, ul n) { sys6(7, (ul)s, n, 0); }

static void pr_hex(ul v, char* o) {
    const char* h = "0123456789ABCDEF";
    o[0] = '0'; o[1] = 'x';
    for (int i = 17; i >= 2; i--) { o[i] = h[v & 0xF]; v >>= 4; }
}

static int pr_dec(ul v, char* o) {
    char t[24]; int tn = 0;
    do { t[tn++] = (char)('0' + v % 10); v /= 10; } while (v);
    for (int i = 0; i < tn; i++) o[i] = t[tn - 1 - i];
    return tn;
}

static void dec_line(const char* label, ul v) {
    char b[32]; int n = 0;
    for (int i = 0; label[i]; i++) b[n++] = label[i];
    n += pr_dec(v, b + n);
    b[n++] = '\n';
    out(b, (ul)n);
}

void _start(void) {
    char buf[256];
    char name[15];
    ul pid = sys3(4);
    sys6(9, (ul)name, 0, 0);

    ul child = 0;
    if (pid == 1) child = fork_id();

    char tag = (pid == 1) ? (child ? 'P' : 'C') : 'U';
    for (int it = 0; it < 3; it++) {
        ul tt = sys3(5);
        int n = 0;
        buf[n++] = '[';
        buf[n++] = tag;
        buf[n++] = ']';
        buf[n++] = ' ';
        for (int k = 0; name[k] && k < 14; k++) buf[n++] = name[k];
        buf[n++] = ' '; buf[n++] = 'p'; buf[n++] = 'i'; buf[n++] = 'd';
        pr_hex(pid, buf + n); n += 18;
        buf[n++] = ' '; buf[n++] = 'i'; buf[n++] = 't'; buf[n++] = '=';
        n += pr_dec((ul)it, buf + n);
        buf[n++] = ' '; buf[n++] = 't'; buf[n++] = '=';
        n += pr_dec(tt, buf + n);
        buf[n++] = '\n';
        out(buf, (ul)n);
        sleep_ms(120);
    }

    if (pid == 4) {
        /* izolasyon testi: kernel bellegine yazmaya calis -> PF ile oldurulmali */
        volatile char* k = (volatile char*)0x200000;
        *k = 1;
    }

    /* exec-self testi: cocuk (pid 2) ilk cagrida kendini basic.cexe ile
       degistirir; pid ve isim korunur. Kapak dosyasi sonsuz donmeyi onler. */
    if (pid == 2) {
        char gate[64];
        long have = (long)sys6(12, (ul)"/uspc/exec_gate", (ul)gate, (ul)sizeof(gate));
        if (have <= 0) {
            const char* g0 = "x";
            sys6(10, (ul)"/uspc/exec_gate", (ul)g0, 1);
            out("[exec] ONCESI (ayni surec imaji degisecek)\n", 43);
            sys6(17, (ul)"/sys/basic.cexe", 0, 0);   /* exec-self, donmez */
            out("[exec] HATA: exec geri dondu!\n", 30);
        } else {
            out("[exec] SONRASI: imaj degisti, pid korundu\n", 42);
        }
    }

    /* FS sistem cagrilari denemesi (her surecte calisir) */
    const char* p = "/uspc/demo.txt";
    const char* m1 = "ilk satir\n";
    const char* m2 = "ikinci satir\n";
    long w1 = (long)sys6(10, (ul)p, (ul)m1, 10);          /* FSWRITE */
    dec_line("[fs] write=", (ul)w1);
    long ap = (long)sys6(11, (ul)p, (ul)m2, 13);          /* FSAPPEND */
    dec_line("[fs] append=", (ul)ap);
    long r = (long)sys6(12, (ul)p, (ul)buf, (ul)sizeof(buf)); /* FSREAD */
    dec_line("[fs] read=", (ul)r);
    out("[fs] icerik: ", 14);
    out(buf, (ul)r);
    long st = (long)sys6(13, (ul)p, (ul)buf, 0);          /* FSSTAT */
    dec_line("[fs] stat=", (ul)st);

    /* WAIT: yalniz pid==1 ana (cocugu zombi olan) reaping testi yapsin */
    if (pid == 1) {
        long wv = (long)sys6(16, 0, 0, 0);
        dec_line("[fs] wait=", (ul)wv);

        /* stdin yoklamalari (engelleyici degil): bos iken GETCH=0, FSGETC=-1 */
        long g1 = (long)sys6(14, 0, 0, 0);
        long g2 = (long)sys6(15, 0, 0, 0);
        dec_line("[io] getch=", (ul)g1);
        dec_line("[io] fsgetc=", (ul)g2);
    }

    sys6(1, (ul)(pid % 10), 0, 0);
}
