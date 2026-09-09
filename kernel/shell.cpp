#include "kernel.h"
#include "x86.h"
#include "pmm.h"
#include "sched.h"
#include "rtc.h"
#include "net.h"

namespace {

/* ---- VGA renk yardimcilari (serial mirror'a dokunmaz) ---- */
enum VGAC { VGA_BLACK=0x0, VGA_BLUE=0x1, VGA_GREEN=0x2, VGA_CYAN=0x3,
            VGA_RED=0x4, VGA_MAGENTA=0x5, VGA_BROWN=0x6, VGA_LIGHT_GRAY=0x7,
            VGA_DARK_GRAY=0x8, VGA_LIGHT_BLUE=0x9, VGA_LIGHT_GREEN=0xA,
            VGA_LIGHT_CYAN=0xB, VGA_LIGHT_RED=0xC, VGA_LIGHT_MAGENTA=0xD,
            VGA_YELLOW=0xE, VGA_WHITE=0xF };

#define VGA_FG(bg, fg) ((uint8_t)(((bg) << 4) | (fg)))

void set_color(uint8_t c) { vga_set_color(c); }
void rst_color(void)      { vga_set_color(VGA_FG(VGA_BLACK, VGA_LIGHT_GRAY)); }

int atoi_cst(const char* s) {
    int v = 0, sg = 1;
    if (!s) return 0;
    while (*s == ' ') s++;
    if (*s == '-') { sg = -1; s++; }
    while (*s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); s++; }
    return v * sg;
}

const char* HELP =
    "cofeuos komutlari:\n"
    "  help                     - bu liste\n"
    "  clear                    - ekrani temizle\n"
    "  ls [yol]                 - dizin listele\n"
    "  cd <yol>                 - dizin degistir\n"
    "  pwd                      - calisma dizinini goster\n"
    "  mkdir <yol>              - dizin olustur\n"
    "  touch <yol>              - bos dosya olustur\n"
    "  echo <metin>             - metni yazdir\n"
    "  <komut> > <dosya>        - komut ciktisini dosyaya yaz (ustune)\n"
    "  <komut> >> <dosya>       - komut ciktisini dosyaya ekle\n"
    "  <k1> | <k2> [| <k3>]...  - komut zinciri (cikti sonrakine stdin)\n"
    "                          (ornek: ls / | wc, cat f | wc)\n"
    "                          (ornek: ls > /uspc/liste.txt, ps >> log.txt)\n"
    "  cat <dosya>              - dosyayi oku (argumansiz: stdin)\n"
    "  wc                       - stdin'den satir/kelime/karakter say\n"
    "  xxd <dosya>              - hexdump\n"
    "  rm [-r] <yol>            - dosya/dizin sil\n"
    "  lsfs                     - dosya sistemi bilgisi\n"
    "  date                     - tarih ve saati goster\n"
    "  uptime                   - calisma suresi\n"
    "  cnv                      - sistem bilgisi (uname gibi)\n"
    "  mem                      - bellek kullanimi\n"
    "  ps                       - surec listesi (bellek/sure)\n"
    "  kill <pid>               - sureci oldur\n"
    "  wait [pid]               - zombie surec temizle / bekle\n"
    "  spawn <ad>               - yeni surec baslat\n"
    "  run <dosya.cexe>         - ELF uygulama calistir (diskten)\n"
    "  ifconfig                 - ag arayuz bilgisi\n"
    "  dhcp                     - DHCP ile IP iste\n"
    "  dns <ad>                 - alan adini coz (A kaydi)\n"
    "  http <host> [yol] [dosya] - HTTP GET iste; govdeyi bulundugu dizine kaydet\n"
    "  httpd [port]             - pasif HTTP sunucu (varsayilan 8080), tek baglanti\n"
    "  nettest                  - ag regresyon testi (ping/dns/http)\n"
    "  ping <a.b.c.d>           - ICMP echo gonder\n"
    "  reboot                   - yeniden baslat\n"
    "  poweroff                 - kapat\n"
    "\n"
    "dizin yapisi:\n"
    "  /    - kok\n"
    "  /temp - gecici dosyalar\n"
    "  /sys  - sistem dosyalari ve .cexe uygulamalari\n"
    "  /uspc - kullanicinin yonettigi alan\n"
    "uygulama uzantisi: .cexe (cofeuos executable)\n";

struct Tokens {
    char tok[32][32];
    int n;
};

int tokenize(char* line, Tokens& t) {
    t.n = 0;
    char* p = line;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        int len = 0;
        while (*p && *p != ' ' && len < 31) t.tok[t.n][len++] = *p++;
        t.tok[t.n][len] = 0;
        t.n++;
        if (t.n >= 32) break;
    }
    return t.n;
}

void print_entries_cb(const fs::EntryInfo& e, void* ctx) {
    (void)ctx;
    if (e.type_ == 2) {
        set_color(VGA_FG(VGA_BLACK, VGA_LIGHT_CYAN));
        kprintf("%-31s <DIZIN>\n", e.name_);
        rst_color();
    } else {
        set_color(VGA_FG(VGA_BLACK, VGA_LIGHT_GRAY));
        kprintf("%-31s    %u bayt\n", e.name_, e.size_);
        rst_color();
    }
}

bool cmd_echo(Tokens& t, uint32_t cwd) {
    (void)cwd;
    if (t.n < 2) { kprintf("\n"); return true; }
    for (int i = 1; i < t.n; i++) {
        if (i > 1) kprintf(" ");
        kprintf("%s", t.tok[i]);
    }
    kprintf("\n");
    return true;
}

/* yonlendirme (cmd > dosya / cmd >> dosya) ayristirici.
   line'daki > veya >> tokenini ve takip eden dosya adini bulur, bunlari
   line'dan cikarir (komut dogrudan calisabilsin), rpath hedefi, rmode
   (1 = > , 2 = >>) doldurur. Yonlendirme yoksa false doner. */
static bool extract_redirect(char* line, char* rpath, int rpath_sz, int* rmode) {
    char toks[32][32];
    int   nt = 0;
    {
        char* p = line;
        while (*p) {
            while (*p == ' ') p++;
            if (!*p) break;
            int l = 0;
            while (*p && *p != ' ' && l < 31) toks[nt][l++] = *p++;
            toks[nt][l] = 0;
            nt++;
            if (nt >= 32) break;
        }
    }

    int redir = -1;
    bool append = false;
    for (int i = 0; i < nt; i++) {
        if (strcmp(toks[i], ">>") == 0) { redir = i; append = true; break; }
        if (strcmp(toks[i], ">") == 0)  { redir = i; append = false; break; }
    }
    if (redir < 0 || redir + 1 >= nt) return false;

    strncpy(rpath, toks[redir + 1], (size_t)(rpath_sz - 1));
    rpath[rpath_sz - 1] = 0;
    *rmode = append ? 2 : 1;

    int o = 0;
    for (int i = 0; i < nt; i++) {
        if (i == redir || i == redir + 1) continue;
        if (o) line[o++] = ' ';
        for (int j = 0; toks[i][j]; j++) line[o++] = toks[i][j];
    }
    line[o] = 0;
    return true;
}

static void norm_join(char* cwdstr, const char* path) {
    char tmp[128];
    tmp[0] = 0;
    if (path[0] == '/') {
        strncpy(tmp, path, 127);
    } else {
        strncpy(tmp, cwdstr, 127);
        size_t tl = strlen(tmp);
        if (tl && tmp[tl - 1] != '/') { tmp[tl++] = '/'; tmp[tl] = 0; }
        size_t pl = strlen(path);
        if (tl + pl + 1 < 127) memcpy(tmp + tl, path, pl + 1);
    }
    char stack[16][20];
    int sp = 0;
    char* t = &tmp[0];
    while (*t) {
        while (*t == '/') t++;
        if (!*t) break;
        char seg[20];
        int n = 0;
        while (*t && *t != '/' && n < 19) seg[n++] = *t++;
        seg[n] = 0;
        if (strcmp(seg, ".") == 0) continue;
        if (strcmp(seg, "..") == 0) { if (sp > 0) sp--; continue; }
        if (sp < 16) strcpy(stack[sp++], seg);
    }
    if (sp == 0) { strcpy(cwdstr, "/"); return; }
    char out[128];
    int o = 0;
    for (int i = 0; i < sp; i++) {
        out[o++] = '/';
        int l = (int)strlen(stack[i]);
        memcpy(out + o, stack[i], l);
        o += l;
    }
    out[o] = 0;
    strncpy(cwdstr, out, 127);
}

void cmd_cd(Tokens& t, uint32_t& cwd, char* cwdstr) {
    const char* path = (t.n >= 2) ? t.tok[1] : "/";
    uint32_t ino;
    if (!fs::resolve(cwd, path, &ino)) {
        kprintf("hata: dizin yok\n");
        return;
    }
    fs::EntryInfo st;
    if (!fs::stat(cwd, path, &st) || st.type_ != 2) {
        kprintf("hata: dizin degil\n");
        return;
    }
    cwd = ino;
    norm_join(cwdstr, path);
}

void cmd_lsfs(void) {
    kprintf("disc toplam blok : %u\n", fs::disk_blocks());
    kprintf("sektor (LBA)     : %u\n", 512U);
}

void cmd_xxd(const char* path, uint32_t cwd) {
    static uint8_t buf[4096];
    uint32_t got = 0;
    if (!fs::read_file(cwd, path, buf, sizeof(buf), &got)) {
        kprintf("hata: okunamadi\n");
        return;
    }
    for (uint32_t i = 0; i < got; i += 16) {
        kprintf("%08x  ", i);
        for (int j = 0; j < 16; j++) {
            if (i + j < got) kprintf("%02x ", buf[i + j]);
            else kprintf("   ");
            if (j == 7) kprintf(" ");
        }
        kprintf(" |");
        for (int j = 0; j < 16 && i + j < got; j++) {
            char c = (char)buf[i + j];
            kprintf("%c", (c >= 32 && c < 127) ? c : '.');
        }
        kprintf("|\n");
    }
}

static void run_line_inner(char* line, uint32_t& cwd, char* cwdstr, const char* pipe_in) {
    Tokens t;
    tokenize(line, t);
    if (t.n == 0) return;

    const char* cmd = t.tok[0];

    if      (strcmp(cmd, "help") == 0)     kprintf("%s", HELP);
    else if (strcmp(cmd, "clear") == 0)    vga_clear();
    else if (strcmp(cmd, "cls") == 0)      vga_clear();
    else if (strcmp(cmd, "cnv") == 0)
        kprintf("cofeuos node x86_64 0.1.0 (uname benzeri)\n");
    else if (strcmp(cmd, "ls") == 0)       fs::list(cwd, (t.n >= 2) ? t.tok[1] : ".", print_entries_cb, NULL);
    else if (strcmp(cmd, "cd") == 0)       cmd_cd(t, cwd, cwdstr);
    else if (strcmp(cmd, "mkdir") == 0) {
        if (t.n < 2) kprintf("kullanim: mkdir <yol>\n");
        else if (!fs::mkdir(cwd, t.tok[1])) kprintf("hata: olusturulamadi\n");
    }
    else if (strcmp(cmd, "touch") == 0) {
        if (t.n < 2) kprintf("kullanim: touch <yol>\n");
        else if (!fs::create_file(cwd, t.tok[1])) kprintf("hata: olusturulamadi\n");
    }
    else if (strcmp(cmd, "echo") == 0)     cmd_echo(t, cwd);
    else if (strcmp(cmd, "cat") == 0) {
        static char buf[12288];
        if (pipe_in) {
            /* stdin (pipe) modu: gelen her seyi oldugu gibi yaz */
            kprintf("%s", pipe_in);
        } else if (t.n < 2) {
            kprintf("kullanim: cat <dosya>\n");
        } else {
            uint32_t got = 0;
            if (!fs::read_file(cwd, t.tok[1], buf, sizeof(buf) - 1, &got))
                kprintf("hata: okunamadi\n");
            else {
                buf[got] = 0;
                kprintf("%s", buf);
                if (got && buf[got - 1] != '\n') kprintf("\n");
            }
        }
    }
    else if (strcmp(cmd, "wc") == 0) {
        /* satir / kelime / karakter sayaci (stdin'den okur) */
        const char* s = pipe_in;
        if (!s) s = "";
        unsigned long lines = 0, words = 0, chars = 0;
        bool in_word = false;
        for (const char* p = s; *p; p++) {
            chars++;
            if (*p == '\n') lines++;
            if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
                in_word = false;
            } else if (!in_word) {
                in_word = true;
                words++;
            }
        }
        if (chars && s[chars - 1] != '\n') lines++;   /* son satirsiz satir */
        kprintf("%lu  %lu  %lu\n", lines, words, chars);
    }
    else if (strcmp(cmd, "xxd") == 0) {
        if (t.n < 2) kprintf("kullanim: xxd <dosya>\n");
        else cmd_xxd(t.tok[1], cwd);
    }
    else if (strcmp(cmd, "rm") == 0) {
        bool rec = false;
        int idx = 1;
        if (t.n >= 2 && strcmp(t.tok[1], "-r") == 0) { rec = true; idx = 2; }
        if (t.n <= idx) kprintf("kullanim: rm [-r] <yol>\n");
        else {
            fs::EntryInfo st;
            bool is_dir = (fs::stat(cwd, t.tok[idx], &st) && st.type_ == 2);
            if (is_dir && !rec) {
                kprintf("hata: '%s' bir dizin, silmek icin 'rm -r %s'\n", t.tok[idx], t.tok[idx]);
            } else if (!fs::remove_file(cwd, t.tok[idx], rec)) {
                kprintf("hata: silinemedi\n");
            }
        }
    }
    else if (strcmp(cmd, "lsfs") == 0)     cmd_lsfs();
    else if (strcmp(cmd, "pwd") == 0)      kprintf("%s\n", cwdstr);
    else if (strcmp(cmd, "uptime") == 0)   kprintf("calisma suresi: %llu sn\n", timer_get_seconds());
    else if (strcmp(cmd, "date") == 0) {
        RTCDate rtc = rtc_read();
        const char* aylar[] = {"Ocak","Subat","Mart","Nisan","Mayis","Haziran",
                               "Temmuz","Agustos","Eylul","Ekim","Kasim","Aralik"};
        const char* gunler[] = {"Pazar","Pazartesi","Sali","Carsamba","Persembe","Cuma","Cumartesi"};
        kprintf("%s, %02d %s %04d  %02d:%02d:%02d\n",
                gunler[(rtc.day + 1) % 7],   /* basit gun hesabi */
                rtc.day, aylar[rtc.month - 1], rtc.year,
                rtc.hour, rtc.minute, rtc.second);
    }
    else if (strcmp(cmd, "mem") == 0) {
        kprintf("RAM        : %lu MB (%lu KB)\n", pmm_total_kb() / 1024u, pmm_total_kb());
        kprintf("yonetilen  : %lu KB (%lu frame, %lu serbest)\n",
                pmm_managed_kb(), (unsigned long)pmm_total_frames(),
                (unsigned long)pmm_free_frames());
        kprintf("heap       : %lu / %lu KB\n",
                (unsigned long)(kmem_used() / 1024u),
                (unsigned long)(kmem_capacity() / 1024u));
    }
    else if (strcmp(cmd, "ps") == 0)       sched_list();
    else if (strcmp(cmd, "kill") == 0) {
        if (t.n < 2) kprintf("kullanim: kill <pid>\n");
        else {
            int pid = atoi_cst(t.tok[1]);
            if (pid < 1 || pid > 0xFFFF || sched_kill((uint16_t)pid) != 0)
                kprintf("hata: %d oldurulemedi\n", pid);
            else
                kprintf("surec %d olduruldu\n", pid);
        }
    }
    else if (strcmp(cmd, "spawn") == 0) {
        const char* nm = (t.n >= 2) ? t.tok[1] : "proc";
        int pid = sched_spawn(nm);
        if (pid < 0) kprintf("hata: baslatilamadi (tablo dolu)\n");
        else kprintf("baslatildi pid=0x%04X (%d)\n", (uint16_t)pid, pid);
    }
    else if (strcmp(cmd, "run") == 0) {
        if (t.n < 2) kprintf("kullanim: run <dosya.cexe>\n");
        else {
            char pathstr[64];
            pathstr[0] = 0;
            if (t.tok[1][0] != '/') {
                strncpy(pathstr, cwdstr, 63);
                int pl = (int)strlen(pathstr);
                if (pl > 1 && pathstr[pl - 1] != '/') {
                    pathstr[pl] = '/'; pathstr[pl + 1] = 0;
                }
                strncpy(pathstr + strlen(pathstr), t.tok[1], 63 - strlen(pathstr));
            } else {
                strncpy(pathstr, t.tok[1], 63);
            }
            pathstr[63] = 0;
            int pid = sched_exec_file(pathstr);
            if (pid < 0) kprintf("hata: %s calistirilamadi\n", pathstr);
            else kprintf("baslatildi pid=0x%04X (%d)\n", (uint16_t)pid, pid);
        }
    }
    else if (strcmp(cmd, "wait") == 0) {
        uint16_t want = 0;
        if (t.n >= 2) want = (uint16_t)atoi_cst(t.tok[1]);
        int ec = sched_wait(want);
        if (ec < 0) kprintf("beklenecek surec yok\n");
        else kprintf("surec tamamlandi (cikis kodu: %d)\n", ec);
    }
    else if (strcmp(cmd, "ifconfig") == 0) {
        if (!net_active()) kprintf("hata: ag arayuzu yok/aktif degil\n");
        else net_ifconfig();
    }
    else if (strcmp(cmd, "sock") == 0) {
        if (!net_active()) kprintf("hata: ag arayuzu yok/aktif degil\n");
        else net_sockdump();
    }
    else if (strcmp(cmd, "dhcp") == 0) {
        if (!net_active()) kprintf("hata: ag arayuzu yok/aktif degil\n");
        else if (net_dhcp()) {
            kprintf("dhcp: tamam\n");
            net_ifconfig();
        } else {
            kprintf("dhcp: zaman asimi (cevap yok)\n");
        }
    }
    else if (strcmp(cmd, "dns") == 0) {
        if (t.n < 2) kprintf("kullanim: dns <alan adi>\n");
        else if (!net_active()) kprintf("hata: ag arayuzu yok\n");
        else {
            uint32_t ip = 0;
            kprintf("cozuluyor: %s ...\n", t.tok[1]);
            if (net_dns_resolve(t.tok[1], &ip))
                kprintf("%s -> %u.%u.%u.%u\n", t.tok[1],
                        (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
            else
                kprintf("cozulemedi: %s\n", t.tok[1]);
        }
    }
    else if (strcmp(cmd, "http") == 0) {
        if (t.n < 2) kprintf("kullanim: http <host> [yol] [dosya]\n");
        else if (!net_active()) kprintf("hata: ag arayuzu yok\n");
        else {
            char hostbuf[64];
            const char* host = t.tok[1];
            const char* path = (t.n >= 3) ? t.tok[2] : "/";
            const char* file = (t.n >= 4) ? t.tok[3] : NULL;
            uint16_t port = 80;
            const char* colon = strchr(host, ':');
            if (colon && colon != host) {
                int hl = (int)(colon - host);
                if (hl > 50) hl = 50;
                memcpy(hostbuf, host, (size_t)hl); hostbuf[hl] = 0;
                uint32_t pv = 0; const char* ps = colon + 1;
                while (*ps >= '0' && *ps <= '9') { pv = pv * 10u + (uint32_t)(*ps - '0'); ps++; }
                if (pv > 0 && pv < 65536) port = (uint16_t)pv;
                host = hostbuf;
            }
            uint32_t ip = 0;
            bool is_ip = false;
            ip = net_parse_ip(host, &is_ip);
            bool host_ok = true;
            if (!is_ip) {
                ip = 0;
                host_ok = net_dns_resolve(host, &ip);
            } else if (!ip) {
                host_ok = false;
            }
            if (!host_ok) {
                kprintf("cozulemedi: %s\n", host);
            } else {
                static char buf[163840];
                kprintf("GET http://%s:%u%s ...\n", host, port, path);
                if (!net_http_get(ip, port, host, path, buf, sizeof(buf))) {
                    kprintf("istek basarisiz (zaman asimi/red)\n");
                } else {
                    char* p = buf;
                    while (*p && *p != '\r' && *p != '\n') p++;
                    char sc = *p; *p = 0;
                    kprintf("cevap status: %s\n", buf);
                    *p = sc;
                    char* body = buf;
                    for (int i = 0; buf[i]; i++)
                        if (i > 0 && buf[i - 3] == '\r' && buf[i - 2] == '\n' &&
                            buf[i - 1] == '\r' && buf[i] == '\n') { body = buf + i + 1; break; }
                    unsigned bl = 0; while (body[bl]) bl++;
                    kprintf("govde: %u bayt\n", bl);
                    uint32_t fnv = 2166136261u;
                    for (unsigned i = 0; i < bl; i++) { fnv ^= (uint8_t)body[i]; fnv *= 16777619u; }
                    kprintf("govde-fnv32: %08X\n", fnv);
                    char name[40];
                    if (file) {
                        strncpy(name, file, 39); name[39] = 0;
                    } else {
                        const char* seg = path;
                        for (const char* q = path; *q; q++)
                            if (*q == '/') seg = q + 1;   /* son '/ sonrasi parcasi */
                        const char* dot = strrchr(seg, '.');
                        if (!seg[0]) {                     /* yol bos: host.html */
                            int h = 0; while (host[h] && h < 33) { name[h] = host[h]; h++; }
                            memcpy(name + h, ".html", 6);
                        } else if (dot && dot != seg) {
                            int l = 0; while (seg[l] && l < 39) { name[l] = seg[l]; l++; }
                            name[l] = 0;
                        } else {
                            int l = 0; while (seg[l] && l < 34) { name[l] = seg[l]; l++; }
                            memcpy(name + l, ".html", 6);
                        }
                    }
                    if (fs::write_file(cwd, name, body, bl)) {
                        kprintf("kaydedildi: %s (%u bayt)\n", name, bl);
                        uint32_t got = 0;
                        if (fs::read_file(cwd, name, buf, sizeof(buf), &got) && got == bl) {
                            uint32_t v = 2166136261u;
                            for (uint32_t i = 0; i < got; i++) { v ^= (uint8_t)buf[i]; v *= 16777619u; }
                            kprintf("disk dogrulama: %s (%08X)\n", (v == fnv) ? "OK" : "BOZUK", v);
                        } else {
                            kprintf("disk dogrulama: okunamadi\n");
                        }
                    } else
                        kprintf("hata: '%s' yazilamadi\n", name);
                    p = body;
                    int shown = 0;
                    while (*p && shown < 8192) {
                        if (*p != '\r') {
                            if (*p == '\n') kprintf("  | ");
                            else kprintf("%c", *p);
                            shown++;
                        }
                        p++;
                    }
                    if (*p) kprintf("  | ... (%u baytin ilk %u bayti)\n", bl, shown);
                    kprintf("\n");
                }
            }
        }
    }
    else if (strcmp(cmd, "httpd") == 0) {
        if (!net_active()) kprintf("hata: ag arayuzu yok\n");
        else {
            uint16_t port = 8080;
            if (t.n >= 2) {
                uint32_t pv = 0; const char* ps = t.tok[1];
                while (*ps >= '0' && *ps <= '9') { pv = pv * 10u + (uint32_t)(*ps - '0'); ps++; }
                if (pv > 0 && pv < 65536) port = (uint16_t)pv;
            }
            int lfd = net_socket();
            if (lfd < 0) { kprintf("httpd: soket yok\n"); }
            else if (!net_tcp_listen(lfd, port)) kprintf("httpd: dinleme basarisiz\n");
            else {
                kprintf("httpd: %u portunda dinleniyor...\n", port);
                for (;;) {
                    if (sys_intr_pending()) { kprintf("httpd: iptal edildi\n"); break; }
                    int cfd = net_tcp_accept(lfd, 0);      /* 0 = sonsuz bekleyis; Ctrl+C iptal eder */
                    if (cfd < 0) {
                        if (sys_intr_pending()) { sys_intr_clear(); kprintf("httpd: iptal edildi\n"); }
                        else kprintf("httpd: accept hatasi\n");
                        break;
                    }
                    /* Istek basligini topla ("\r\n\r\n" a kadar) */
                    static char req[4096];
                    uint32_t rn = 0;
                    int empty = 0;
                    uint64_t req_wall = timer_get_ticks() + 300;
                    while (rn < sizeof(req) - 1 && timer_get_ticks() < req_wall && !sys_intr_pending()) {
                        uint8_t c;
                        if (net_tcp_recv_some(cfd, &c, 1, 5) == 1) {
                            req[rn++] = (char)c;
                            if (c == '\n') empty++;
                            else if (c != '\r') empty = 0;
                            if (empty >= 2) break;
                        } else if (net_tcp_done(cfd) || net_tcp_err(cfd)) break;
                    }
                    req[rn] = 0;
                    kprintf("httpd: geldi (%u bayt)\n", rn);
                    /* Yolu cikar: "GET /pat HTTP/1.1" */
                    char path[256] = "/";
                    if (req[0] == 'G' && req[1] == 'E' && req[2] == 'T') {
                        const char* s = req + 4;
                        while (*s == ' ') s++;
                        int pl = 0;
                        while (*s && *s != ' ' && pl < 254) path[pl++] = *s++;
                        if (pl) path[pl] = 0;
                    }
                    fs::EntryInfo st;
                    char body[8192];
                    uint32_t bl = 0;
                    static char resp[9000];
                    int rlen = 0;
                    const char* ctype = "text/plain";
                    if (fs::stat(0, path, &st) && st.type_ == 1) {
                        if (!fs::read_file(0, path, body, sizeof(body), &bl)) { bl = 0; }
                        rlen = ksnprintf(resp, sizeof(resp),
                            "HTTP/1.0 200 OK\r\nContent-Type: %s\r\nContent-Length: %u\r\n\r\n",
                            ctype, bl);
                        memcpy(resp + rlen, body, bl > 0 ? bl : 0);
                        rlen += (int)bl;
                    } else {
                        rlen = ksnprintf(resp, sizeof(resp),
                            "HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n");
                    }
                    /* Govdeyi segmentlere bolerek gonder */
                    uint32_t off = 0;
                    while (off < (uint32_t)rlen && !sys_intr_pending()) {
                        uint32_t chunk = (uint32_t)(rlen - off);
                        if (chunk > 1460) chunk = 1460;
                        net_tcp_send(cfd, (const uint8_t*)resp + off, (uint16_t)chunk);
                        net_tcp_wait(cfd, 10);
                        off += chunk;
                    }
                    kprintf("httpd: %u bayt yanit gonderildi\n", rlen);
                    net_tcp_close(cfd);
                    sys_intr_clear();
                }
            }
        }
    }
    else if (strcmp(cmd, "nettest") == 0) {
        if (!net_active()) {
            kprintf("nettest: FAIL (ag arayuzu yok)\n");
        } else {
            int step = 0;
            bool ok = true;
            uint32_t gw = net_get_gw();
            kprintf("nettest: adim1 ping %u.%u.%u.%u ...\n",
                    (gw >> 24) & 0xFF, (gw >> 16) & 0xFF, (gw >> 8) & 0xFF, gw & 0xFF);
            if (!net_ping(gw)) { ok = false; step = 1; }

            if (ok) {
                kprintf("nettest: adim1b ip parcalama/birlestirme ...\n");
                if (!net_frag_selftest()) { ok = false; step = 5; }
            }

            if (ok) {
                kprintf("nettest: adim1c ip gonderim parcalama ...\n");
                if (!net_frag_send_selftest()) { ok = false; step = 6; }
            }

            if (ok) {
                kprintf("nettest: adim1d rx hardening (checksum + ip options) ...\n");
                if (!net_rx_harden_selftest()) { ok = false; step = 7; }
            }

            if (ok) {
                kprintf("nettest: adim1e fast recovery + limited transmit ...\n");
                if (!net_fast_recovery_selftest()) { ok = false; step = 8; }
            }

            if (ok) {
                kprintf("nettest: adim1f ws/ts + nagle + keepalive ...\n");
                if (!net_tcp_ext_selftest()) { ok = false; step = 9; }
            }

            uint32_t dip = 0;
            if (ok) {
                kprintf("nettest: adim2 dns google.com ...\n");
                if (!net_dns_resolve("google.com", &dip)) { ok = false; step = 2; }
            }
            uint32_t eip = 0;
            if (ok) {
                kprintf("nettest: adim3 dns example.com ...\n");
                if (!net_dns_resolve("example.com", &eip)) { ok = false; step = 3; }
            }
            if (ok) {
                static char hb[2048];
                kprintf("nettest: adim4 http example.com/ ...\n");
                if (!net_http_get(eip, 80, "example.com", "/", hb, sizeof(hb))) { ok = false; step = 4; }
            }

            if (ok) kprintf("nettest: PASS\n");
            else    kprintf("nettest: FAIL (adim %d)\n", step);
        }
    }
    else if (strcmp(cmd, "ping") == 0) {
        if (t.n < 2) kprintf("kullanim: ping <a.b.c.d>\n");
        else {
            bool ok = false;
            uint32_t ip = net_parse_ip(t.tok[1], &ok);
            if (!ok) { kprintf("hata: gecersiz IP\n"); }
            else if (!net_active()) { kprintf("hata: ag arayuzu yok\n"); }
            else {
                kprintf("PING %s (64 bayt):\n", t.tok[1]);
                if (net_ping(ip))
                    kprintf("cevap! %s makinesinden\n", t.tok[1]);
                else
                    kprintf("zaman asimi (cevap yok)\n");
            }
        }
    }
    else if (strcmp(cmd, "reboot") == 0) {
        kprintf("yeniden baslatiliyor...\n");
        outw(0xCF9, 0x06);
        for (;;) cpu_hlt();
    }
    else if (strcmp(cmd, "poweroff") == 0 || strcmp(cmd, "exit") == 0) {
        kprintf("kapatiliyor...\n");
        outw(0x604, 0x2000);
        outw(0xB004, 0x2000);
        for (;;) cpu_hlt();
    }
    else kprintf("bilinmeyen komut: %s ('help' yazin)\n", cmd);
    return;
}

/* Tek komutu yonlendirmeyle calistirir. pipe_in != NULL ise komut giris olarak
   onu kullanicidan okur (filtre). */
static void run_cmd(char* line, uint32_t& cwd, char* cwdstr, const char* pipe_in) {
    static char rpath[64];
    int rmode = 0;
    bool has = extract_redirect(line, rpath, sizeof(rpath), &rmode);

    if (!has) { run_line_inner(line, cwd, cwdstr, pipe_in); return; }

    static char capbuf[8192];
    int caplen = 0;
    output_capture_begin(capbuf, sizeof(capbuf), &caplen);
    run_line_inner(line, cwd, cwdstr, pipe_in);
    output_capture_end();

    bool ok = (rmode == 2)
              ? fs::append_file(cwd, rpath, capbuf, (uint32_t)caplen)
              : fs::write_file(cwd, rpath, capbuf, (uint32_t)caplen);

    if (!ok) kprintf("hata: '%s' yonlendirilemedi\n", rpath);
    else if (rmode == 1) kprintf("(%d bayt yazildi: %s)\n", caplen, rpath);
}

/* cmd1 | cmd2 | ... pipe zinciri: her komutun ciktisini yakalar, sonraki komuta
   stdin olarak verir. Cift tampon (ping-pong) kullanir; son komut ciktisini
   normal (redirect destekli) basar. */
static void run_pipe_chain(uint32_t& cwd, char* cwdstr, char* segs[], int nsegs) {
    static char capA[8192], capB[8192];
    const char* prev = NULL;
    for (int i = 0; i < nsegs; i++) {
        if (i == nsegs - 1) {                /* son komut: cikti ekrana/dosyaya */
            run_cmd(segs[i], cwd, cwdstr, prev);
            return;
        }
        char* dst = (i % 2 == 0) ? capA : capB;
        int plen = 0;
        output_capture_begin(dst, 8192, &plen);
        run_line_inner(segs[i], cwd, cwdstr, prev);
        output_capture_end();
        dst[plen] = 0;
        prev = dst;
    }
}

/* Genel komut isleyici: pipe ( | ) ve yonlendirme (> / >>) destegi. */
static void run_line(char* line, uint32_t& cwd, char* cwdstr) {
    /* pipe tokenlarini bul (boslukla cevrili turleri dahil) */
    enum { MAXP = 8 };
    char* pipes[MAXP];
    int np = 0;
    {
        bool in_tok = false;
        for (char* p = line; *p; p++) {
            if (*p == ' ') { in_tok = false; continue; }
            if (in_tok) continue;
            if (*p == '|') {
                if (np < MAXP) pipes[np] = p;
                np++;
                continue;
            }
            in_tok = true;
        }
    }

    if (np == 0) { run_cmd(line, cwd, cwdstr, NULL); return; }

    /* her | konumunu NUL yap, segmentleri topla */
    for (int k = 0; k < np; k++) *pipes[k] = 0;
    char* segs[MAXP + 1];
    int nsegs = 0;
    segs[nsegs++] = line;
    {
        char* p = line;
        int read = 0;
        while (read < np) {
            while (read < np && pipes[read] < p) read++;
            if (read >= np) break;
            p = pipes[read] + 1;
            read++;
            while (*p == ' ') p++;
            segs[nsegs++] = p;
        }
    }
    for (int i = 0; i < nsegs; i++) {
        char* e = segs[i] + strlen(segs[i]);
        while (e > segs[i] && e[-1] == ' ') *--e = 0;
    }

    run_pipe_chain(cwd, cwdstr, segs, nsegs);
}

void read_line(char* line, int max) {
    static char hist[32][256];
    static int hist_count = 0;
    static int hist_browse = -1;

    int pos = 0;
    line[0] = 0;
    char c;
    for (;;) {
        if (sys_intr_pending()) {
            sys_intr_clear();
            vga_putc('\n');
            serial_putc('\r'); serial_putc('\n');
            line[0] = 0;
            return;
        }
        if (keyboard_has_char())       c = keyboard_getc();
        else if (serial_has_char())    c = serial_getc();
        else { cpu_hlt(); continue; }

        if (c == (char)0x80) {
            if (hist_count > 0 && hist_browse < hist_count - 1) {
                int old_pos = pos;
                hist_browse++;
                for (int i = 0; i < old_pos; i++) { vga_putc('\b'); serial_putc('\b'); }
                strncpy(line, hist[hist_browse], max - 1);
                line[max - 1] = 0;
                pos = (int)strlen(line);
                for (int i = 0; i < pos; i++) { vga_putc(line[i]); serial_putc(line[i]); }
                if (pos < old_pos) {
                    for (int i = pos; i < old_pos; i++) { vga_putc(' '); serial_putc(' '); }
                    for (int i = pos; i < old_pos; i++) { vga_putc('\b'); serial_putc('\b'); }
                }
            }
            continue;
        }
        if (c == (char)0x81) {
            if (hist_browse >= 0) {
                int old_pos = pos;
                for (int i = 0; i < old_pos; i++) { vga_putc('\b'); serial_putc('\b'); }
                if (hist_browse > 0) {
                    hist_browse--;
                    strncpy(line, hist[hist_browse], max - 1);
                    line[max - 1] = 0;
                    pos = (int)strlen(line);
                } else {
                    hist_browse = -1;
                    line[0] = 0;
                    pos = 0;
                }
                for (int i = 0; i < pos; i++) { vga_putc(line[i]); serial_putc(line[i]); }
                if (pos < old_pos) {
                    for (int i = pos; i < old_pos; i++) { vga_putc(' '); serial_putc(' '); }
                    for (int i = pos; i < old_pos; i++) { vga_putc('\b'); serial_putc('\b'); }
                }
            }
            continue;
        }
        if (c == (char)0x82 || c == (char)0x83) continue;

        if (c == '\r' || c == '\n') {
            vga_putc('\n');
            serial_putc('\r'); serial_putc('\n');
            if (pos > 0) {
                for (int i = 31; i > 0; i--) { strncpy(hist[i], hist[i-1], 255); hist[i][255] = 0; }
                strncpy(hist[0], line, 255);
                hist[0][255] = 0;
                if (hist_count < 32) hist_count++;
            }
            hist_browse = -1;
            line[pos] = 0;
            return;
        }
        if (c == '\b') {
            if (pos > 0) {
                pos--;
                vga_putc('\b');
                serial_putc('\b');
            }
            hist_browse = -1;
            continue;
        }
        if (c == 0 || c < 32) continue;

        hist_browse = -1;
        if (pos < max - 2) {
            line[pos++] = c;
            line[pos] = 0;
            vga_putc(c);
            serial_putc(c);
        }
    }
}

} /* namespace */

void shell_run(void) {
    uint32_t cwd = 0;
    char cwdstr[128];
    strcpy(cwdstr, "/");

    kprintf("\n");
    set_color(VGA_FG(VGA_BLACK, VGA_LIGHT_CYAN));
    kprintf(" ###############################################\n");
    kprintf(" #  cofeuos 0.1 - x86_64 toy OS                #\n");
    kprintf(" #  assembly + C + C++                         #\n");
    kprintf(" #  'help' yazarak komutlari gorebilirsin      #\n");
    kprintf(" ###############################################\n");
    rst_color();
    kprintf("\n");

    char line[256];
    for (;;) {
        set_color(VGA_FG(VGA_BLACK, VGA_LIGHT_GREEN));
        if (strcmp(cwdstr, "/") == 0)
            kprintf("cofeuos:/$ ");
        else
            kprintf("cofeuos:%s$ ", cwdstr);
        rst_color();
        read_line(line, sizeof(line));
        if (line[0]) run_line(line, cwd, cwdstr);
    }
}