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