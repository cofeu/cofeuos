#include "kernel.h"
#include "x86.h"
#include "pmm.h"
#include "sched.h"

namespace {

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
    "  mkdir <yol>              - dizin olustur\n"
    "  touch <yol>              - bos dosya olustur\n"
    "  echo <metin>             - metni yazdir\n"
    "  echo <metin> > <dosya>   - dosyaya yaz (ustune)\n"
    "  echo <metin> >> <dosya>  - dosyaya ekle\n"
    "  cat <dosya>              - dosyayi oku\n"
    "  xxd <dosya>              - hexdump\n"
    "  rm [-r] <yol>            - dosya/dizin sil\n"
    "  lsfs                     - dosya sistemi bilgisi\n"
    "  uptime                   - calisma suresi\n"
    "  ver                      - surum bilgisi\n"
    "  mem                      - bellek kullanimi\n"
    "  ps                       - surec listesi\n"
    "  kill <pid>               - sureci oldur\n"
    "  spawn <ad>               - yeni surec baslat\n"
    "  reboot                   - yeniden baslat\n"
    "  poweroff                 - kapat\n";

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
        kprintf("%-31s <DIZIN>\n", e.name_);
    } else {
        kprintf("%-31s    %u bayt\n", e.name_, e.size_);
    }
}

bool cmd_echo(Tokens& t, uint32_t cwd) {
    if (t.n < 2) { kprintf("\n"); return true; }

    /* kirmizi isaretci ara: > veya >> */
    int redir = -1;
    bool append = false;
    for (int i = 1; i < t.n; i++) {
        if (strcmp(t.tok[i], ">") == 0)    { redir = i; append = false; break; }
        if (strcmp(t.tok[i], ">>") == 0)   { redir = i; append = true; break; }
    }

    if (redir < 0) {
        for (int i = 1; i < t.n; i++) {
            if (i > 1) kprintf(" ");
            kprintf("%s", t.tok[i]);
        }
        kprintf("\n");
        return true;
    }

    if (redir + 1 >= t.n) { kprintf("hata: dosya adi eksik\n"); return true; }

    /* dosya yolu */
    const char* file = t.tok[redir + 1];
    for (int i = redir + 2; i < t.n; i++) {
        kprintf("uyari: fazla arguman '%s' yok sayildi\n", t.tok[i]);
    }

    /* icerik */
    static char content[256];
    int pos = 0;
    for (int i = 1; i < redir; i++) {
        int l = (int)strlen(t.tok[i]);
        if (pos + l + 1 >= (int)sizeof(content)) break;
        if (pos && i > 1) content[pos++] = ' ';
        for (int j = 0; j < l; j++) content[pos++] = t.tok[i][j];
    }
    content[pos] = 0;

    if (append) {
        if (!fs::append_file(cwd, file, content, (uint32_t)pos))
            kprintf("hata: ekleme basarisiz\n");
    } else {
        if (!fs::write_file(cwd, file, content, (uint32_t)pos))
            kprintf("hata: yazma basarisiz\n");
        else
            kprintf("(%u bayt yazildi: %s)\n", (uint32_t)pos, file);
    }
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

bool run_line(char* line, uint32_t& cwd, char* cwdstr) {
    Tokens t;
    tokenize(line, t);
    if (t.n == 0) return true;

    const char* cmd = t.tok[0];

    if      (strcmp(cmd, "help") == 0)     kprintf("%s", HELP);
    else if (strcmp(cmd, "clear") == 0)    vga_clear();
    else if (strcmp(cmd, "cls") == 0)      vga_clear();
    else if (strcmp(cmd, "ver") == 0)      kprintf("%s (gcc %s)\n", KERNEL_VERSION, __VERSION__);
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
        if (t.n < 2) kprintf("kullanim: cat <dosya>\n");
        else {
            static char buf[12288];
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
    else if (strcmp(cmd, "xxd") == 0) {
        if (t.n < 2) kprintf("kullanim: xxd <dosya>\n");
        else cmd_xxd(t.tok[1], cwd);
    }
    else if (strcmp(cmd, "rm") == 0) {
        bool rec = false;
        int idx = 1;
        if (t.n >= 2 && strcmp(t.tok[1], "-r") == 0) { rec = true; idx = 2; }
        if (t.n <= idx) kprintf("kullanim: rm [-r] <yol>\n");
        else if (!fs::remove_file(cwd, t.tok[idx], rec)) kprintf("hata: silinemedi\n");
    }
    else if (strcmp(cmd, "lsfs") == 0)     cmd_lsfs();
    else if (strcmp(cmd, "uptime") == 0)   kprintf("calisma suresi: %llu sn\n", timer_get_seconds());
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
        int pid = sched_spawn(nm, 'x', 200, 0);
        if (pid < 0) kprintf("hata: baslatilamadi (tablo dolu)\n");
        else kprintf("baslatildi pid=0x%04X (%d)\n", (uint16_t)pid, pid);
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
    return true;
}

void read_line(char* line, int max) {
    int pos = 0;
    line[0] = 0;
    char c;
    for (;;) {
        if (keyboard_has_char())       c = keyboard_getc();
        else if (serial_has_char())    c = serial_getc();
        else { cpu_hlt(); continue; }
        if (c == '\r' || c == '\n') {
            vga_putc('\n');
            serial_putc('\r'); serial_putc('\n');
            line[pos] = 0;
            return;
        }
        if (c == '\b') {
            if (pos > 0) {
                pos--;
                vga_putc('\b');
                serial_putc('\b');
            }
            continue;
        }
        if (c == 0 || c < 32) continue;
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
    kprintf(" ###############################################\n");
    kprintf(" #  cofeuos 0.1 - x86_64 toy OS                #\n");
    kprintf(" #  assembly + C + C++                         #\n");
    kprintf(" #  'help' yazarak komutlari gorebilirsin      #\n");
    kprintf(" ###############################################\n");
    kprintf("\n");

    char line[256];
    for (;;) {
        if (strcmp(cwdstr, "/") == 0)
            kprintf("cofeuos:/$ ");
        else
            kprintf("cofeuos:%s$ ", cwdstr);
        read_line(line, sizeof(line));
        if (line[0]) run_line(line, cwd, cwdstr);
    }
}