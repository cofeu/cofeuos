#include "kernel.h"

/*
 * cofeufs - cofeuos icin basit blok tabanli dosya sistemi.
 *
 *   LBA 0        : boot sector
 *   LBA 1..2047  : kernel goruntu
 *   LBA 2048     : superblock (1 blok)
 *   LBA 2050..   : blok bitmap (16 blok, ~64K veri blogu izler)
 *   LBA 2066..   : inode tablosu (64 blok -> 256 inode, 128B adet)
 *   LBA 2130..   : veri bloklari (512B)
 *
 * Inode (128B): name[32] u16 type u16 rsv u32 size u32 blocks[22]
 * Dizin girdisi (40B): u32 ino char name[32] u8 type u8 pad[3]  (12/blok)
 */

namespace fs {

/* ---- disk duzeni sabitleri ---- */
constexpr uint32_t SB_LBA      = 2048;
constexpr uint32_t BM_LBA      = 2050;
constexpr uint32_t BM_BLOCKS   = 16;
constexpr uint32_t INO_LBA     = 2066;
constexpr uint32_t INO_BLOCKS  = 64;
constexpr uint32_t DATA_LBA    = 2130;
constexpr uint32_t DISK_BLOCKS = 67584;
constexpr uint32_t DATA_COUNT  = DISK_BLOCKS - DATA_LBA;

constexpr uint16_t FT_FREE = 0;
constexpr uint16_t FT_FILE = 1;
constexpr uint16_t FT_DIR  = 2;

constexpr uint32_t INO_SIZE    = 128;
constexpr uint32_t INO_PER_BLK = 512 / INO_SIZE;      /* 4 */
constexpr uint32_t INO_COUNT   = INO_BLOCKS * INO_PER_BLK;
constexpr uint32_t MAX_BLOCKS  = 22;
constexpr uint32_t MAX_FILE    = MAX_BLOCKS * 512;

constexpr uint32_t DE_SIZE    = 40;
constexpr uint32_t DE_PER_BLK = 512 / DE_SIZE;         /* 12 */

struct __attribute__((packed)) SuperBlock {
    char magic[8];
    uint32_t fs_start;
    uint32_t fs_blocks;
    uint32_t bm_lba;
    uint32_t bm_blocks;
    uint32_t ino_lba;
    uint32_t ino_blocks;
    uint32_t data_lba;
    uint32_t data_blocks;
    uint32_t ino_per_blk;
    uint32_t ino_count;
    uint32_t root_ino;
    uint32_t pad[3];
};

struct __attribute__((packed)) Inode {
    char name[32];
    uint16_t type;
    uint16_t rsv;
    uint32_t size;
    uint32_t blocks[MAX_BLOCKS];
};

struct __attribute__((packed)) DirEntry {
    uint32_t ino;
    char name[32];
    uint8_t type;
    uint8_t pad[3];
};

static_assert(sizeof(SuperBlock) <= 512, "superblock fits in sector");
static_assert(sizeof(Inode) == INO_SIZE, "inode size");
static_assert(sizeof(DirEntry) == DE_SIZE, "direntry size");

/* ---- durum ---- */
static SuperBlock super;
static uint8_t bm[512 * BM_BLOCKS];
static uint8_t sec[512];
static bool mounted = false;

/* ---- disk IO ---- */
static void disk_read(uint32_t lba, void* buf) { ata_read_sector(lba, buf); }
static void disk_write(uint32_t lba, const void* buf) { ata_write_sector(lba, buf); }

/* ---- superblock ---- */
static bool read_super(void) {
    disk_read(SB_LBA, sec);
    memcpy(&super, sec, sizeof(SuperBlock));
    return memcmp(super.magic, "COFEUFS1", 8) == 0;
}

static void write_super(void) {
    memset(sec, 0, 512);
    memcpy(sec, &super, sizeof(SuperBlock));
    disk_write(SB_LBA, sec);
}

/* ---- inode okuma/yazma ---- */
static void inode_read(uint32_t n, Inode& out) {
    uint32_t blk = INO_LBA + (n / INO_PER_BLK);
    disk_read(blk, sec);
    memcpy(&out, sec + (n % INO_PER_BLK) * INO_SIZE, INO_SIZE);
}

static void inode_write(uint32_t n, const Inode& in) {
    uint32_t blk = INO_LBA + (n / INO_PER_BLK);
    uint32_t off = (n % INO_PER_BLK) * INO_SIZE;
    disk_read(blk, sec);
    memcpy(sec + off, &in, INO_SIZE);
    disk_write(blk, sec);
}

/* ---- bitmap ---- */
static void bm_read(void) {
    for (uint32_t i = 0; i < BM_BLOCKS; i++)
        disk_read(BM_LBA + i, bm + i * 512);
}

static void bm_flush(void) {
    for (uint32_t i = 0; i < BM_BLOCKS; i++)
        disk_write(BM_LBA + i, bm + i * 512);
}

static bool block_alloc(uint32_t& idx) {
    for (uint32_t i = 0; i < DATA_COUNT; i++) {
        if (!(bm[i >> 3] & (1 << (i & 7)))) {
            bm[i >> 3] |= (uint8_t)(1 << (i & 7));
            idx = i;
            return true;
        }
    }
    return false;
}

static void block_free(uint32_t n) {
    if (n >= DATA_COUNT) return;
    bm[n >> 3] &= (uint8_t)~(1 << (n & 7));
}

static void inode_free_blocks(Inode& in) {
    for (uint32_t i = 0; i < MAX_BLOCKS; i++) {
        if (in.blocks[i] != 0xFFFFFFFF && in.blocks[i] < DATA_COUNT) {
            block_free(in.blocks[i]);
            in.blocks[i] = 0xFFFFFFFF;
        }
    }
}

static void inode_reset(Inode& in) {
    for (uint32_t i = 0; i < MAX_BLOCKS; i++) in.blocks[i] = 0xFFFFFFFF;
}

/* ---- dizin girdileri (slot) ---- */
static uint32_t dir_used(const Inode& d) { return d.size / DE_SIZE; }

static bool dir_slot_read(const Inode& d, uint32_t slot, DirEntry& e) {
    uint32_t blk = slot / DE_PER_BLK;
    uint32_t off = (slot % DE_PER_BLK) * DE_SIZE;
    if (blk >= MAX_BLOCKS || d.blocks[blk] == 0xFFFFFFFF) return false;
    disk_read(DATA_LBA + d.blocks[blk], sec);
    memcpy(&e, sec + off, DE_SIZE);
    return true;
}

static bool dir_slot_write(const Inode& d, uint32_t slot, const DirEntry& e) {
    uint32_t blk = slot / DE_PER_BLK;
    uint32_t off = (slot % DE_PER_BLK) * DE_SIZE;
    if (blk >= MAX_BLOCKS || d.blocks[blk] == 0xFFFFFFFF) return false;
    disk_read(DATA_LBA + d.blocks[blk], sec);
    memcpy(sec + off, &e, DE_SIZE);
    disk_write(DATA_LBA + d.blocks[blk], sec);
    return true;
}

static bool dir_find(const Inode& d, const char* name, DirEntry& out, uint32_t& slot_out) {
    uint32_t n = dir_used(d);
    for (uint32_t i = 0; i < n; i++) {
        DirEntry e;
        if (!dir_slot_read(d, i, e)) break;
        if (e.ino && strcmp(e.name, name) == 0) {
            out = e;
            slot_out = i;
            return true;
        }
    }
    return false;
}

static bool dir_add(uint32_t dirino, const char* name, uint32_t newino, uint16_t type) {
    Inode d;
    inode_read(dirino, d);
    if (d.type != FT_DIR) return false;

    /* bos slot var mi? */
    uint32_t n = dir_used(d);
    for (uint32_t i = 0; i < n; i++) {
        DirEntry e;
        if (!dir_slot_read(d, i, e)) break;
        if (e.ino == 0) {
            e.ino = newino;
            e.type = (uint8_t)type;
            strncpy(e.name, name, 31);
            e.name[31] = 0;
            return dir_slot_write(d, i, e);
        }
    }

    /* sona ekle; gerekirse yeni veri blogu ayir */
    uint32_t slot = n;
    uint32_t blk = slot / DE_PER_BLK;
    uint32_t off = (slot % DE_PER_BLK) * DE_SIZE;
    if (blk >= MAX_BLOCKS) return false;

    if (d.blocks[blk] == 0xFFFFFFFF) {
        uint32_t idx;
        if (!block_alloc(idx)) return false;
        d.blocks[blk] = idx;
        memset(sec, 0, 512);
        disk_write(DATA_LBA + idx, sec);
    }

    DirEntry e;
    memset(&e, 0, sizeof(e));
    e.ino = newino;
    e.type = (uint8_t)type;
    strncpy(e.name, name, 31);
    e.name[31] = 0;
    disk_read(DATA_LBA + d.blocks[blk], sec);
    memcpy(sec + off, &e, DE_SIZE);
    disk_write(DATA_LBA + d.blocks[blk], sec);

    d.size += DE_SIZE;
    inode_write(dirino, d);
    bm_flush();
    return true;
}

static bool dir_remove(uint32_t dirino, const char* name) {
    Inode d;
    inode_read(dirino, d);
    if (d.type != FT_DIR) return false;
    uint32_t slot;
    DirEntry e;
    if (!dir_find(d, name, e, slot)) return false;
    DirEntry empty;
    memset(&empty, 0, sizeof(empty));
    return dir_slot_write(d, slot, empty);
}

/* ---- yol cozumu ---- */
static bool resolve_from(uint32_t base, const char* path, uint32_t* out) {
    if (!path) { *out = base; return true; }
    uint32_t cur = (*path == '/') ? super.root_ino : base;
    const char* p = path;
    if (*p == '/') p++;

    for (;;) {
        if (*p == 0) { *out = cur; return true; }
        char comp[32];
        int len = 0;
        while (*p && *p != '/' && len < 31) comp[len++] = *p++;
        while (*p == '/') p++;
        if (len == 0) { if (*p == 0) { *out = cur; return true; } continue; }
        comp[len] = 0;

        if (strcmp(comp, ".") == 0) continue;
        Inode d;
        inode_read(cur, d);
        if (d.type != FT_DIR) return false;
        uint32_t slot;
        DirEntry e;
        if (!dir_find(d, comp, e, slot)) return false;
        cur = e.ino;
    }
}

/* /parent/name ayirimi; parent inode = parent. Mutlak yollar kokten cozulur. */
static bool split_last(uint32_t base, const char* path,
                       uint32_t* parent, char* name_out) {
    if (!path || !path[0]) return false;

    const char* last = NULL;
    for (const char* p = path; *p; p++)
        if (*p == '/') last = p;

    if (last) {
        const char* after = last + 1;
        if (!*after) return false;                      /* son "/" sonrasi bos */
        size_t dl = (size_t)(last - path);
        if (dl >= 95) return false;
        char dirpart[96];
        memcpy(dirpart, path, dl);
        dirpart[dl] = 0;
        if (*path == '/' && dl == 0) {
            *parent = super.root_ino;                   /* /name  -> kok */
        } else {
            if (!resolve_from(base, dirpart, parent)) return false;
        }
        size_t nl = strlen(after);
        if (nl > 31) return false;
        strcpy(name_out, after);
    } else {
        *parent = base;                                 /* yalniz ad */
        size_t nl = strlen(path);
        if (nl > 31) return false;
        strcpy(name_out, path);
    }
    return true;
}

/* ---- ilk kurulum (format) ---- */
static bool format(void) {
    memset(bm, 0, sizeof(bm));
    memset(&super, 0, sizeof(SuperBlock));
    memcpy(super.magic, "COFEUFS1", 8);
    super.fs_start    = SB_LBA;
    super.fs_blocks   = DISK_BLOCKS - SB_LBA;
    super.bm_lba      = BM_LBA;
    super.bm_blocks   = BM_BLOCKS;
    super.ino_lba     = INO_LBA;
    super.ino_blocks  = INO_BLOCKS;
    super.data_lba    = DATA_LBA;
    super.data_blocks = DATA_COUNT;
    super.ino_per_blk = INO_PER_BLK;
    super.ino_count   = INO_COUNT;
    super.root_ino    = 0;

    memset(sec, 0, 512);
    for (uint32_t i = 0; i < INO_BLOCKS; i++) disk_write(INO_LBA + i, sec);

    /* kok dizin inode #0 */
    Inode root;
    memset(&root, 0, sizeof(root));
    strcpy(root.name, "/");
    root.type = FT_DIR;
    root.size = 2 * DE_SIZE;
    inode_reset(root);
    root.blocks[0] = 0;
    bm[0] |= 1;                                  /* data blok 0: kok dizin */
    inode_write(0, root);

    /* "." ve ".." girdileri */
    DirEntry dot{0, {0}, FT_DIR, {0, 0, 0}};     strcpy(dot.name, ".");
    DirEntry ddot{0, {0}, FT_DIR, {0, 0, 0}};    strcpy(ddot.name, "..");
    memset(sec, 0, 512);
    memcpy(sec + 0,      &dot, DE_SIZE);
    memcpy(sec + DE_SIZE, &ddot, DE_SIZE);
    disk_write(DATA_LBA + 0, sec);

    write_super();
    bm_flush();
    return true;
}

/* ---- cocuk inode'u degilsek, recursive silme - */
static void remove_inode_by_ino(uint32_t ino, bool recursive);

/* ---- genel API ---- */
bool mount(void) {
    if (!read_super()) {
        kprintf("fs: cofeufs yok, formatlaniyor...\n");
        format();
        if (!read_super()) return false;
    }
    bm_read();
    mounted = true;
    return true;
}

uint32_t disk_blocks(void) { return DISK_BLOCKS; }

bool resolve(uint32_t base, const char* path, uint32_t* out) {
    if (!mounted) return false;
    return resolve_from(base, path, out);
}

bool stat(uint32_t base, const char* path, EntryInfo* out) {
    if (!mounted) return false;
    uint32_t ino;
    if (!resolve_from(base, path, &ino)) return false;
    Inode in;
    inode_read(ino, in);
    out->type_ = (uint8_t)in.type;
    out->size_ = in.size;
    strncpy(out->name_, in.name, 32);
    out->name_[31] = 0;
    return true;
}

void list(uint32_t base, const char* path,
          void (*cb)(const EntryInfo&, void*), void* ctx) {
    if (!mounted) return;
    uint32_t ino;
    if (!resolve_from(base, path, &ino)) return;
    Inode d;
    inode_read(ino, d);
    if (d.type != FT_DIR) return;
    uint32_t n = dir_used(d);
    for (uint32_t i = 0; i < n; i++) {
        DirEntry e;
        if (!dir_slot_read(d, i, e)) break;
        if (!e.ino) continue;
        Inode ci;
        inode_read(e.ino, ci);
        EntryInfo info;
        info.type_ = e.type;
        info.size_ = ci.size;
        strncpy(info.name_, e.name, 32);
        info.name_[31] = 0;
        cb(info, ctx);
    }
}

/* -------- olusturma -------- */
static bool create_inode(uint32_t base, const char* path, bool is_dir) {
    if (!mounted) return false;
    uint32_t parent;
    char name[32];
    if (!split_last(base, path, &parent, name)) return false;

    uint32_t existing;
    if (resolve_from(base, path, &existing)) return false;   /* varken yok */

    uint32_t ino = 0xFFFFFFFF;
    for (uint32_t i = super.root_ino; i < super.ino_count; i++) {
        Inode t;
        inode_read(i, t);
        if (t.type == FT_FREE) { ino = i; break; }
    }
    if (ino == 0xFFFFFFFF) return false;

    Inode ni;
    memset(&ni, 0, sizeof(ni));
    strncpy(ni.name, name, 31);
    ni.name[31] = 0;
    ni.type = is_dir ? FT_DIR : FT_FILE;
    ni.size = 0;
    inode_reset(ni);

    if (is_dir) {
        uint32_t idx;
        if (!block_alloc(idx)) return false;
        ni.blocks[0] = idx;
        ni.size = 2 * DE_SIZE;
        DirEntry dot{ino, {0}, FT_DIR, {0, 0, 0}};   strcpy(dot.name, ".");
        DirEntry ddot{ino, {0}, FT_DIR, {0, 0, 0}};  strcpy(ddot.name, "..");
        memset(sec, 0, 512);
        memcpy(sec, &dot, DE_SIZE);
        memcpy(sec + DE_SIZE, &ddot, DE_SIZE);
        disk_write(DATA_LBA + idx, sec);
    }

    inode_write(ino, ni);
    if (!dir_add(parent, name, ino, ni.type)) {
        inode_free_blocks(ni);
        Inode z;
        memset(&z, 0, sizeof(z));
        inode_write(ino, z);
        return false;
    }
    return true;
}

bool create_file(uint32_t base, const char* path) { return create_inode(base, path, false); }
bool mkdir(uint32_t base, const char* path)       { return create_inode(base, path, true); }

/* -------- yazma / okuma -------- */
bool write_file(uint32_t base, const char* path, const void* data, uint32_t len) {
    if (!mounted) return false;
    uint32_t ino;
    if (!resolve_from(base, path, &ino)) {
        if (!create_file(base, path)) return false;
        if (!resolve_from(base, path, &ino)) return false;
    }
    Inode in;
    inode_read(ino, in);
    if (in.type != FT_FILE) return false;
    if (len > MAX_FILE) return false;

    inode_free_blocks(in);
    inode_reset(in);
    in.size = len;

    uint32_t need = (len + 511) / 512;
    for (uint32_t i = 0; i < need; i++) {
        uint32_t idx;
        if (!block_alloc(idx)) {
            inode_free_blocks(in);
            in.size = 0;
            inode_write(ino, in);
            bm_flush();
            return false;
        }
        in.blocks[i] = idx;
    }

    const uint8_t* src = (const uint8_t*)data;
    for (uint32_t i = 0; i < need; i++) {
        memset(sec, 0, 512);
        uint32_t chunk = 512;
        if (i == need - 1) chunk = len - i * 512;
        memcpy(sec, src + i * 512, chunk);
        disk_write(DATA_LBA + in.blocks[i], sec);
    }

    inode_write(ino, in);
    bm_flush();
    return true;
}

bool append_file(uint32_t base, const char* path, const void* data, uint32_t len) {
    if (!mounted) return false;
    uint32_t ino;
    if (!resolve_from(base, path, &ino)) return write_file(base, path, data, len);

    Inode in;
    inode_read(ino, in);
    if (in.type != FT_FILE) return false;
    if (in.size + len > MAX_FILE) return false;

    static uint8_t tmp[MAX_FILE];
    uint32_t cur = in.size;
    for (uint32_t i = 0; i < (cur + 511) / 512; i++) {
        uint32_t chunk = 512;
        if (i == (cur - 1) / 512) chunk = cur - i * 512;
        uint32_t lba = DATA_LBA + in.blocks[i];
        disk_read(lba, sec);
        memcpy(tmp + i * 512, sec, chunk);
    }
    memcpy(tmp + cur, data, len);
    return write_file(base, path, tmp, cur + len);
}

bool read_file(uint32_t base, const char* path, void* buf, uint32_t maxlen, uint32_t* out_len) {
    if (!mounted) return false;
    uint32_t ino;
    if (!resolve_from(base, path, &ino)) return false;
    Inode in;
    inode_read(ino, in);
    if (in.type != FT_FILE) return false;

    uint32_t to_read = in.size < maxlen ? in.size : maxlen;
    uint8_t* dst = (uint8_t*)buf;
    for (uint32_t i = 0; i < (to_read + 511) / 512; i++) {
        uint32_t chunk = 512;
        if (i == (to_read - 1) / 512) chunk = to_read - i * 512;
        uint32_t lba = DATA_LBA + in.blocks[i];
        disk_read(lba, sec);
        memcpy(dst + i * 512, sec, chunk);
    }
    if (out_len) *out_len = to_read;
    return true;
}

/* -------- silme -------- */
static bool remove_inode_recursive(uint32_t dirino, const char* name, bool recursive) {
    Inode d;
    inode_read(dirino, d);
    if (d.type != FT_DIR) return false;
    uint32_t slot;
    DirEntry e;
    if (!dir_find(d, name, e, slot)) return false;

    if (e.type == FT_DIR && !recursive) return false;   /* dizin icin -r gerek */

    Inode child;
    inode_read(e.ino, child);
    if (child.type == FT_DIR) {
        /* once cocuklari sil */
        uint32_t nc = dir_used(child);
        for (uint32_t i = 0; i < nc; i++) {
            DirEntry ce;
            if (!dir_slot_read(child, i, ce)) break;
            if (ce.ino == 0) continue;
            if (strcmp(ce.name, ".") == 0 || strcmp(ce.name, "..") == 0) continue;
            remove_inode_by_ino(ce.ino, recursive);
        }
    }
    inode_free_blocks(child);
    Inode z;
    memset(&z, 0, sizeof(z));
    inode_write(e.ino, z);

    dir_remove(dirino, name);
    bm_flush();
    return true;
}

static void remove_inode_by_ino(uint32_t ino, bool recursive) {
    if (!mounted) return;
    Inode child;
    inode_read(ino, child);
    if (child.type == FT_DIR) {
        uint32_t nc = dir_used(child);
        for (uint32_t i = 0; i < nc; i++) {
            DirEntry ce;
            if (!dir_slot_read(child, i, ce)) break;
            if (ce.ino == 0) continue;
            if (strcmp(ce.name, ".") == 0 || strcmp(ce.name, "..") == 0) continue;
            remove_inode_by_ino(ce.ino, recursive);
        }
    }
    inode_free_blocks(child);
    Inode z;
    memset(&z, 0, sizeof(z));
    inode_write(ino, z);
}

bool remove_file(uint32_t base, const char* path, bool recursive) {
    if (!mounted) return false;
    uint32_t parent;
    char name[32];
    if (!split_last(base, path, &parent, name)) return false;
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return false;
    return remove_inode_recursive(parent, name, recursive);
}

/* -------- otomatik test -------- */
void selftest(void) {
    kprintf("fs: selftest basliyor...\n");
    kslog("fs selftest\n");
    static const char* data = "cofeufs selftest: merhaba dunya!\n";
    uint32_t len = (uint32_t)strlen(data);

    uint32_t ino = 1;
    if (resolve(0, "/selftest.txt", &ino)) {
        kprintf("fs: FAIL - dosya zaten var\n");
        return;
    }
    if (!create_file(0, "/selftest.txt")) { kprintf("fs: FAIL - create\n"); return; }
    if (!write_file(0, "/selftest.txt", data, len)) { kprintf("fs: FAIL - write\n"); return; }

    static char buf[128];
    uint32_t got = 0;
    if (!read_file(0, "/selftest.txt", buf, sizeof(buf), &got) || got != len ||
        memcmp(buf, data, len) != 0) {
        kprintf("fs: FAIL - readback\n");
        return;
    }

    if (!append_file(0, "/selftest.txt", "ek:", 3)) { kprintf("fs: FAIL - append\n"); return; }
    static char buf2[160];
    uint32_t got2 = 0;
    read_file(0, "/selftest.txt", buf2, sizeof(buf2), &got2);
    if (got2 != len + 3 || memcmp(buf2 + len, "ek:", 3) != 0) {
        kprintf("fs: FAIL - append readback\n");
        return;
    }

    if (!mkdir(0, "/selftest_dir")) { kprintf("fs: FAIL - mkdir\n"); return; }
    if (!create_file(0, "/selftest_dir/nested.txt")) { kprintf("fs: FAIL - nested create\n"); return; }
    if (!write_file(0, "/selftest_dir/nested.txt", "nested", 6)) { kprintf("fs: FAIL - nested write\n"); return; }
    if (!remove_file(0, "/selftest_dir", true)) { kprintf("fs: FAIL - rm -r\n"); return; }
    if (!remove_file(0, "/selftest.txt", false)) { kprintf("fs: FAIL - remove\n"); return; }

    kprintf("fs: ALL TESTS PASSED\n");
    kslog("fs selftest: PASS\n");
}

} /* namespace fs */