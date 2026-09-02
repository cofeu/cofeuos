#pragma once

typedef unsigned char   uint8_t;
typedef unsigned short  uint16_t;
typedef unsigned int    uint32_t;
typedef unsigned long   uint64_t;
typedef signed char     int8_t;
typedef short           int16_t;
typedef int             int32_t;
typedef long            int64_t;

typedef uint64_t        size_t;
typedef uint64_t        uintptr_t;
typedef int64_t         intptr_t;

#ifndef NULL
#define NULL 0
#endif

#define KERNEL_VERSION "cofeuos 0.1.0 (x86_64)"

extern "C" {

void* memset(void*, int, size_t);
void* memcpy(void*, const void*, size_t);
void* memmove(void*, const void*, size_t);
int   memcmp(const void*, const void*, size_t);
size_t strlen(const char*);
int   strcmp(const char*, const char*);
int   strncmp(const char*, const char*, size_t);
char* strcpy(char*, const char*);
char* strncpy(char*, const char*, size_t);
char* strchr(const char*, int);
char* strrchr(const char*, int);

/* formatli cikti: kprintf -> VGA, kslog -> seri (COM1) */
void  kprintf(const char* fmt, ...);
void  kslog(const char* fmt, ...);
int   ksnprintf(char* buf, size_t n, const char* fmt, ...);

/* bellek albkatoforu (bump allocator + operator new/delete) */
void* kmalloc(size_t n);

/* ---- VGA metin modu ---- */
void vga_init(void);
void vga_clear(void);
void vga_set_color(uint8_t c);
void vga_putc(char c);
void vga_write(const char* s);
void vga_set_cursor(uint8_t x, uint8_t y);

/* ---- COM1 su]rial ---- */
void serial_init(void);
void serial_putc(char c);
void serial_write(const char* s);

/* ---- GDT / IDT / IRQ ---- */
void gdt_init(void);
void idt_init(void);
void pic_remap(void);
void pic_send_eoi(uint8_t irq);
extern void isr_dispatch(uint64_t vec, uint64_t err);

/* ---- PIT zamanlayici (100Hz) ---- */
void timer_init(void);
uint64_t timer_get_ticks(void);
uint64_t timer_get_seconds(void);
extern void timer_irq(void);

/* ---- PS/2 klavye ---- */
void keyboard_init(void);
extern void keyboard_irq(void);
bool keyboard_has_char(void);
char keyboard_getc(void);

/* ---- ATA PIO (birincil master) ---- */
bool ata_init(void);
bool ata_identify(void);
bool ata_read_sector(uint32_t lba, void* buf);
bool ata_write_sector(uint32_t lba, const void* buf);

/* ---- bellek istatistikleri ---- */
uint32_t kmem_used(void);
uint32_t kmem_capacity(void);

}

/* ---- cofeufs dosya sistemi ---- */
namespace fs {

struct EntryInfo {
    char name_[32];
    uint8_t type_;
    uint32_t size_;
};

bool mount(void);
uint32_t disk_blocks(void);

bool create_file(uint32_t base_ino, const char* path);
bool mkdir(uint32_t base_ino, const char* path);
bool write_file(uint32_t base_ino, const char* path, const void* data, uint32_t len);
bool append_file(uint32_t base_ino, const char* path, const void* data, uint32_t len);
bool read_file(uint32_t base_ino, const char* path, void* buf, uint32_t maxlen, uint32_t* out_len);
bool remove_file(uint32_t base_ino, const char* path, bool recursive);
bool resolve(uint32_t base_ino, const char* path, uint32_t* out_ino);
bool stat(uint32_t base_ino, const char* path, EntryInfo* out);
void list(uint32_t base_ino, const char* path,
          void (*cb)(const EntryInfo&, void*), void* ctx);
void selftest(void);

}

void shell_run(void);