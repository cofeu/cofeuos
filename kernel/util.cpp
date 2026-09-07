#include "kernel.h"
#include "x86.h"

static volatile bool g_intr_pending = false;

/* ---- Ctrl+C (iptal) sinyali ---- */
extern "C" void sys_intr_set(void)   { g_intr_pending = true; }
extern "C" void sys_intr_clear(void) { g_intr_pending = false; }
extern "C" bool sys_intr_pending(void) { return g_intr_pending; }

/* Bekleyen (poll) islerin her turunedok cagrilir: seriden 0x03 (Ctrl+C) bayraga cerçevirir. */
extern "C" void sys_intr_poll(void) {
    if (serial_has_char() && serial_getc() == 0x03) g_intr_pending = true;
}

extern "C" {

void* memset(void* dst, int v, size_t n) {
    uint8_t* p = (uint8_t*)dst;
    while (n--) *p++ = (uint8_t)v;
    return dst;
}

void* memcpy(void* dst, const void* src, size_t n) {
    uint8_t* d = (uint8_t*)dst;
    const uint8_t* s = (const uint8_t*)src;
    if (n >= 4 && ((uintptr_t)d & 3) == ((uintptr_t)s & 3)) {
        while (n >= 4 && ((uintptr_t)d & 3)) { *d++ = *s++; n--; }
        uint32_t* dw = (uint32_t*)d;
        const uint32_t* sw = (const uint32_t*)s;
        while (n >= 4) { *dw++ = *sw++; n -= 4; }
        d = (uint8_t*)dw;
        s = (const uint8_t*)sw;
    }
    while (n--) *d++ = *s++;
    return dst;
}

void* memmove(void* dst, const void* src, size_t n) {
    uint8_t* d = (uint8_t*)dst;
    const uint8_t* s = (const uint8_t*)src;
    if (d < s) {
        while (n--) *d++ = *s++;
    } else if (d > s) {
        d += n; s += n;
        while (n--) *--d = *--s;
    }
    return dst;
}

int memcmp(const void* a, const void* b, size_t n) {
    const uint8_t* x = (const uint8_t*)a;
    const uint8_t* y = (const uint8_t*)b;
    while (n--) {
        if (*x != *y) return (int)*x - (int)*y;
        x++; y++;
    }
    return 0;
}

size_t strlen(const char* s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

int strcmp(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return (int)(uint8_t)*a - (int)(uint8_t)*b;
}

int strncmp(const char* a, const char* b, size_t n) {
    if (!n) return 0;
    while (--n && *a && *a == *b) { a++; b++; }
    return (int)(uint8_t)*a - (int)(uint8_t)*b;
}

char* strcpy(char* d, const char* s) {
    char* r = d;
    while ((*d++ = *s++)) {}
    return r;
}

char* strncpy(char* d, const char* s, size_t n) {
    char* r = d;
    while (n && *s) { *d++ = *s++; n--; }
    while (n--) *d++ = 0;
    return r;
}

char* strchr(const char* s, int c) {
    while (*s) {
        if (*s == (char)c) return (char*)s;
        s++;
    }
    return ((char)c == 0) ? (char*)s : NULL;
}

char* strrchr(const char* s, int c) {
    const char* last = NULL;
    while (*s) {
        if (*s == (char)c) last = s;
        s++;
    }
    if ((char)c == 0) return (char*)s;
    return (char*)last;
}

} /* extern "C" */