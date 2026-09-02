#include "kernel.h"
#include "x86.h"
#include <stdarg.h>

namespace {

typedef void (*emit_fn)(char c, void* ctx);

struct BufCtx {
    char* p;
    char* end;
    int count;
};

void emit_buf(char c, void* ctx) {
    BufCtx* b = (BufCtx*)ctx;
    if (b->p < b->end) *b->p++ = c;
    b->count++;
}

void pad(emit_fn emit, void* ctx, int width, char fill) {
    while (width-- > 0) emit(fill, ctx);
}

void print_u64(emit_fn emit, void* ctx, uint64_t v, int base,
               bool upper, int width, char fill, bool left) {
    char digits[24];
    int len = 0;
    const char* t = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    do {
        digits[len++] = t[v % (uint64_t)base];
        v /= (uint64_t)base;
    } while (v);
    int padn = width - len;
    if (!left && padn > 0) pad(emit, ctx, padn, fill);
    while (len) emit(digits[--len], ctx);
    if (left && padn > 0) pad(emit, ctx, padn, ' ');
}

void vformat(emit_fn emit, void* ctx, const char* fmt, va_list ap) {
    for (; *fmt; fmt++) {
        if (*fmt != '%') { emit(*fmt, ctx); continue; }

        fmt++;
        bool left = false;
        while (*fmt == '-') { left = true; fmt++; }
        char fill = ' ';
        if (*fmt == '0') { fill = '0'; fmt++; }
        int width = 0;
        while (*fmt >= '0' && *fmt <= '9') { width = width * 10 + (*fmt - '0'); fmt++; }
        while (*fmt == 'l' || *fmt == 'z' || *fmt == 'h') fmt++;

        switch (*fmt) {
        case 'c': {
            emit((char)va_arg(ap, int), ctx);
            continue;
        }
        case 's': {
            const char* s = va_arg(ap, const char*);
            if (!s) s = "(null)";
            int l = (int)strlen(s);
            int padn = width - l;
            if (!left && padn > 0) pad(emit, ctx, padn, ' ');
            while (*s) emit(*s++, ctx);
            if (left && padn > 0) pad(emit, ctx, padn, ' ');
            continue;
        }
        case 'n': {
            int* p = va_arg(ap, int*);
            if (p) *p = emit == emit_buf ? ((BufCtx*)ctx)->count : 0;
            continue;
        }
        case '%':
            emit('%', ctx);
            continue;
        default:
            break;
        }

        bool is_signed = false;
        bool upper = false;
        int base = 10;
        switch (*fmt) {
        case 'd': case 'i': is_signed = true; break;
        case 'u': break;
        case 'x': base = 16; break;
        case 'X': base = 16; upper = true; break;
        case 'p': base = 16; upper = true; break;
        case 'b': base = 2; break;
        default:
            emit('%', ctx);
            emit(*fmt, ctx);
            continue;
        }

        uint64_t v;
        if (is_signed) {
            int64_t sv = (int64_t)va_arg(ap, int64_t);
            if (sv < 0) {
                fill = ' ';
                emit('-', ctx);
                v = (uint64_t)(-(sv + 1)) + 1;
            } else {
                v = (uint64_t)sv;
            }
        } else {
            v = va_arg(ap, uint64_t);
        }
        print_u64(emit, ctx, v, base, upper, width, fill, left);
    }
}

void emit_vga_serial(char c, void*) {
    vga_putc(c);
    if (c == '\n') serial_putc('\r');
    serial_putc(c);
}

void emit_serial(char c, void*) {
    if (c == '\n') serial_putc('\r');
    serial_putc(c);
}

} /* namespace */

extern "C" void kprintf(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vformat(emit_vga_serial, NULL, fmt, ap);
    va_end(ap);
}

extern "C" void kslog(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vformat(emit_serial, NULL, fmt, ap);
    va_end(ap);
}

extern "C" int ksnprintf(char* buf, size_t n, const char* fmt, ...) {
    if (!n) return 0;
    BufCtx b;
    b.p = buf;
    b.end = buf + n - 1;
    b.count = 0;
    va_list ap;
    va_start(ap, fmt);
    vformat(emit_buf, &b, fmt, ap);
    va_end(ap);
    *b.p = 0;
    return b.count;
}