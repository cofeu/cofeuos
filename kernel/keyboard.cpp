#include "kernel.h"
#include "x86.h"

namespace {

constexpr int RING_SIZE = 256;
char ring[RING_SIZE];
volatile int head = 0;
volatile int tail = 0;

bool shift = false;
bool caps = false;

static const char normal[128] = {
    0, 27, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b',
    '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n',
    0, 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`', 0,
    '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0, '*', 0, ' ',
    ' ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static const char shifted[128] = {
    0, 27, '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '\b',
    '\t', 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', '\n',
    0, 'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '~', 0,
    '|', 'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<', '>', '?', 0, '*', 0, ' ',
    ' ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void push(char c) {
    int n = (head + 1) % RING_SIZE;
    if (n == tail) return;      /* fu:el */
    ring[head] = c;
    head = n;
}

} /* namespace */

extern "C" void keyboard_init(void) {
    /* PS/2 denetleyiciyi kullanilabilir segi: port 0x60/0x64 otomatik */
    head = tail = 0;
    shift = false;
    caps = false;
}

extern "C" void keyboard_irq(void) {
    uint8_t code = inb(0x60);
    bool released = (code & 0x80) != 0;
    uint8_t sc = code & 0x7F;

    if (released) {
        if (sc == 0x2A || sc == 0x36) shift = false;
        return;
    }

    switch (sc) {
    case 0x2A: case 0x36: shift = true; return;
    case 0x3A: caps = !caps; return;
    case 0x60: return;   /* 0xE0 genisetilmis prefix */
    default: break;
    }

    if (sc >= 128) return;
    char c = shift ? shifted[sc] : normal[sc];
    if (c == 0) return;

    if (c >= 'a' && c <= 'z' && caps) c = (char)(c - 'a' + 'A');
    push(c);
}

extern "C" bool keyboard_has_char(void) {
    return head != tail;
}

extern "C" char keyboard_getc(void) {
    if (head == tail) return 0;
    char c = ring[tail];
    tail = (tail + 1) % RING_SIZE;
    return c;
}