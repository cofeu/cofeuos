#include "kernel.h"
#include "x86.h"

namespace {

constexpr int WIDTH  = 80;
constexpr int HEIGHT = 25;
volatile uint16_t* const fb = (volatile uint16_t*)0xB8000;

uint8_t color = 0x07;
int row = 0;
int col = 0;

void update_cursor(void) {
    uint16_t pos = (uint16_t)(row * WIDTH + col);
    outb(0x3D4, 0x0F);
    outb(0x3D5, (uint8_t)(pos & 0xFF));
    outb(0x3D4, 0x0E);
    outb(0x3D5, (uint8_t)(pos >> 8));
}

void scroll(void) {
    for (int y = 1; y < HEIGHT; y++)
        for (int x = 0; x < WIDTH; x++)
            fb[(y - 1) * WIDTH + x] = fb[y * WIDTH + x];
    for (int x = 0; x < WIDTH; x++)
        fb[(HEIGHT - 1) * WIDTH + x] = (uint16_t)((uint16_t)color << 8) | ' ';
    row = HEIGHT - 1;
    col = 0;
}

} /* namespace */

extern "C" void vga_init(void) {
    vga_clear();
    vga_set_cursor(0, 0);
}

extern "C" void vga_clear(void) {
    uint16_t blank = (uint16_t)(((uint16_t)color << 8) | ' ');
    for (int i = 0; i < WIDTH * HEIGHT; i++) fb[i] = blank;
    row = 0;
    col = 0;
    update_cursor();
}

extern "C" void vga_set_color(uint8_t c) { color = c; }

extern "C" void vga_putc(char c) {
    switch (c) {
    case '\n':
        row++;
        col = 0;
        break;
    case '\r':
        col = 0;
        break;
    case '\t':
        col = (col + 4) & ~3;
        break;
    case '\b':
        if (col) col--;
        fb[row * WIDTH + col] = (uint16_t)(((uint16_t)color << 8) | ' ');
        break;
    default:
        if (c >= 32) {
            fb[row * WIDTH + col] = (uint16_t)(((uint16_t)color << 8) | (uint8_t)c);
            col++;
        }
        break;
    }
    if (col >= WIDTH) { row++; col = 0; }
    if (row >= HEIGHT) scroll();
    update_cursor();
}

extern "C" void vga_write(const char* s) {
    while (*s) vga_putc(*s++);
}

extern "C" void vga_set_cursor(uint8_t x, uint8_t y) {
    if (x >= WIDTH) x = WIDTH - 1;
    if (y >= HEIGHT) y = HEIGHT - 1;
    row = y;
    col = x;
    update_cursor();
}