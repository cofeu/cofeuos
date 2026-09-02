#include "kernel.h"
#include "x86.h"
#include "pmm.h"

#include <new>

namespace {

/* Boyut-baslikli, adres-sirali free list heap allocator.
   Kumesi (arena) pmm_alloc_range() ile cekirdek disinda bitisik frame'lerden gelir. */
struct Block {
    size_t size;   /* blogun toplam boyutu (baslik dahil, 8 hizali) */
    Block* next;   /* free list zinciri */
};

constexpr size_t HDR       = sizeof(Block);   /* 16 */
constexpr size_t MIN_BLOCK = HDR + 16;
constexpr size_t HEAP_PAGES = 256;            /* 1MB arena */

uint64_t arena_start = 0;
size_t arena_size   = 0;
size_t heap_used    = 0;                       /* ayrilmis aktif bayt */
Block*  free_list   = nullptr;

size_t align8(size_t n) { return (n + 7u) & ~(size_t)7u; }

void* alloc_from(size_t need) {
    Block** pp = &free_list;
    while (*pp) {
        Block* b = *pp;
        if (b->size >= need) {
            if (b->size - need >= MIN_BLOCK) {
                Block* rest = (Block*)((uint8_t*)b + need);
                rest->size  = b->size - need;
                rest->next  = b->next;
                b->next     = rest;
            } else {
                *pp = b->next;                 /* blogun tamamini kullan */
            }
            b->size = need;
            return b + 1;
        }
        pp = &b->next;
    }
    return NULL;
}

bool in_arena(Block* b) {
    uint64_t p = (uint64_t)b;
    return p >= arena_start && p + b->size <= arena_start + arena_size;
}

void insert_keep_coalesced(Block* b) {
    Block** pp = &free_list;
    while (*pp && (uint64_t)*pp < (uint64_t)b) pp = &(*pp)->next;

    /* saga birlestir */
    if (*pp && (uint64_t)b + b->size == (uint64_t)*pp) {
        b->size += (*pp)->size;
        b->next  = (*pp)->next;
    } else {
        b->next = *pp;
    }
    *pp = b;

    /* sola birlestir: sirali listede b'den once geleni bul */
    if (pp != &free_list) {
        Block* prev = free_list;
        while (prev->next != b) prev = prev->next;
        if ((uint64_t)prev + prev->size == (uint64_t)b) {
            prev->size += b->size;
            prev->next  = b->next;
        }
    }
}

} /* namespace */

extern "C" {

void kmalloc_init(void) {
    if (arena_size) return;

    uint32_t want = HEAP_PAGES;
    uint32_t avail = pmm_free_frames();
    if (want > avail) want = avail / 2u;
    if (!want) return;

    uint64_t a = pmm_alloc_range(want);
    if (!a) {
        kprintf("kmalloc_init: bitisik bellek yok\n");
        return;
    }
    arena_start = a;
    arena_size  = (size_t)want * 4096u;
    free_list   = (Block*)a;
    free_list->size = arena_size;
    free_list->next = NULL;
    heap_used = 0;
}

void* kmalloc(size_t n) {
    if (!n) n = 1;
    n = align8(n);
    if (n < 8) n = 8;
    size_t need = HDR + n;

    void* p = alloc_from(need);
    if (!p) {
        kprintf("kmalloc: heap tukendi (%u kullanilan / %u kapasite)\n",
                (uint32_t)heap_used, (uint32_t)arena_size);
        return NULL;
    }
    heap_used += need;
    return p;
}

void kfree(void* p) {
    if (!p) return;
    Block* b = (Block*)p - 1;
    if (!in_arena(b) || (b->size & 7u)) return;
    heap_used -= b->size;
    insert_keep_coalesced(b);
}

uint32_t kmem_used(void)     { return (uint32_t)heap_used; }
uint32_t kmem_capacity(void) { return (uint32_t)arena_size; }

} /* extern "C" */

void* operator new(size_t n)                     { return kmalloc(n); }
void* operator new[](size_t n)                   { return kmalloc(n); }
void operator delete(void* p) noexcept           { kfree(p); }
void operator delete[](void* p) noexcept         { kfree(p); }
void operator delete(void* p, size_t) noexcept   { kfree(p); }
void operator delete[](void* p, size_t) noexcept { kfree(p); }

extern "C" void __cxa_pure_virtual(void) {
    kprintf("pure virtual called!\n");
    for (;;) asm volatile("hlt");
}