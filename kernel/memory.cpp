#include "kernel.h"

#include <new>

static char heap_pool[512 * 1024];
static size_t heap_used = 0;

extern "C" {

void* kmalloc(size_t n) {
    if (!n) n = 1;
    n = (n + 7) & ~(size_t)7;
    if (heap_used + n > sizeof(heap_pool)) {
        kprintf("kmalloc: out of memory (%u + %u)\n", (uint32_t)heap_used, (uint32_t)n);
        return NULL;
    }
    void* p = &heap_pool[heap_used];
    heap_used += n;
    return p;
}

void kfree(void*) {}

uint32_t kmem_used(void)     { return (uint32_t)heap_used; }
uint32_t kmem_capacity(void) { return (uint32_t)sizeof(heap_pool); }

} /* extern "C" */

void* operator new(size_t n)          { return kmalloc(n); }
void* operator new[](size_t n)        { return kmalloc(n); }
void operator delete(void* p) noexcept { (void)p; }
void operator delete[](void* p) noexcept { (void)p; }
void operator delete(void* p, size_t) noexcept { (void)p; }
void operator delete[](void* p, size_t) noexcept { (void)p; }

extern "C" void __cxa_pure_virtual(void) {
    kprintf("pure virtual called!\n");
    for (;;) asm volatile("hlt");
}