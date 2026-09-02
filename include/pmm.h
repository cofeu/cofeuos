#pragma once

#include "kernel.h"

extern "C" {

/* fiziksel bellek yoneticisi: 4K frame bitmap'i + ayirici */
void pmm_init(void);

/* tek frame ayir (0 = yok) */
uint64_t pmm_alloc_frame(void);

/* bitisik n frame ayir (kontigu, 0 = yok) */
uint64_t pmm_alloc_range(uint32_t nframes);

void pmm_free_frame(uint64_t phys);
void pmm_free_range(uint64_t phys, uint32_t nframes);

/* istatistikler */
uint64_t pmm_total_kb(void);   /* toplam fiziksel RAM (KB) */
uint64_t pmm_managed_kb(void); /* allocator'un yonettigi bolge (KB) */
uint32_t pmm_free_frames(void);
uint32_t pmm_total_frames(void);

}

/* heap (kmalloc) bildirimleri kernel.h icinde */