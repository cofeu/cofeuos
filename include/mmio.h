#pragma once
/* 1GB ustu aygit MMIO erisimi (e1000 gibi BAR'lar >1GB adreslenir).
   Kimlik haritalama: fiziksel adres ayni sanal adreste gorunur. */

#include "kernel.h"

extern "C" {

bool mmio_map_device(uint32_t base_phys, uint32_t size_bytes);  /* bolgeyi haritala */
uint64_t mmio_shared_pd(void);                                  /* paylasilan ust PD (0=yok) */
uint64_t mmio_boot_pml4(void);                                  /* boot PML4 fiziksel adresi */

}