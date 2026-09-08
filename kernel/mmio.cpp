#include "kernel.h"
#include "x86.h"
#include "pmm.h"
#include "mmio.h"

/* Baglam: boot 0..1GB kimlik haritalar (2MB sayfalar, PD@0x72000).
   BAR'lar (>1GB, orn. QEMU e1000 0xFEBE0000) icin ust pencere acilir:
     PDPT[3] (0xC0000000-0xFFFFFFFF) -> paylasilan PD (kimlik, 2MB sayfalar)
   Boot PML4'unde (0x70000) ve her surecin PDPT'sinde bu giris bulunur. */

namespace {
constexpr uint32_t BOOT_PML4 = 0x70000;
constexpr uint32_t BOOT_PDPT = 0x71000;
uint64_t dev_pd = 0;          /* paylasilan ust PD (fiziksel) */
bool     ready  = false;
}

extern "C" bool mmio_map_device(uint32_t base_phys, uint32_t size_bytes) {
    (void)base_phys; (void)size_bytes;
    if (ready) return true;

    dev_pd = pmm_alloc_frame();
    if (!dev_pd) { kslog("mmio: paylasilan PD ayrilamadi\n"); return false; }
    memset((void*)dev_pd, 0, 4096);

    /* 1GB'lik ust pencerenin tamamini kimlik yap: 0xC0000000 + i*2MB <-> ayni fiziksel.
       Boylece hangi BAR (0xFEBExxxx, 0xFEC0xxxx, ...) olursa olsun erisilebilir. */
    volatile uint64_t* pd = (volatile uint64_t*)dev_pd;
    for (uint32_t i = 0; i < 512; i++)
        pd[i] = (uint64_t)(0xC0000000u + (i << 21u)) | 0x83;    /* P|RW|PS(2MB) */

    /* boot pml4: PML4[3] -> boot PDPT; PDPT[3] -> dev_pd */
    volatile uint64_t* pml4 = (volatile uint64_t*)BOOT_PML4;
    volatile uint64_t* pdpt = (volatile uint64_t*)BOOT_PDPT;
    pml4[3] = BOOT_PDPT | 0x7;
    pdpt[3] = dev_pd | 0x3;

    ready = true;
    kslog("mmio: ust pencere hazir (3GB bolgesi, dev_pd=0x%llx)\n",
          (unsigned long long)dev_pd);
    return true;
}

extern "C" uint64_t mmio_shared_pd(void) { return dev_pd; }