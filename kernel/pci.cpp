#include "kernel.h"
#include "x86.h"
#include "pci.h"

namespace {

PCIDevice devices[32];
int device_count = 0;

} /* namespace */

extern "C" uint32_t pci_read_config(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset) {
    uint32_t addr = 0x80000000u | ((uint32_t)bus << 16) |
                    ((uint32_t)slot << 11) | ((uint32_t)func << 8) |
                    (offset & 0xFCu);
    outl(0xCF8, addr);
    return inl(0xCFC);
}

extern "C" void pci_write_config(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint32_t val) {
    uint32_t addr = 0x80000000u | ((uint32_t)bus << 16) |
                    ((uint32_t)slot << 11) | ((uint32_t)func << 8) |
                    (offset & 0xFCu);
    outl(0xCF8, addr);
    outl(0xCFC, val);
}

/* PCI Komut registeri (0x04) bit2 = Bus Master Enable; DMA islemleri icin gerekli */
extern "C" void pci_set_bus_master(uint8_t bus, uint8_t slot, uint8_t func) {
    uint32_t cmd = pci_read_config(bus, slot, func, 0x04);
    pci_write_config(bus, slot, func, 0x04, cmd | 0x0004u);
    kslog("pci: bus master eklendi (%02x:%02x.%x cmd=0x%x)\n",
          bus, slot, func, cmd | 0x0004u);
}

extern "C" int pci_scan(void) {
    device_count = 0;
    kslog("pci: tarama basladi\n");
    for (int bus = 0; bus < 1; bus++) {
        for (int slot = 0; slot < 32; slot++) {
            uint32_t id = pci_read_config((uint8_t)bus, (uint8_t)slot, 0, 0);
            if (id == 0xFFFFFFFFu) continue;

            PCIDevice* d = &devices[device_count];
            d->bus = (uint8_t)bus;
            d->slot = (uint8_t)slot;
            d->func = 0;
            d->vendor_id = (uint16_t)(id & 0xFFFF);
            d->device_id = (uint16_t)(id >> 16);

            uint32_t cc = pci_read_config((uint8_t)bus, (uint8_t)slot, 0, 0x08);
            d->class_code = (uint8_t)(cc >> 24);
            d->subclass   = (uint8_t)(cc >> 16);

            d->bar0 = pci_read_config((uint8_t)bus, (uint8_t)slot, 0, 0x10);
            d->bar1 = pci_read_config((uint8_t)bus, (uint8_t)slot, 0, 0x14);

            uint32_t il = pci_read_config((uint8_t)bus, (uint8_t)slot, 0, 0x3C);
            d->irq = (uint8_t)(il & 0xFF);

            kprintf("pci: %02x:%02x.%x %04x:%04x sinif=%02x/%02x irq=%u bar0=0x%x bar1=0x%x\n",
                    bus, slot, 0, d->vendor_id, d->device_id,
                    d->class_code, d->subclass, d->irq, d->bar0, d->bar1);
            kslog("pci %02x:%02x.%x %04x:%04x class=%02x/%02x irq=%d bar0=0x%x\n",
                  bus, slot, 0, d->vendor_id, d->device_id,
                  d->class_code, d->subclass, d->irq, d->bar0);
            device_count++;
            if (device_count >= 32) return device_count;
        }
    }
    kslog("pci: %d aygit bulundu\n", device_count);
    return device_count;
}

extern "C" int pci_find(uint16_t vendor, uint16_t device) {
    for (int i = 0; i < device_count; i++)
        if (devices[i].vendor_id == vendor && devices[i].device_id == device)
            return i;
    return -1;
}

extern "C" const PCIDevice* pci_get(int index) {
    if (index < 0 || index >= device_count) return NULL;
    return &devices[index];
}