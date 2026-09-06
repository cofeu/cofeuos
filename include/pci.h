#pragma once
/* PCI bus tarama (config space: portlar 0xCF8 / 0xCFC) */

#include "kernel.h"

struct PCIDevice {
    uint8_t  bus;
    uint8_t  slot;
    uint8_t  func;
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t  class_code;
    uint8_t  subclass;
    uint8_t  irq;
    uint32_t bar0;
    uint32_t bar1;
};

extern "C" {

int  pci_scan(void);                          /* aygitlari tarar; sayiyi doner */
int  pci_find(uint16_t vendor, uint16_t device);
const PCIDevice* pci_get(int index);
uint32_t pci_read_config(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset);
void pci_write_config(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint32_t val);
void pci_set_bus_master(uint8_t bus, uint8_t slot, uint8_t func);   /* Komut+bit2 */

}