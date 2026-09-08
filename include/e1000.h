#pragma once
/* Intel e1000 (82540EM, QEMU -device e1000) MMIO surucusu */

#include "kernel.h"
#include "pci.h"
#include "nic.h"

extern "C" {

bool e1000_nic_probe(const PCIDevice* pci, NicDevice* out);

}