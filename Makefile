CXX      ?= g++
LD       ?= ld
NASM     ?= nasm
OBJCOPY  ?= objcopy
QEMU     ?= qemu-system-x86_64

CXXFLAGS  = -std=gnu++17 -m64 -ffreestanding -fno-exceptions -fno-rtti
CXXFLAGS += -fno-pic -fno-stack-protector -fno-builtin -fno-plt -mgeneral-regs-only
CXXFLAGS += -mno-red-zone -mcmodel=small -mno-mmx -mno-sse -mno-sse2 -mno-80387
CXXFLAGS += -O2 -Wall -Wextra -DKCOFEUOS -Iinclude

LDFLAGS   = -m elf_x86_64 -T linker.ld -nostdlib -z max-page-size=0x1000

OBJ = kernel/entry.o kernel/isr.o kernel/main.o kernel/util.o kernel/memory.o \
      kernel/pmm.o kernel/kprintf.o kernel/vga.o kernel/serial.o kernel/gdt.o \
      kernel/idt.o kernel/irq.o kernel/timer.o kernel/keyboard.o kernel/ata.o \
      kernel/cofeufs.o kernel/shell.o kernel/sched.o

DISK_SIZE_SECTORS = 67584

DPKG = python3 -c "import sys;d=open(sys.argv[1],'rb').read();d=d.rstrip(b'\x00');open(sys.argv[1],'wb').write(d)"

.PHONY: all run run-headless clean

all: disk.img

boot/boot.bin: boot/boot.asm kernel.bin
	$(NASM) -f bin \
	    -DKERNEL_SECTORS=$$(python3 -c "import os;print((os.path.getsize('kernel.bin')+511)//512)") \
	    -o $@ $<

%.o: %.asm
	$(NASM) -f elf64 -o $@ $<

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

kernel.elf: $(OBJ) linker.ld
	$(LD) $(LDFLAGS) -o $@ $(OBJ)

kernel.bin: kernel.elf
	$(OBJCOPY) -O binary --strip-all $< $@.tmp
	$(DPKG) $@.tmp
	mv $@.tmp $@
	@sz=$$(stat -c%s $@); \
	if [ $$sz -gt $$((127 * 512)) ]; then \
	    echo "HATA: kernel.bin $$sz bayt - boot tek sektor okumasi max 127*512 ile sinirli!" >&2; \
	    exit 1; \
	fi

disk.img: boot/boot.bin kernel.bin
	truncate -s $$((67584 * 512)) $@
	dd if=boot/boot.bin of=$@ conv=notrunc status=none
	dd if=kernel.bin of=$@ bs=512 seek=1 conv=notrunc status=none

run: disk.img
	$(QEMU) -drive file=disk.img,format=raw,cache=writethrough,index=0 \
	        -m 128 -boot c -serial stdio -monitor none -no-reboot

run-headless: disk.img
	$(QEMU) -drive file=disk.img,format=raw,cache=writethrough,index=0 \
	        -m 128 -boot c -nographic -serial mon:stdio -monitor none -no-reboot

clean:
	rm -f kernel.elf kernel.bin disk.img boot/boot.bin
	rm -f kernel/*.o