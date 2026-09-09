CC       ?= gcc
CXX      ?= g++
LD       ?= ld
NASM     ?= nasm
OBJCOPY  ?= objcopy
QEMU     ?= qemu-system-x86_64

CXXFLAGS  = -std=gnu++17 -m64 -ffreestanding -fno-exceptions -fno-rtti
CXXFLAGS += -fno-pic -fno-stack-protector -fno-builtin -fno-plt -mgeneral-regs-only
CXXFLAGS += -mno-red-zone -mcmodel=small -mno-mmx -mno-sse -mno-sse2 -mno-80387
CXXFLAGS += -O2 -Wall -Wextra -DKCOFEUOS -Iinclude

USERFLAGS = -Os -m64 -ffreestanding -nostdlib -fno-pic -no-pie -fno-stack-protector
USERFLAGS += -fno-builtin -fno-plt -mgeneral-regs-only -fno-asynchronous-unwind-tables
USERFLAGS += -Wl,-Ttext=0x40000000 -Wl,--entry=_start -Wl,--build-id=none

LDFLAGS   = -m elf_x86_64 -T linker.ld -nostdlib -z max-page-size=0x1000

OBJ = kernel/entry.o kernel/isr.o kernel/main.o kernel/util.o kernel/memory.o \
      kernel/pmm.o kernel/kprintf.o kernel/vga.o kernel/serial.o kernel/gdt.o \
      kernel/idt.o kernel/irq.o kernel/timer.o kernel/keyboard.o kernel/ata.o \
      kernel/cofeufs.o kernel/shell.o kernel/sched.o kernel/user_embed.o \
      kernel/rtc.o kernel/pci.o kernel/mmio.o kernel/nic.o kernel/rtl8139.o \
      kernel/e1000.o kernel/net.o

DISK_SIZE_SECTORS = 67584

DPKG = python3 -c "import sys;d=open(sys.argv[1],'rb').read();d=d.rstrip(b'\x00');open(sys.argv[1],'wb').write(d)"

.PHONY: all run run-headless run-iso iso clean

all: disk.img

boot/boot.bin: boot/boot.asm kernel.bin
	$(NASM) -f bin \
	    -DKERNEL_SECTORS=$$(python3 -c "import os;print((os.path.getsize('kernel.bin')+511)//512)") \
	    -o $@ $<

%.o: %.asm
	$(NASM) -f elf64 -o $@ $<

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

user/cofeu_note.o: user/cofeu_note.asm
	$(NASM) -f elf64 -o $@ $<

user/user_demo.o: user/user.c
	$(CC) $(USERFLAGS) -c -o $@ $<

user/user_demo.elf: user/user_demo.o user/cofeu_note.o
	$(CC) $(USERFLAGS) -o $@ $< user/cofeu_note.o

user/user_demo.bin: user/user_demo.elf
	$(OBJCOPY) -O binary --remove-section=.note.gnu.property $< $@
	@echo "user entry: $$(readelf -h $< | grep 'Entry point' | sed -n 's/.*\(0x[0-9a-fA-F]*\).*/\1/p')"

kernel/user_embed.o: user/user_demo.bin
	$(LD) -r -b binary $< -o $@

user/user2.o: user2/user2.c
	$(CC) $(USERFLAGS) -c -o $@ $<

user/user2.elf: user/user2.o user/cofeu_note.o
	$(CC) $(USERFLAGS) -o $@ $< user/cofeu_note.o

user/udp_dns.o: user/udp_dns.c
	$(CC) $(USERFLAGS) -c -o $@ $<

user/udp_dns.elf: user/udp_dns.o user/cofeu_note.o
	$(CC) $(USERFLAGS) -o $@ $< user/cofeu_note.o

kernel/sched.o: kernel/sched.cpp user/user_demo.elf
	$(CXX) $(CXXFLAGS) -DUSER_ENTRY_ADDR=$$(readelf -h user/user_demo.elf | grep 'Entry point' | sed -n 's/.*\(0x[0-9a-fA-F]*\).*/\1/p') -c -o $@ $<

kernel.elf: $(OBJ) linker.ld
	$(LD) $(LDFLAGS) -o $@ $(OBJ)

kernel.bin: kernel.elf
	$(OBJCOPY) -O binary --strip-all $< $@.tmp
	$(DPKG) $@.tmp
	mv $@.tmp $@
	@sz=$$(stat -c%s $@); \
	if [ $$sz -gt $$((400 * 512)) ]; then \
	    echo "HATA: kernel.bin $$sz bayt - boot ara tamponu (640KB) sinirli!" >&2; \
	    exit 1; \
	fi

disk.img: boot/boot.bin kernel.bin user/user_demo.elf user/user2.elf user/udp_dns.elf tools/mkfs.py
	truncate -s $$((67584 * 512)) $@
	dd if=boot/boot.bin of=$@ conv=notrunc status=none
	dd if=kernel.bin of=$@ bs=512 seek=1 conv=notrunc status=none
	python3 tools/mkfs.py $@ \
	    user/user_demo.elf:/sys/basic.cexe \
	    user/user2.elf:/sys/hello.cexe \
	    user/udp_dns.elf:/sys/udp_dns.cexe

QEMU_NET = -netdev user,id=n0 -device rtl8139,netdev=n0

run: disk.img
	$(QEMU) -drive file=disk.img,format=raw,cache=writethrough,index=0 \
	        -m 128 -boot c -serial stdio -monitor none -no-reboot $(QEMU_NET)

run-headless: disk.img
	$(QEMU) -drive file=disk.img,format=raw,cache=writethrough,index=0 \
	        -m 128 -boot c -nographic -serial mon:stdio -monitor none -no-reboot $(QEMU_NET)

iso: disk.img
	@mkdir -p iso_root
	@cp disk.img iso_root/cofeuos.img
	xorriso -as mkisofs \
	    -o cofeuos.iso \
	    -J -joliet-long \
	    iso_root
	@rm -rf iso_root
	@echo "cofeuos.iso olusturuldu ($$(stat -c%s cofeuos.iso) bayt)"

run-iso: iso disk.img
	$(QEMU) -drive file=disk.img,format=raw,cache=writethrough,index=0 \
	        -drive file=cofeuos.iso,format=raw,if=ide,media=cdrom,index=2 \
	        -m 128 -boot c -serial stdio -monitor none -no-reboot

clean:
	rm -f kernel.elf kernel.bin disk.img boot/boot.bin cofeuos.iso
	rm -f kernel/*.o user/user_demo.o user/user_demo.elf user/user_demo.bin user/user2.o user/user2.elf user/cofeu_note.o
	rm -rf iso_root