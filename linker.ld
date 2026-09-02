ENTRY(_start)

SECTIONS
{
    . = 0x100000;

    .text : ALIGN(0x1000) {
        *(.text*)
    }

    .rodata : ALIGN(0x1000) {
        *(.rodata*)
    }

    .data : ALIGN(0x1000) {
        *(.data*)
    }

    __bss_start = .;
    .bss : ALIGN(0x1000) {
        *(.bss*)
        *(COMMON)
    }
    __bss_end = .;

    /* cekirdek yigin alani (bss'e dahil degil, ayri NOBITS) */
    . = ALIGN(0x1000);
    .kstack (NOLOAD) : {
        __kstack_top = . + 0x20000;
    }

    /* cekirdegin fiziksel bitisi: PMM buradan itibaren frame ayirir */
    __kernel_end = __kstack_top;

    /DISCARD/ : {
        *(.comment)
        *(.eh_frame)
        *(.note*)
        *(.gnu.version*)
    }
}