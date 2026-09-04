; cofeuos cexe imza notu: ELF'nin icinde tasinir, kernel bunu dogrular.
; ELF note duzeni: namesz, descsz, type, name(pad4), desc(pad4)
section .note.cofeu progbits alloc noexec nowrite
align 4
    dd 8                 ; namesz  (COFEUOS\0)
    dd 8                 ; descsz  (COFEU2\0 + pad)
    dd 0xC0FE            ; type    (cofeu sihirli turu)
    db "COFEUOS", 0      ; sahip adi (8 bayt, hizali)
    db "COFEU2", 0, 0, 0 ; descriptor imzasi (8 bayt)
