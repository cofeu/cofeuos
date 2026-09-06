section .note.cofeu progbits alloc noexec nowrite align=4
    dd 8                    ; namesz
    dd 8                    ; descsz
    dd 0xC0FE               ; type
    db "COFEUOS", 0         ; name (8 bayt)
    db "COFEU", 0, 0, 0    ; desc (8 bayt)
