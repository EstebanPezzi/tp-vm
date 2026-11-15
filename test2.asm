root  equ    4
seg equ 1050
MOV EDX, DS
ADD EDX, 100
MOV EFX, SP
MOV w[EFX], root
MOV CX, root
SYS 0x3
SYS 0x4