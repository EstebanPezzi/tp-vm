mostrar_lista:  push bp
                mov bp, sp
                push eax
                push ecx
                push edx
                mov edx, [bp+8]


                mov eax, 1
                ldl ecx, 1
                ldh ecx, 4
muestro_sig:    cmp edx, null
                jz fin_mostrar_LS
                sys 2
                mov edx, [edx+sig]
                jmp muestro_sig
fin_mostrar_LS: pop edx
                pop ecx
                pop eax
                mov sp, bp
                pop bp
                ret