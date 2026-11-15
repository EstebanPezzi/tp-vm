size_extra equ 1024
root equ 4
size_nodo equ 8
val equ 0
sig equ 4


heap_init:  mov [es], es
            add [es], 4
            ret

alloc:      push bp
            mov bp, sp
            push ebx
            mov eax, null
            mov ebx, w[es+2]
            add ebx, [bp+8]
            cmp ebx, size_extra
            jp alloc_fin
            mov eax, [es]
            add [es], [bp+8]
alloc_fin:  pop ebx
            mov sp, bp
            pop bp
            ret

crear_nodo_LD:      push bp
                    mov bp, sp
                    push size_nodo
                    call alloc
                    add sp, 4
                    cmp eax, null
                    jz fin_crear_nodo_LD
                    mov [eax+val], [bp+8]
                    mov [eax+sig], null
fin_crear_nodo_LD:  mov sp, bp
                    pop bp
                    ret



agregar_nodo:       push bp
                    mov bp, sp
                    push eax
                    push ebx
                    push edx
                    mov edx, [bp+12]
                    mov eax, [bp+8]

                    cmp eax, null
                    jz fin_agregar_nodo
                    mov ebx, [edx]
                    mov [eax+sig], ebx
                    mov [edx], eax

fin_agregar_nodo:   pop edx
                    pop ebx
                    pop eax
                    mov sp, bp
                    pop bp
                    ret