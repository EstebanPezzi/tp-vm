size_nodo equ 8
sig equ 4

crear_nodo_LS:      push bp
                    mov bp, sp
                    push size_nodo
                    call alloc
                    add sp, 4
                    cmp eax, null
                    jz fin_crear_nodo_LS
                    mov [eax+val], [bp+8]
                    mov [eax+sig], null
fin_crear_nodo_LS:  mov sp, bp
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

agregar_nodo_LS:    push bp
                    mov bp,sp
                    push eax
                    push ebx
                    mov ebx, [bp+12]
                    push [bp+8]
                    call crear_nodo_LS
                    add sp, 4

                    push ebx
                    push eax
                    call agregar_nodo
                    add sp, 8

                    pop ebx
                    pop eax
                    mov sp, bp
                    pop bp
                    ret