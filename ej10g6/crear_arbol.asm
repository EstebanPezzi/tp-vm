

size_nodo_arbol equ 12
val equ 0
izq equ 4
der equ 8

heap_init:      mov [es], es
                add [es], 4
                ret

alloc:          push bp
                mov bp, sp
                push ebx

                mov eax, null
                mov ebx, w[es+2]
                add ebx, [bp+8]
                cmp ebx, size_extra
                jz alloc_fin
                mov eax, [es]
                add [es], [bp+8]

alloc_fin:      pop ebx
                mov sp, bp
                pop bp
                ret

crear_nodo:     push bp
                mov bp, sp

                push size_nodo_arbol
                call alloc
                add sp, 4

                cmp eax, null
                jz crear_nodo_fin
                mov [eax+val], [bp+8]
                mov [eax+izq], null
                mov [eax+der], null

crear_nodo_fin: mov sp, bp
                pop bp
                ret


agregar_nodo_arbol:     push bp
                        mov bp, sp
                        push eax
                        push ebx
                        push edx
                        mov edx, [bp+12]
                        mov eax, [bp+8]
                        mov ebx, [edx]

                        cmp eax, null
                        jz fin_agregacion ; si alloc lanzo null porque no hay espacion para nuevos nodos

                        cmp ebx, null
                        jz append
                        cmp [ebx+val], [eax+val]
                        jz fin_agregacion ; no se agregan nodos repetidos

                        jp agregar_izq
                        jn agregar_der

agregar_izq:            add ebx, izq
                        push ebx
                        push eax
                        call agregar_nodo_arbol
                        add sp, 8
                        jmp fin_agregacion

agregar_der:            add ebx, der
                        push ebx
                        push eax
                        call agregar_nodo_arbol
                        add sp, 8
                        jmp fin_agregacion

append:                 mov [edx], eax
fin_agregacion:         pop edx
                        pop ebx
                        pop eax
                        mov sp, bp
                        pop bp
                        ret


crear_nodo_arbol:       push bp
                        mov bp, sp
                        push eax
                        push ebx
                        mov ebx, [bp+12]

                        push [bp+8]
                        call crear_nodo
                        add sp, 4

                        push ebx
                        push eax
                        call agregar_nodo_arbol
                        add sp, 8

                        pop ebx
                        pop eax
                        mov sp, bp
                        pop bp
                        ret