nodo_LD equ 12
val equ 0
ant equ 4
sig equ 8
null equ -1
stack_size equ 1024

alloc:          push bp
                mov bp, sp
                push ebx

                mov ebx, w[es+2]
                add ebx, [bp+8]
                cmp [ebx], stack_size
                jz alloc_fin
                mov eax, [es]
                add [es], [bp+8]

alloc_fin:      pop ebx
                mov sp, bp
                pop bp
                ret

nodo_nuevo:     push bp
                mov bp, sp
                
                mov eax, null
                push nodo_LD
                call alloc
                add sp, 4
                cmp eax, null
                jz nodo_nuevo_fin
                mov [eax+val], [bp+8]
                mov [eax+ant], null                
                mov [eax+sig], null

nodo_nuevo_fin: mov sp, bp
                pop bp
                ret



lista_doble:        push bp
                    mov bp, sp
                    push eax
                    push ebx
                    push edx
                    push efx

                    mov edx, [bp+8] ; puntero a la cabeza
                    mov eax, [bp+12] ; puntero al nodo a insertar
                    mov ebx, [edx]

                    cmp ebx, null
                    jz insertar_primero
                    cmp [ebx+val], [eax+val]
                    jp insertar_inicio
comparar:           cmp ebx, null
                    jz insertar_final
                    cmp [ebx+val], [eax+val]
                    jz fin_insercion ; no inserta nodos repetidos
                    jp insertar_medio
                    mov edx, ebx
                    mov ebx, [ebx+sig]
                    jmp comparar

insertar_primero:   mov [edx], eax
                    jmp fin_insercion

insertar_inicio:    mov [ebx+ant], eax
                    mov [eax+sig], ebx
                    mov [edx], eax
                    jmp fin_insercion

insertar_final:     mov ebx, edx
                    mov [ebx+sig], eax
                    mov [eax+ant], ebx
                    jmp fin_insercion

insertar_medio:     mov [eax+sig], ebx
                    mov efx, [ebx+ant]
                    mov [efx+sig], eax
                    mov [eax+ant], efx
                    mov [ebx+ant], eax
                    jmp fin_insercion

fin_insercion:      pop efx
                    pop edx
                    pop ebx
                    pop eax
                    mov sp, bp
                    pop bp
                    ret
