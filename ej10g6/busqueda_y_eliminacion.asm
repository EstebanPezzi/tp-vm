busquedar_y_elim:       push bp
                        mov bp, sp
                        push eax
                        push ebx
                        push ecx
                        push edx

                        mov ebx, [bp+8] ; **nodo arbol
                        mov edx, [bp+12] ; **nodo lista

                        mov ecx, [edx]
avanzo_lista:           cmp ecx, null
                        jz fin_busqueda_y_elim
                        mov eax, 0
                        push ebx
                        push [ecx+val]
                        call buscar ; buscar en el arbol si el valor existe
                        add sp, 8
                        cmp eax, 1
                        jz eliminar_nodo_LS
                        mov ecx, [ecx+sig]
                        jmp avanzo_lista

eliminar_nodo_LS:       push edx
                        push [ecx+val]
                        call eliminar_nodo
                        add sp, 4
                        mov ecx, [ecx+sig]
                        jmp avanzo_lista

fin_busqueda_y_elim:    pop edx
                        pop ecx
                        pop ebx
                        pop eax
                        mov sp, bp
                        pop bp
                        ret