eliminar_repetidos:     push bp
                        mov bp, sp
                        push eax
                        push ebx
                        push edx
                        push efx

                        mov edx, [bp+8]

nodo_unico:             cmp edx, null
                        jz fin_eliminar_repetidos
                        mov ebx, [edx+sig]

avanzo_repetidos:       cmp ebx, null
                        jz otro_numero
                        cmp [ebx+val], [edx+val]
                        jnz busco_repetidos
                        mov efx, [ebx+ant] ; nodo anterior
                        mov eax, [ebx+sig]  ; nodo siguiente puede ser null
                        mov ebx, eax
                        mov [efx+sig], eax
                        cmp eax, null ; si nodo sig es null
                        jz avanzo_repetidos
                        mov [eax+ant], efx
                        jmp avanzo_repetidos

busco_repetidos:        mov ebx, [ebx+sig]
                        jmp avanzo_repetidos

otro_numero:            mov edx, [edx+sig]
                        jmp nodo_unico

fin_eliminar_repetidos: pop efx
                        pop edx
                        pop ebx
                        pop eax
                        mov sp, bp
                        pop bp
                        ret
