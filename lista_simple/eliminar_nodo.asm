eliminar_nodo:  push bp
                mov bp, sp
                push ebx
                push ecx
                push edx
                mov edx, [bp+12]
                mov ebx, [edx]

                cmp ebx, null
                jz fin_eliminar

                cmp [ebx+val], [bp+8]
                jnz busco_nodo
                mov [edx], [ebx+sig]
                jmp fin_eliminar

busco_nodo:     mov ecx, ebx ; anterior
                mov ebx, [ebx+sig]
                cmp ebx, null
                jz fin_eliminar
                cmp [ebx+val], [bp+8]
                jnz busco_nodo

                mov [ecx+sig], [ebx+sig]
fin_eliminar:   pop edx
                pop ecx
                pop ebx
                mov sp, bp
                pop bp
                ret

                