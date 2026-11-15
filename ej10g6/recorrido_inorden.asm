mostrar_nodo_arbol:     push bp
                        mov bp, sp
                        push eax
                        push ecx
                        push edx

                        mov edx, [bp+8]
                        mov eax, 1
                        ldl ecx, 1
                        ldh ecx, 4
                        sys 2
                        pop edx
                        pop ecx
                        pop eax
                        mov sp, bp
                        pop bp
                        ret



inorden:                push bp
                        mov bp, sp
                        push ebx
                        push edx

                        mov ebx, [bp+8]

                        cmp ebx, null
                        jz fin_inorden

                        push ebx
                        call mostrar_nodo_arbol
                        add sp,4

                        mov edx, [ebx+izq]
                        push edx
                        call inorden
                        add sp,4

                        mov edx, [ebx+der]
                        push edx
                        call inorden
                        add sp,4

fin_inorden:            pop edx
                        pop ebx
                        mov sp, bp
                        pop bp
                        ret

