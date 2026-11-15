preorden:               push bp
                        mov bp, sp
                        push ebx
                        push edx

                        mov ebx, [bp+8]

                        cmp ebx, null
                        jz fin_preorden

                        mov edx, [ebx+izq]
                        push edx
                        call inorden
                        add sp,4

                        push ebx
                        call mostrar_nodo_arbol
                        add sp,4

                        mov edx, [ebx+der]
                        push edx
                        call inorden
                        add sp,4

fin_preorden:           pop edx
                        pop ebx
                        mov sp, bp
                        pop bp
                        ret

