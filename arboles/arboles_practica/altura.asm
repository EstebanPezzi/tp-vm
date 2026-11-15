altura:     push bp
            mov bp, sp
            push ebx
            push edx
            push eex
            push efx
            mov edx, [bp+8]
            mov ebx, [edx]

            cmp ebx, null
            mov eax, 0
            jz fin_altura
            
            add ebx, izq
            push ebx
            call altura
            add sp, 4
            mov eex, eax

            mov ebx, [edx]
            add ebx, der
            push ebx
            call altura
            add sp, 4
            mov efx, eax

            cmp eex, efx
            jn max_der
            mov eax, eex
max_der:    mov eax, efx
            add eax, 1

fin_altura: pop efx
            pop eex
            pop edx
            pop ebx
            mov sp, bp
            pop bp
            ret

