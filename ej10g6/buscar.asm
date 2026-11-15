buscar:     push bp
            mov bp, sp
            push ebx
            push edx
            mov edx, [bp+12]
            mov ebx, [edx]

            cmp eax, 1
            jz fin_buscar
            cmp ebx, null
            jz fin_buscar

            cmp [ebx+val], [bp+8]
            jz encontrado
            jp buscar_izq
            jn buscar_der

buscar_izq: add ebx, izq
            push ebx
            push [bp+8]
            call buscar
            add sp, 8
            jmp fin_buscar

buscar_der: add ebx, der
            push ebx
            push [bp+8]
            call buscar
            add sp, 8
            jmp fin_buscar

encontrado: mov eax, 1
fin_buscar: pop edx
            pop ebx
            mov sp, bp
            pop bp
            ret