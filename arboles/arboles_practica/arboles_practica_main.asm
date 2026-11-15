\\extra 2024
\\include "crear_arbol.asm"
\\include "recorrido_inorden.asm"
\\include "recorrido_posorden.asm"
\\include "recorrido_preorden.asm"
\\include "buscar.asm"
\\include "altura.asm"

size_extra equ 1024
null equ -1
root equ 4
main:       push bp
            mov bp, sp
            sub sp, root

            call heap_init

            mov [bp-root], null
            mov ebx, bp
            sub ebx, root

            push 20
            call crear_nodo
            add sp, 4

            push ebx
            push eax
            call agregar_nodo_arbol
            add sp, 8

            push 4
            call crear_nodo
            add sp, 4

            push ebx
            push eax
            call agregar_nodo_arbol
            add sp, 8

            push 17
            call crear_nodo
            add sp, 4

            push ebx
            push eax
            call agregar_nodo_arbol
            add sp, 8

            push 21
            call crear_nodo
            add sp, 4

            push ebx
            push eax
            call agregar_nodo_arbol
            add sp, 8

            push 1
            call crear_nodo
            add sp, 4

            push ebx
            push eax
            call agregar_nodo_arbol
            add sp, 8

            push 35
            call crear_nodo
            add sp, 4

            push ebx
            push eax
            call agregar_nodo_arbol
            add sp, 8

            push 39
            call crear_nodo
            add sp, 4

            push ebx
            push eax
            call agregar_nodo_arbol
            add sp, 8

            push 34
            call crear_nodo
            add sp, 4

            push ebx
            push eax
            call agregar_nodo_arbol
            add sp, 8

            push [ebx]
            call inorden
            add sp, 4

            mov eax, 0
            push ebx
            push 5
            call buscar
            add sp, 8
            
            mov edx, ds
            mov [edx], eax
            mov eax, 1
            ldl ecx, 1
            ldh ecx, 4
            sys 2

            mov eax, 0

            push ebx
            call altura
            add sp, 4

            mov edx, ds
            mov [edx], eax
            mov eax, 1
            ldl ecx, 1
            ldh ecx, 4
            sys 2
            
            ret