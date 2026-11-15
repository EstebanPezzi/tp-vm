\\STACK 1024
\\include "lista_doble.asm"
\\include "eliminar_repetidos_LD.asm"
\\include "print_nodo.asm"

main:           push bp
                mov bp, sp
                sub sp, 4
                call heap_init
                mov [bp-4], null
                mov ebx, bp
                sub ebx, 4

                push 4
                call nodo_nuevo
                add sp, 4

                push eax
                push ebx
                call lista_doble
                add sp, 8

                push 5
                call nodo_nuevo
                add sp, 4

                push eax
                push ebx
                call lista_doble
                add sp, 8
        
                push 4
                call nodo_nuevo
                add sp, 4

                push eax
                push ebx
                call lista_doble
                add sp, 8

                push 8
                call nodo_nuevo
                add sp, 4

                push eax
                push ebx
                call lista_doble
                add sp, 8


                push 4
                call nodo_nuevo
                add sp, 4

                push eax
                push ebx
                call lista_doble
                add sp, 8

                push 7
                call nodo_nuevo
                add sp, 4

                push eax
                push ebx
                call lista_doble
                add sp, 8

                push 7
                call nodo_nuevo
                add sp, 4

                push eax
                push ebx
                call lista_doble
                add sp, 8

                push 4
                call nodo_nuevo
                add sp, 4

                push eax
                push ebx
                call lista_doble
                add sp, 8

                push 8
                call nodo_nuevo
                add sp, 4

                push eax
                push ebx
                call lista_doble
                add sp, 8

repetidos:      push [ebx]
                call eliminar_repetidos
                add sp, 4

                mov efx, [ebx]
                mov eax, 1
                ldl ecx, 1
                ldh ecx, 4
mostrar_nodos:  mov edx, efx
                cmp edx, null
                jz fin
                sys 2
                mov efx, [efx+sig]
                jmp mostrar_nodos

fin:            ret

heap_init:      mov [es], es
                add [es], 4
                ret


