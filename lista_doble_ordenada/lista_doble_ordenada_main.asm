\\STACK 1024
\\include "lista_doble_ordenada.asm"

main:           push bp
                mov bp, sp
                sub sp, 4
                call heap_init
                mov [bp-4], null
                mov ebx, bp
                sub ebx, 4

                push 54
                call nodo_nuevo
                add sp, 4

                push eax
                push ebx
                call lista_doble
                add sp, 8

                push 26
                call nodo_nuevo
                add sp, 4

                push eax
                push ebx
                call lista_doble
                add sp, 8
        
                push 12
                call nodo_nuevo
                add sp, 4

                push eax
                push ebx
                call lista_doble
                add sp, 8

                push 100
                call nodo_nuevo
                add sp, 4

                push eax
                push ebx
                call lista_doble
                add sp, 8


                push 45
                call nodo_nuevo
                add sp, 4

                push eax
                push ebx
                call lista_doble
                add sp, 8

                push 12
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

                push 154
                call nodo_nuevo
                add sp, 4

                push eax
                push ebx
                call lista_doble
                add sp, 8


                mov efx, [ebx]
                mov eax, 1
                mov edx, efx
                LDL ecx, 1
                LDH ecx, 4
                sys 2

                mov efx, [efx+sig]
                mov edx, efx
                sys 2

                mov efx, [efx+sig]
                mov edx, efx
                sys 2

                mov efx, [efx+sig]
                mov edx, efx
                sys 2

                mov efx, [efx+sig]
                mov edx, efx
                sys 2

                mov efx, [efx+sig]
                mov edx, efx
                sys 2

                mov efx, [efx+sig]
                mov edx, efx
                sys 2

                ret

heap_init:      mov [es], es
                add [es], 4
                ret


