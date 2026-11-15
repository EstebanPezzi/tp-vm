\\extra 1024
\\include "lista_simple.asm"
\\include "eliminar_nodo.asm"

null equ -1
main:           push bp
                mov bp, sp

                call heap_init

                sub sp, root
                mov [bp-root], null
                mov ebx, bp
                sub ebx, root

                push 5
                call crear_nodo_LD
                add sp, 4

                push ebx
                push eax
                call agregar_nodo
                add sp, 8

                push 7
                call crear_nodo_LD
                add sp, 4

                push ebx
                push eax
                call agregar_nodo
                add sp, 8

                push 20
                call crear_nodo_LD
                add sp, 4

                push ebx
                push eax
                call agregar_nodo
                add sp, 8

                push 32
                call crear_nodo_LD
                add sp, 4

                push ebx
                push eax
                call agregar_nodo
                add sp, 8

                mov efx, [ebx]
                ldl ecx, 1
                ldh ecx, 4
                mov eax, 1
list_print_imp: cmp     efx, null
                mov edx, efx
                jz      list_print_fin
                sys     0x2
                mov     efx, [efx+sig]
                jmp     list_print_imp

list_print_fin: push ebx
                push 21
                call eliminar_nodo
                add sp, 4

                mov efx, [ebx]
                ldl ecx, 1
                ldh ecx, 4
                mov eax, 1
list_print:     cmp     efx, null
                mov edx, efx
                jz      fin
                sys     0x2
                mov     efx, [efx+sig]
                jmp     list_print

fin:            ret