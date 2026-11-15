\\extra 2024
\\include "crear_arbol.asm"
\\include "recorrido_inorden.asm"
\\include "eliminar_nodo_LS.asm"
\\include "buscar.asm"
\\include "lista_simple.asm"
\\include "mostrar_lista.asm"
\\include "busqueda_y_eliminacion.asm"

size_extra equ 1024
null equ -1
root equ 4
rootAB equ 8
rootLD equ 4
main:           push bp
                mov bp, sp

                call heap_init

                sub sp, root
                mov [bp-rootLD], null
                mov edx, bp
                sub edx, rootLD
                
                sub sp, root
                mov [bp-rootAB], null
                mov ebx, bp
                sub ebx, rootAB

                push ebx
                push 10
                call crear_nodo_arbol
                add sp, 8

                push ebx
                push 8
                call crear_nodo_arbol
                add sp, 8

                push ebx
                push 1
                call crear_nodo_arbol
                add sp, 8

                push ebx
                push 20
                call crear_nodo_arbol
                add sp, 8

                push ebx
                push 21
                call crear_nodo_arbol
                add sp, 8

                push ebx
                push 16
                call crear_nodo_arbol
                add sp, 8

                push edx
                push 16
                call agregar_nodo_LS
                add sp, 8

                push edx
                push 6
                call agregar_nodo_LS
                add sp, 8

                push edx
                push 8
                call agregar_nodo_LS
                add sp, 8

                push edx
                push 1
                call agregar_nodo_LS
                add sp, 8

                push edx
                push 2
                call agregar_nodo_LS
                add sp, 8

                push edx
                push 10
                call agregar_nodo_LS
                add sp, 8

                push edx ; **nodo lista
                push ebx ; **nodo arbol
                call busquedar_y_elim
                add sp, 8

                push [edx]
                call mostrar_lista
                add sp, 4
                
                ret


