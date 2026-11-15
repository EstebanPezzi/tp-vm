print_nodo:     push bp
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