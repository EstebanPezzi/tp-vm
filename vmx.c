#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vmx.h"
#include "instructions.h"

void vm_init(VM *vm)
{
    memset(vm->memory, 0, MEMORY_SIZE);
    memset(vm->segment_table, 0, sizeof(vm->segment_table));
    memset(vm->registers, 0, sizeof(vm->registers));
    srand(time(NULL)); //semilla distinta cada vez que ejecuto el programa para funcion rand()
    vm->running = false;
}

int vm_load_program(VM *vm, const char *filename)
{
    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        return 0;
    }

    // Leer encabezado
    char identifier[6];
    fread(identifier, 1, 5, file);
    identifier[5] = '\0';
    printf("%s\n", identifier);
    if (strcmp(identifier, "VMX25") != 0)
    {
        fclose(file);
        return -1;
    }

    uint8_t version;
    fread(&version, 1, 1, file);
    printf("%d\n", version);
    if (version != 1)
    {
        fclose(file);
        return 0;
    }

    uint16_t code_size;
    fread(&code_size, 2, 1, file);

    // Cargar el codigo en la memoria
    fread(vm->memory, 1, code_size, file);
    fclose(file);

    // Inicializar tabla de segmentos
    // PREGUNTAR SI ES ASI O AL REVES
    // Tabla de descriptores de segmentos
    // Consta de 8 entradas de 32 bits, cada una se divide en dos partes: los primeros 2 bytes
    // son para guardar la dirección física de comienzo del segmento (base) y los siguientes 2
    // bytes la cantidad de bytes que ocupa. Se inicializa en el momento de la carga del programa.

    vm->segment_table[0] = (code_size << 16) | 0;
    vm->segment_table[1] = ((MEMORY_SIZE - code_size) << 16) | code_size;

    // Inicializar registros
    vm->registers[REG_CS] = 0x00000000;            // Puntero al segmento de codigo
    vm->registers[REG_DS] = 0x00010000;            // Puntero al segmento de datos
    vm->registers[REG_IP] = vm->registers[REG_CS]; // IP apunta al inicio del code segment


    vm->running = true;
    return 1;
}

void vm_execute(VM *vm)
{
    while (vm->running)
    {
        // FETCH: Lee la instruccion desde el IP
        uint32_t ip = vm->registers[REG_IP];
        printf("\n[VM] IP = %08X\n", ip); //DEBUG

        uint16_t seg = ip >> 16;
        uint16_t offset = ip & 0xFFFF;
        if (seg != 0)
            break; // Fuera de codigo

        uint16_t base = vm->segment_table[seg] & 0xFFFF;
        uint16_t tam = vm->segment_table[seg] >> 16 & 0xFFFF;
        if (offset >= tam)
            break;

        uint16_t phys = base + offset;
        // Leo el primer byte
        uint8_t first_byte = vm->memory[phys++];
        printf("[VM] First byte = %02X\n", first_byte);
        uint8_t type_b = first_byte >> 6;
        uint8_t type_a = (first_byte >> 4) & 0b0011;
        uint8_t op_code = first_byte & 0x1F;
        printf("[VM] Opcode = %02X, type_a = %d, type_b = %d\n", op_code, type_a, type_b);

        if (op_code > 0x1F)
        {
            printf("Instruccion invalida 0x%02X en %04X\n", first_byte, phys);
            break;
        }

        int instr_len = 1 + type_a + type_b;

        // Leo OP B
        uint16_t p = phys;
        uint32_t opb_bytes = 0;
        if (type_b > 0x0)
            opb_bytes |= vm->memory[p++];
        if (type_b > 0x1)
            opb_bytes = (opb_bytes << 8) | vm->memory[p++];
        if (type_b > 0x2)
            opb_bytes = (opb_bytes << 16) | vm->memory[p++];

        // LEO OP A
        uint32_t opa_bytes = 0;
        if (type_a > 0)
            opa_bytes |= vm->memory[p++];
        if (type_a > 1)
            opa_bytes = (opa_bytes << 8) | vm->memory[p++];
        if (type_a > 2)
            opa_bytes = (opa_bytes << 16) | vm->memory[p++];

        printf("[VM] OP1 raw = %08X, OP2 raw = %08X\n", (type_a << 24) | opa_bytes, (type_b << 24) | opb_bytes);

        // Seteo OP1 y OP2
        vm->registers[REG_OP1] = (type_a << 24) | opa_bytes;
        vm->registers[REG_OP2] = (type_b << 24) | opb_bytes;
        vm->registers[REG_OPC] = op_code;

        uint16_t new_off = offset + instr_len;
        uint16_t code_size = vm->segment_table[0] >> 16;
        if (new_off >= code_size)
        {
            vm->memory[REG_IP] = 0xFFFF0000;
            break;
        }

        vm->registers[REG_IP] = (ip & 0xFFFF0000) | new_off;

        // Crear la ejecucion de la instruccion
        InstructionFunc func = instruction_table[op_code];
        if (func) {
            func(vm);   // ejecutar instrucción
        } else {
            printf("Opcode 0x%02X no implementado\n", op_code);
            vm->running = false;
        }
           printf("[DEBUG] IP = %08X\n", vm->registers[REG_IP]);
    }
}

int main(int argc, char **argv)
{
    printf("Cant args %d\n", argc);
    VM vm;
    init_instruction_table(); // Inicializa la tabla de instrucciones

    // Comentado para Debbugear
    // if (argc < 2)
    //     return 1;
    const char *filename = argv[1];
    bool disassemble = (argc == 3 && strcmp(argv[2], "-d") == 0);
    vm_init(&vm);

    if (vm_load_program(&vm, filename) == 0)
    {
        printf("Error: no se pudo cargar el archivo '%s'\n", filename);
        return 1;
    }

    if (disassemble)
    {
        printf("Dissassemble on\n");
    }

    vm_execute(&vm);
    printf("\nEstado final de los registros:\n");
    printf("EAX = %08X\n", vm.registers[REG_EAX]);
    printf("EBX = %08X\n", vm.registers[REG_EBX]);
    printf("EDX = %08X\n", vm.registers[REG_EDX]);
    printf("AC = %08X\n", vm.registers[REG_AC]);
    printf("CC = %08X\n", vm.registers[REG_CC]);
    return 0;
}