#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Memoria principal: 16 KiB
#define MEMORY_SIZE 16384

// Tabla de descriptores de segmentos: 8 entradas de 4 bytes cada una
#define SEGMENT_TABLE_SIZE 8

// Registros: 32 de 4 bytes
#define NUM_REGISTERS 32

// Códigos de registros PARTE 1
#define REG_LAR 0
#define REG_MAR 1
#define REG_MBR 2
#define REG_IP 3
#define REG_OPC 4
#define REG_OP1 5
#define REG_OP2 6
#define REG_EAX 10
#define REG_EBX 11
#define REG_ECX 12
#define REG_EDX 13
#define REG_EEX 14
#define REG_EFX 15
#define REG_AC 16
#define REG_CC 17
#define REG_CS 26
#define REG_DS 27

// Códigos de operaciones (opcodes)
#define OPC_MOV 0x10
#define OPC_ADD 0x11
#define OPC_SUB 0x12
#define OPC_MUL 0x13
#define OPC_DIV 0x14
#define OPC_CMP 0x15
#define OPC_SHL 0x16
#define OPC_SHR 0x17
#define OPC_SAR 0x18
#define OPC_AND 0x19
#define OPC_OR 0x1A
#define OPC_XOR 0x1B
#define OPC_SWAP 0x1C
#define OPC_LDL 0x1D
#define OPC_LDH 0x1E
#define OPC_RND 0x1F
#define OPC_SYS 0x00
#define OPC_JMP 0x01
#define OPC_JZ 0x02
#define OPC_JP 0x03
#define OPC_JN 0x04
#define OPC_JNZ 0x05
#define OPC_JNP 0x06
#define OPC_JNN 0x07
#define OPC_NOT 0x08
#define OPC_STOP 0x0F

// Tipos de operandos
#define OP_TYPE_NONE 0x00
#define OP_TYPE_REGISTER 0x01
#define OP_TYPE_IMMEDIATE 0x10
#define OP_TYPE_MEMORY 0x11

// Estructura para la VM
typedef struct
{
    uint8_t memory[MEMORY_SIZE];
    uint32_t segment_table[SEGMENT_TABLE_SIZE];
    int32_t registers[NUM_REGISTERS];
    bool running;
} VM;

// Funciones principales
void vm_init(VM *vm);
int vm_load_program(VM *vm, const char *filename);
void vm_execute(VM *vm);

void vm_init(VM *vm)
{
    memset(vm->memory, 0, MEMORY_SIZE);
    memset(vm->segment_table, 0, sizeof(vm->segment_table));
    memset(vm->registers, 0, sizeof(vm->registers));
    vm->running = false;
}

int vm_load_program(VM *vm, const char *filename)
{
    FILE *file = fopen("test.vmx", "rb");
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
        // Print para debbuging
        printf("First byte %X", first_byte);
        uint8_t type_b = first_byte >> 6;
        uint8_t type_a = (first_byte >> 4) & 0b0011;
        uint8_t op_code = first_byte & 0x1F;

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
    }
}

int main(int argc, char **argv)
{
    printf("Cant args %d\n", argc);
    VM vm;
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
    return 0;
}