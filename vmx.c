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
#define OP_TYPE_NONE 0b00
#define OP_TYPE_REGISTER 0b01
#define OP_TYPE_IMMEDIATE 0b10
#define OP_TYPE_MEMORY 0b11

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
typedef void (*InstructionFunc)(VM *vm); // Para el vector punto a función

void instr_MOV(VM *vm);
void instr_ADD(VM *vm);
void instr_SUB(VM *vm);
void instr_MUL(VM *vm);
void instr_DIV(VM *vm);
void instr_CMP(VM *vm);
void instr_SHL(VM *vm);
void instr_SHR(VM *vm);
void instr_SAR(VM *vm);
void instr_AND(VM *vm);
void instr_OR(VM *vm);
void instr_XOR(VM *vm);
void instr_SWAP(VM *vm);
void instr_LDL(VM *vm);
void instr_LDH(VM *vm);
void instr_RND(VM *vm);
void instr_SYS(VM *vm);
void instr_JMP(VM *vm);
void instr_JZ(VM *vm);
void instr_JP(VM *vm);
void instr_JN(VM *vm);
void instr_JNZ(VM *vm);
void instr_JNP(VM *vm);
void instr_JNN(VM *vm);
void instr_NOT(VM *vm);
void instr_STOP(VM *vm);
void update_flags(VM *vm, int32_t result);
uint32_t get_operand_value(VM *vm, uint32_t op_reg);
void set_operand_value(VM *vm, uint32_t op_reg, uint32_t value);

InstructionFunc instruction_table[0x20];
void init_instruction_table();

// Prototipos de funciones auxiliares usadas en instructions.c
uint32_t translate_logical(VM *vm, uint32_t logical_addr, uint16_t num_bytes);
uint32_t vm_memory_read(VM *vm, uint32_t logical_addr, uint8_t num_bytes);
uint32_t vm_memory_write(VM *vm, uint32_t logical_addr, uint8_t num_bytes, uint32_t value);

void vm_init(VM *vm)
{
    memset(vm->memory, 0, MEMORY_SIZE);
    memset(vm->segment_table, 0, sizeof(vm->segment_table));
    memset(vm->registers, 0, sizeof(vm->registers));
    srand(time(NULL)); // semilla distinta cada vez que ejecuto el programa para funcion rand()
    vm->running = true;
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

    uint8_t code_size_bytes[2];
    fread(code_size_bytes, 1, 2, file);
    uint16_t code_size = (code_size_bytes[0] << 8) | code_size_bytes[1]; // Big-endian: byte0=alto, byte1=bajo
    printf("Code size %u\n", code_size);                                 // Cambia %x a %u para decimal

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
    printf("tamanio data segment %d\n", MEMORY_SIZE - code_size);

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
        printf("\n[VM] IP = %08X\n", ip); // DEBUG

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
        uint32_t opb_bytes = 0x0;
        if (type_b > 0x0)
            opb_bytes |= vm->memory[p++];
        if (type_b > 0x1)
            opb_bytes = (opb_bytes << 8) | vm->memory[p++];
        if (type_b > 0x2)
            opb_bytes = (opb_bytes << 8) | vm->memory[p++];

        // LEO OP A
        uint32_t opa_bytes = 0;
        if (type_a > 0)
            opa_bytes |= vm->memory[p++];
        printf("\n%x\n", opa_bytes);
        if (type_a > 1)
            opa_bytes = (opa_bytes << 8) | vm->memory[p++];
        printf("\n%x\n", opa_bytes);
        if (type_a > 2)
            opa_bytes = (opa_bytes << 8) | vm->memory[p++];
        printf("\n%x\n", opa_bytes);

        printf("[VM] OP1 raw = %08X, OP2 raw = %08X\n", (type_a << 24) | opa_bytes, (type_b << 24) | opb_bytes);

        // Seteo OP1 y OP2
        if (op_code != 0x8) // Si no es NOT
        {
            vm->registers[REG_OP1] = (type_a << 24) | opa_bytes;
            vm->registers[REG_OP2] = (type_b << 24) | opb_bytes;
            vm->registers[REG_OPC] = op_code;
        }
        else // Si es NOT ponemos en el registro OP1 opb_bytes y tipo
        {
            vm->registers[REG_OP1] = (type_b << 24) | opb_bytes;
            vm->registers[REG_OPC] = op_code;
        }

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
        if (func)
        {
            func(vm); // ejecutar instrucción
        }
        else
        {
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
    const char *filename = "test.vmx";
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
void init_instruction_table()
{
    // Inicializar a NULL
    for (int i = 0; i < 0x20; i++)
    {
        instruction_table[i] = NULL;
    }

    // Asignaciones
    instruction_table[OPC_MOV] = instr_MOV;
    instruction_table[OPC_ADD] = instr_ADD;
    instruction_table[OPC_SUB] = instr_SUB;
    instruction_table[OPC_MUL] = instr_MUL;
    instruction_table[OPC_DIV] = instr_DIV;
    instruction_table[OPC_CMP] = instr_CMP;
    instruction_table[OPC_SHL] = instr_SHL;
    instruction_table[OPC_SHR] = instr_SHR;
    instruction_table[OPC_SAR] = instr_SAR;
    instruction_table[OPC_AND] = instr_AND;
    instruction_table[OPC_OR] = instr_OR;
    instruction_table[OPC_XOR] = instr_XOR;
    instruction_table[OPC_SWAP] = instr_SWAP;
    instruction_table[OPC_LDL] = instr_LDL;
    instruction_table[OPC_LDH] = instr_LDH;
    instruction_table[OPC_RND] = instr_RND;
    instruction_table[OPC_SYS] = instr_SYS;
    instruction_table[OPC_JMP] = instr_JMP;
    instruction_table[OPC_JZ] = instr_JZ;
    instruction_table[OPC_JP] = instr_JP;
    instruction_table[OPC_JN] = instr_JN;
    instruction_table[OPC_JNZ] = instr_JNZ;
    instruction_table[OPC_JNP] = instr_JNP;
    instruction_table[OPC_JNN] = instr_JNN;
    instruction_table[OPC_NOT] = instr_NOT;
    instruction_table[OPC_STOP] = instr_STOP;
}

uint32_t translate_logical(VM *vm, uint32_t logical_addr, uint16_t num_bytes)
{
    uint16_t seg = (logical_addr >> 16) & 0xFFFF;
    uint16_t offset = logical_addr & 0xFFFF;

    if (seg >= SEGMENT_TABLE_SIZE)
    {
        printf("Fallo de segmento: codigo %u excede tabla.\n", seg);
        vm->running = false;
        return -1;
    }

    uint32_t entry = vm->segment_table[seg];
    uint16_t base_phys = entry & 0xFFFF;
    uint16_t seg_size = (entry >> 16) & 0xFFFF;
    if (offset + num_bytes > seg_size)
    {
        printf("Fallo de segmento: acceso fuera de lmites (offset %u + %u > %u).\n", offset, num_bytes, seg_size);
        vm->running = false;
        return -1;
    }
    return base_phys + offset;
}

uint32_t vm_memory_read(VM *vm, uint32_t logical_addr, uint8_t num_bytes)
{
    vm->registers[REG_LAR] = logical_addr;

    vm->registers[REG_MAR] = ((uint32_t)num_bytes << 16);

    uint32_t phys = translate_logical(vm, logical_addr, num_bytes);

    vm->registers[REG_MAR] |= (phys & 0xFFFF);

    uint32_t value = 0;
    for (uint8_t i = 0; i < num_bytes; i++)
    {
        uint8_t byte = vm->memory[phys + i];
        value |= ((uint32_t)byte << (i * 8));
    }
    vm->registers[REG_MBR] = value;

    return value;
}

uint32_t vm_memory_write(VM *vm, uint32_t logical_addr, uint8_t num_bytes, uint32_t value)
{
    vm->registers[REG_LAR] = logical_addr;
    vm->registers[REG_MAR] = ((uint32_t)num_bytes << 16); // MAR 2 bytes altos: numero de bytes
    uint32_t phys = translate_logical(vm, logical_addr, num_bytes);

    if (phys == (uint32_t)-1)
        return false;
    vm->registers[REG_MAR] |= (phys & 0xFFFF); // MAR baja = memoria fisica
    vm->registers[REG_MBR] = value;            // MBR valor a escribir

    for (uint8_t i = 0; i < num_bytes; i++)
        vm->memory[phys + i] = (value >> (i * 8) & 0xFF);
    return true;
}

uint32_t get_operand_value(VM *vm, uint32_t op_reg)
{
    uint8_t type = (op_reg >> 24) & 0xFF;
    uint32_t value = op_reg & 0x00FFFFFF;
    if (type == OP_TYPE_REGISTER)
        return vm->registers[value];
    else if (type == OP_TYPE_IMMEDIATE)
    {
        int32_t value2 = op_reg << 16; // Arrastro el signo
        return value2 >> 16;
    }
    else if (type == OP_TYPE_MEMORY)
    {
        uint8_t base_reg_code = (value >> 16) & 0xFF;
        int16_t disp = (int16_t)(value & 0xFFFF);
        uint32_t base_ptr = vm->registers[base_reg_code];
        uint16_t base_seg = base_ptr >> 16;
        uint16_t base_off = base_ptr & 0xFFFF;
        int32_t logical_off = (int32_t)base_off + disp;
        if (logical_off < 0)
        {
            vm->running = false;
            return 0;
        }
        uint32_t logical_addr = (base_seg << 16) | (logical_off & 0xFFFF);
        return vm_memory_read(vm, logical_addr, 4); // Por defecto 4 bytes
    }
    return 0; // Error
}

void set_operand_value(VM *vm, uint32_t op_reg, uint32_t value)
{
    uint8_t type = (op_reg >> 24) & 0xFF;
    uint32_t value_field = op_reg & 0x00FFFFFF;
    printf("\n %x \n", type);
    if (type == OP_TYPE_REGISTER)
        vm->registers[value_field] = value;
    else if (type == OP_TYPE_MEMORY)
    {
        uint8_t base_reg_code = (value_field >> 16) & 0xFF;
        int16_t disp = (int16_t)(value_field & 0xFFFF);
        uint32_t base_ptr = vm->registers[base_reg_code]; // Por ej, DS
        uint16_t base_seg = base_ptr >> 16;
        uint16_t base_off = base_ptr & 0xFFFF;
        int32_t logical_off = (int32_t)base_off + disp;
        if (logical_off < 0)
        {
            vm->running = false;
            return;
        }
        uint32_t logical_addr = (base_seg << 16) | (logical_off & 0xFFFF);
        vm_memory_write(vm, logical_addr, 4, value); // Por defecto 4 bytes
    }
}

// bits mas significativos?
void update_flags(VM *vm, int32_t result)
{
    // Actualizar el cc
    uint32_t cc = vm->registers[REG_CC];
    cc &= 0x3FFFFFFF;
    cc |= (result & 0x80000000) ? 0x80000000 : 0; // Bit 31 = N (signo)
    cc |= (result == 0) ? 0x40000000 : 0;         // Bit 30 = Z (cero)
    vm->registers[REG_CC] = cc;
}

// Se debe modularizar más ¿?

void instr_MOV(VM *vm)
{
    int32_t value = get_operand_value(vm, vm->registers[REG_OP2]);
    set_operand_value(vm, vm->registers[REG_OP1], value);
}

void instr_ADD(VM *vm)
{
    int32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]);
    int32_t val2 = get_operand_value(vm, vm->registers[REG_OP2]);

    int32_t result = val1 + val2;

    set_operand_value(vm, vm->registers[REG_OP1], result);

    update_flags(vm, result); // Actualiza el registro CC.
}

void instr_SUB(VM *vm)
{
    int32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]);
    int32_t val2 = get_operand_value(vm, vm->registers[REG_OP2]);

    int32_t result = val1 - val2;

    set_operand_value(vm, vm->registers[REG_OP1], result);

    update_flags(vm, result); // Actualiza el registro CC.
}

void instr_MUL(VM *vm)
{
    int32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]);
    int32_t val2 = get_operand_value(vm, vm->registers[REG_OP2]);

    int64_t result = (int64_t)val1 * (int64_t)val2; // para detectar overflow
    int32_t truncated = (int32_t)result;            // si hubo overflow perdes datos. analizar

    set_operand_value(vm, vm->registers[REG_OP1], result);

    update_flags(vm, truncated); // Actualiza el registro CC.
}

void instr_DIV(VM *vm)
{
    int32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]);
    int32_t val2 = get_operand_value(vm, vm->registers[REG_OP2]);

    if (val2 == 0)
    {
        printf("Error: division por cero\n");
        vm->running = false;
        return;
    }

    int32_t cociente = val1 / val2; // Division entera
    int32_t resto = val1 % val2;    // resto

    set_operand_value(vm, vm->registers[REG_OP1], cociente);
    vm->registers[REG_AC] = resto; // resto en AC

    update_flags(vm, cociente); // Actualiza el registro CC.
}

void instr_CMP(VM *vm)
{
    int32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]);
    int32_t val2 = get_operand_value(vm, vm->registers[REG_OP2]);

    int32_t result = val1 - val2;

    update_flags(vm, result); // Actualiza el registro CC.
}

void instr_SHL(VM *vm)
{
    int32_t val = get_operand_value(vm, vm->registers[REG_OP1]);
    int32_t shift = get_operand_value(vm, vm->registers[REG_OP2]);

    int32_t result = val << shift;

    set_operand_value(vm, vm->registers[REG_OP1], result);

    update_flags(vm, result); // Actualiza el registro CC.
}

void instr_SHR(VM *vm)
{
    int32_t val = get_operand_value(vm, vm->registers[REG_OP1]);
    int32_t shift = get_operand_value(vm, vm->registers[REG_OP2]);

    // Revisar ->. mascara?
    uint32_t uval = (uint32_t)val;   // convertir a unsigned para shift lógico
    uint32_t result = uval >> shift; // corrimiento lógico

    set_operand_value(vm, vm->registers[REG_OP1], (int32_t)result);

    update_flags(vm, result); // Actualiza el registro CC.
}

void instr_SAR(VM *vm)
{
    int32_t val = get_operand_value(vm, vm->registers[REG_OP1]);
    int32_t shift = get_operand_value(vm, vm->registers[REG_OP2]);

    int32_t result = val >> shift; // en C el shift es aritmético

    set_operand_value(vm, vm->registers[REG_OP1], result);

    update_flags(vm, result); // Actualiza el registro CC.
}

void instr_AND(VM *vm)
{
    int32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]);
    int32_t val2 = get_operand_value(vm, vm->registers[REG_OP2]);

    int32_t result = val1 & val2;

    set_operand_value(vm, vm->registers[REG_OP1], result);

    update_flags(vm, result); // Actualiza el registro CC.
}

void instr_OR(VM *vm)
{
    int32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]);
    int32_t val2 = get_operand_value(vm, vm->registers[REG_OP2]);

    int32_t result = val1 | val2;

    set_operand_value(vm, vm->registers[REG_OP1], result);

    update_flags(vm, result); // Actualiza el registro CC.
}

void instr_XOR(VM *vm)
{
    int32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]);
    int32_t val2 = get_operand_value(vm, vm->registers[REG_OP2]);

    int32_t result = val1 ^ val2;

    set_operand_value(vm, vm->registers[REG_OP1], result);

    update_flags(vm, result); // Actualiza el registro CC.
}

void instr_SWAP(VM *vm)
{
    int32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]);
    int32_t val2 = get_operand_value(vm, vm->registers[REG_OP2]);

    // Intercambiar
    set_operand_value(vm, vm->registers[REG_OP1], val2);
    set_operand_value(vm, vm->registers[REG_OP2], val1);

    // No modifica CC
}

void instr_LDH(VM *vm)
{
    int32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]); // destino
    int32_t val2 = get_operand_value(vm, vm->registers[REG_OP2]); // fuente

    // Tomamos los 16 bits menos significativos de val2
    int32_t low16 = val2 & 0xFFFF;

    // Limpiamos los 16 bits más significativos de val1 y los reemplazamos con low16
    int32_t result = (low16 << 16) | (val1 & 0xFFFF);

    set_operand_value(vm, vm->registers[REG_OP1], result);

    // No modificamos CC
}

// hay algo que no anda
void instr_LDL(VM *vm)
{
    int32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]); // destino
    int32_t val2 = get_operand_value(vm, vm->registers[REG_OP2]); // fuente

    // Tomamos los 16 bits menos significativos de val2
    int32_t low16 = val2 & 0xFFFF;

    // Conservo los 16 bits altos de val1, y meto los 16 bits bajos de val2
    int32_t result = (val1 & 0xFFFF0000) | low16;

    set_operand_value(vm, vm->registers[REG_OP1], result);

    // No modificamos CC
}

void instr_RND(VM *vm)
{
    int32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]);
    int32_t max = get_operand_value(vm, vm->registers[REG_OP2]);

    if (max < 0)
    {
        max = -max; // aseguramos que sea positivo
    }

    int32_t rnd = (max == 0) ? 0 : rand() % (max + 1); // numero entre 0 y max. el +1 incluye a max

    set_operand_value(vm, vm->registers[REG_OP1], rnd);
}

// Revisar
void instr_SYS(VM *vm)
{
    uint32_t op_mode = get_operand_value(vm, vm->registers[REG_OP2]); // 1=READ, 2=WRITE
    uint32_t fmt = vm->registers[REG_EAX];                            // formato: 0x01 DEC, 0x10 BIN, 0x08 HEX, 0x04 OCT, 0x02 CHAR
    uint32_t start_addr = vm->registers[REG_EDX];
    uint32_t ecx = vm->registers[REG_ECX];

    uint16_t cell_size = ecx >> 16;
    uint16_t cell_count = ecx & 0xFFFF;

    for (int i = 0; i < cell_count; i++)
    {
        uint32_t logical_addr = start_addr + i * cell_size;
        uint32_t phys_addr = translate_logical(vm, logical_addr, cell_size);
        if (phys_addr == (uint32_t)-1)
            return;

        if (op_mode == 1)
        { // READ
            int value;
            scanf("%d", &value);
            vm_memory_write(vm, logical_addr, cell_size, value);
        }
        else if (op_mode == 2)
        { // WRITE
            uint32_t value = vm_memory_read(vm, logical_addr, cell_size);
            switch (fmt)
            {
            case 0x01:
                printf("%u\n", value);
                break; // DEC
            case 0x10:
            { // BIN
                for (int b = cell_size * 8 - 1; b >= 0; b--)
                    printf("%u", (value >> b) & 1);
                printf("\n");
                break;
            }
            case 0x08:
                printf("%X\n", value);
                break; // HEX
            case 0x04:
                printf("%o\n", value);
                break; // OCT
            case 0x02:
                printf("%c\n", (char)value);
                break; // CHAR
            default:
                printf("Formato inválido: 0x%X\n", fmt);
                vm->running = false;
                return;
            }
        }
        else
        {
            printf("Modo SYS inválido: %u\n", op_mode);
            vm->running = false;
            return;
        }
    }
}

void instr_JMP(VM *vm)
{
    int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]); // Direccion del salto

    vm->registers[REG_IP] = direc;
}

// Revisar las condiciones de salto, me maree un poco
void instr_JZ(VM *vm)
{

    if (vm->registers[REG_CC] & 0x40000000)
    { // IF Z==1
        int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]);
        vm->registers[REG_IP] = direc;
    }
}

void instr_JP(VM *vm)
{ // solo si N no es 1 revisar

    if (!(vm->registers[REG_CC] & 0x80000000))
    { // N = 0 y Z = 0
        int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]);
        vm->registers[REG_IP] = direc;
    }
}

void instr_JN(VM *vm)
{

    if (vm->registers[REG_CC] & 0x80000000)
    {
        int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]);
        vm->registers[REG_IP] = direc;
    }
}

void instr_JNZ(VM *vm)
{

    if (!(vm->registers[REG_CC] & 0x40000000))
    {
        int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]);
        vm->registers[REG_IP] = direc;
    }
}

//????
void instr_JNP(VM *vm)
{
    if ((vm->registers[REG_CC] & 0x03) != 0)
    { // IF  Z o N activas
        int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]);
        vm->registers[REG_IP] = direc;
    }
}

void instr_JNN(VM *vm)
{

    if (!(vm->registers[REG_CC] & 0x80000000))
    { // IF
        int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]);
        vm->registers[REG_IP] = direc;
    }
}

// Seria con el operando 2?
void instr_NOT(VM *vm)
{
    uint32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]);
    printf("VALOR%X\n", val1);

    uint32_t result = ~val1; // Negación bit a bit
    printf("VALOR INVERTIDO%X\n", val1);
    set_operand_value(vm, vm->registers[REG_OP1], result); // Guardar el resultado

    update_flags(vm, result); // Actualiza el registro CC.
}

// LO DE LA IP ESTÁ BIEN ¿?
void instr_STOP(VM *vm)
{
    vm->registers[REG_IP] = 0xFFFFFFFF; // IP inválida para indicar fin de ejecución
    vm->running = false;
}