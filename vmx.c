#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>

// Memoria por default: 16 KiB
#define DEFAULT_MEMORY_SIZE 16384

// Tabla de descriptores de segmentos: 8 entradas de 4 bytes cada una
#define SEGMENT_TABLE_SIZE 8

// Registros: 32 de 4 bytes
#define NUM_REGISTERS 32

#define REG_LAR 0
#define REG_MAR 1
#define REG_MBR 2
#define REG_IP 3
#define REG_OPC 4
#define REG_OP1 5
#define REG_OP2 6
#define REG_SP 7
#define REG_BP 8
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
#define REG_ES 28
#define REG_SS 29
#define REG_KS 30
#define REG_PS 31

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

#define OPC_PUSH 0x0B
#define OPC_POP 0x0C
#define OPC_CALL 0x0D
#define OPC_RET 0x0E

// Tipos de operandos
#define OP_TYPE_NONE 0b00
#define OP_TYPE_REGISTER 0b01
#define OP_TYPE_IMMEDIATE 0b10
#define OP_TYPE_MEMORY 0b11

// Estructura para la VM
typedef struct
{
    uint8_t *memory; // La memoria depende del valor ingresado por el que la ejecuta
    uint32_t segment_table[SEGMENT_TABLE_SIZE];
    int32_t registers[NUM_REGISTERS];
    bool running;

    int memory_size;
    bool vmi_enabled;
    char vmi_path[256];
    bool debug_step_by_step;
} VM;

// Funciones principales
void vm_init(VM *vm, int memory_size);
int vm_load_program(VM *vm, const char *filename, int memory_size, char **params, int params_count);
void vm_execute(VM *vm);
typedef void (*InstructionFunc)(VM *vm); // Para el vector punto a funcioon

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
void instr_PUSH(VM *vm);
void instr_POP(VM *vm);
void instr_CALL(VM *vm);
void instr_RET(VM *vm);

void update_flags(VM *vm, int32_t result);
uint32_t get_operand_value(VM *vm, uint32_t op_reg);
void set_operand_value(VM *vm, uint32_t op_reg, uint32_t value);

InstructionFunc instruction_table[0x20];
void init_instruction_table();
void disassemble_instruction(VM *vm, uint32_t phys_addr, uint8_t op_code, uint8_t type_a, uint8_t type_b);
void vm_disassemble(VM *vm);
void vm_debug_pause(VM *vm);

// Prototipos de funciones auxiliares usadas en instructions.c
uint32_t translate_logical(VM *vm, uint32_t logical_addr, uint16_t num_bytes);
uint32_t vm_memory_read(VM *vm, uint32_t logical_addr, uint8_t num_bytes);
uint32_t vm_memory_write(VM *vm, uint32_t logical_addr, uint8_t num_bytes, uint32_t value);
void push_to_stack(VM *vm, uint32_t value);
uint32_t pop_from_stack(VM *vm);

void vm_init(VM *vm, int memory_size)
{
    vm->memory = (uint8_t *)malloc(memory_size);
    memset(vm->memory, 0, memory_size);
    memset(vm->segment_table, 0, sizeof(vm->segment_table));
    memset(vm->registers, 0, sizeof(vm->registers));
    srand(time(NULL)); // semilla distinta cada vez que ejecuto el programa para funcion rand()
    vm->running = true;

    vm->memory_size = memory_size;
    vm->vmi_enabled = false;
    vm->vmi_path[0] = '\0'; // Habria que pasarle el path si se quiere usar VMI
    vm->debug_step_by_step = false;
}

int vm_load_program(VM *vm, const char *filename, int memory_size, char **params, int params_count)
{
    FILE *file = fopen(filename, "rb");

    if (!file)
    {
        printf("Error: no se pudo abrir el archivo '%s'\n", filename);
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
    fread(&version, 1, 1, file); // 5
    printf("%d\n", version);

    if (version != 1 && version != 2)
    {
        fclose(file);
        return 0;
    }
    else if (version == 1)
    {
        uint8_t code_size_bytes[2];
        fread(code_size_bytes, 1, 2, file);                                  // 6 - 7
        uint16_t code_size = (code_size_bytes[0] << 8) | code_size_bytes[1]; // Big-endian: byte0=alto, byte1=bajo

        fread(vm->memory, 1, code_size, file);

        vm->segment_table[0] = (code_size << 16) | 0;
        vm->segment_table[1] = ((DEFAULT_MEMORY_SIZE - code_size) << 16) | code_size;

        // Inicializar registros
        vm->registers[REG_CS] = 0x00000000;            // Puntero al segmento de codigo
        vm->registers[REG_DS] = 0x00010000;            // Puntero al segmento de datos
        vm->registers[REG_IP] = vm->registers[REG_CS]; // IP apunta al inicio del code segment
    }
    else if (version == 2)
    {
        uint8_t code_size_bytes[2];
        fread(code_size_bytes, 1, 2, file);                                          // 6 - 7
        uint16_t code_segment_size = (code_size_bytes[0] << 8) | code_size_bytes[1]; // Big-endian: byte0=alto, byte1=bajo

        uint8_t data_segment_bytes[2];
        fread(data_segment_bytes, 1, 2, file); // 8 - 9
        uint16_t data_segment_size = (data_segment_bytes[0] << 8) | data_segment_bytes[1];

        uint8_t extra_segment_bytes[2];
        fread(extra_segment_bytes, 1, 2, file); // 10 - 11
        uint16_t extra_segment_size = (extra_segment_bytes[0] << 8) | extra_segment_bytes[1];

        uint8_t stack_segment_bytes[2];
        fread(stack_segment_bytes, 1, 2, file); // 12 - 13
        uint16_t stack_segment_size = (stack_segment_bytes[0] << 8) | stack_segment_bytes[1];

        uint8_t const_segment_bytes[2];
        fread(const_segment_bytes, 1, 2, file); // 14 - 15
        uint16_t const_segment_size = (const_segment_bytes[0] << 8) | const_segment_bytes[1];

        uint8_t entry_point_offset_bytes[2];
        fread(entry_point_offset_bytes, 1, 2, file);
        uint16_t entry_point_offset = (entry_point_offset_bytes[0] << 8) | entry_point_offset_bytes[1];

        if (data_segment_size == 0)
            data_segment_size = 1024;
        if (extra_segment_size == 0)
            extra_segment_size = 1024;
        if (stack_segment_size == 0)
            stack_segment_size = 1024;

        uint16_t param_segment_size = 0;
        if (params_count > 0)
        {
            uint32_t strings_size = 0;
            for (int i = 0; i < params_count; i++)
            {
                strings_size += strlen(params[i]) + 1;
            }
            uint32_t array_size = (params_count + 1) * 4; // argv[argc] = NULL
            param_segment_size = array_size + strings_size;
        }

        // Calcular bases y construir tabla
        uint32_t current_base = 0;
        int table_index = 0;

        // Param Segment

        if (params_count > 0)
        {
            // Calcular tamaño de strings
            uint32_t strings_size = 0;
            for (int i = 0; i < params_count; i++)
            {
                strings_size += strlen(params[i]) + 1;
            }
            uint32_t argv_size = params_count * 4;
            param_segment_size = strings_size + argv_size;

            // Configurar segmento
            vm->segment_table[table_index] = (param_segment_size << 16) | current_base;
            current_base += param_segment_size;
            vm->registers[REG_PS] = table_index << 16;
            uint32_t segment_index = table_index;
            table_index++;

            uint32_t current_string_offset = 0;

            // PRIMERA PASADA: Solo escribir strings
            for (int i = 0; i < params_count; i++)
            {
                char *param = params[i];
                int len = strlen(param) + 1;
                for (int j = 0; j < len; j++)
                {
                    uint32_t logical_addr = (segment_index << 16) | current_string_offset;
                    vm_memory_write(vm, logical_addr, 1, (uint8_t)param[j]);
                    current_string_offset++;
                }
            }

            // SEGUNDA PASADA: Escribir argv calculando offsets sobre la marcha
            uint32_t argv_start_offset = strings_size;

            uint32_t string_offset = 0;

            for (int i = 0; i < params_count; i++)
            {
                uint32_t logical_addr = (segment_index << 16) | (argv_start_offset + i * 4);

                vm_memory_write(vm, logical_addr, 4, string_offset);
                string_offset += strlen(params[i]) + 1;
            }

            // Mostrar contenido en hexadecimal
            uint32_t seg_index = vm->registers[REG_PS] >> 16;
            uint32_t base_fisica = vm->segment_table[seg_index] & 0xFFFF;
        }
        else
            vm->registers[REG_PS] = 0xFFFFFFFF; // -1 si no hay parámetros

        // Const Segment
        if (const_segment_size > 0)
        {
            vm->segment_table[table_index] = (const_segment_size << 16) | current_base;
            current_base += const_segment_size;
            vm->registers[REG_KS] = table_index << 16;
            table_index++;
        }
        else
            vm->registers[REG_KS] = 0xFFFFFFFF;

        // Code Segment
        if (code_segment_size > 0)
        {
            vm->segment_table[table_index] = (code_segment_size << 16) | current_base;
            fread(vm->memory + current_base, 1, code_segment_size, file);
            vm->registers[REG_CS] = table_index << 16;
            vm->registers[REG_IP] = (table_index << 16) | entry_point_offset;
            current_base += code_segment_size;
            table_index++;
        }

        // Data Segment
        if (data_segment_size > 0)
        {
            vm->segment_table[table_index] = (data_segment_size << 16) | current_base;
            current_base += data_segment_size;
            vm->registers[REG_DS] = table_index << 16;
            table_index++;
        }
        else
            vm->registers[REG_DS] = 0xFFFFFFFF;

        // Extra Segment
        if (extra_segment_size > 0)
        {
            vm->segment_table[table_index] = (extra_segment_size << 16) | current_base;
            current_base += extra_segment_size;
            vm->registers[REG_ES] = table_index << 16;
            table_index++;
        }
        else
            vm->registers[REG_ES] = 0xFFFFFFFF;

        // Stack Segment
        if (stack_segment_size > 0)
        {
            vm->segment_table[table_index] = (stack_segment_size << 16) | current_base;
            vm->registers[REG_SS] = table_index << 16;
            vm->registers[REG_SP] = table_index << 16 | stack_segment_size; // SP inicial al final del stack
            current_base += stack_segment_size;
            table_index++;
        }

        uint32_t total_size = current_base;
        if (total_size > memory_size)
        {
            vm->running = 0;
            return -1;
        }

        // Carga del Const segment si existe
        if (const_segment_size > 0)
        {
            int const_segment_index = vm->registers[REG_KS] >> 16;
            uint32_t const_base = vm->segment_table[const_segment_index] & 0xFFFF; // Base fisica del Const
            fread(vm->memory + const_base, 1, const_segment_size, file);
        }
        if (params_count > 0)
        {
            // Calcular el offset donde empieza el arreglo argv
            uint32_t strings_size = 0;
            for (int i = 0; i < params_count; i++)
            {
                strings_size += strlen(params[i]) + 1;
            }
            uint32_t argv_offset = strings_size; // argv empieza después de los strings
            push_to_stack(vm, argv_offset);      // *argv = offset en Param Segment (SP+8)
        }
        else
            push_to_stack(vm, 0xFFFFFFFF); // *argv = -1 si no hay parámetros (SP+8)

        push_to_stack(vm, params_count); // argc (SP+4)
        push_to_stack(vm, 0xFFFFFFFF);   // RET (-1) (SP)

        uint32_t sp_val = vm->registers[REG_SP];
        for (int i = 0; i < 3; i++)
        {
            uint32_t addr = sp_val + (i * 4);
            uint32_t value = vm_memory_read(vm, addr, 4);
        }

        // Guardan datos iniciales que no son necesarios
        vm->registers[REG_LAR] = 0x0;
        vm->registers[REG_MAR] = 0x0;
        vm->registers[REG_MBR] = 0x0;
    }
    else
    {
        fclose(file);
        vm->running = false;
        return 0;
    }
    fclose(file);
    vm->running = true;
    return 1;
}

void vm_execute(VM *vm)
{
    while (vm->running)
    {
        // FETCH: Lee la instruccion desde el IP
        uint32_t ip = vm->registers[REG_IP];
        uint32_t phys = translate_logical(vm, ip, 1);
        // Leo el primer byte
        uint8_t first_byte = vm->memory[phys++];
        uint8_t type_b = first_byte >> 6;
        uint8_t type_a = (first_byte >> 4) & 0b0011;
        uint8_t op_code = first_byte & 0x1F;

        // if (vm->vmi_enabled && vm->debug_step_by_step)
        // {
        //     printf("[%04X] ", ip & 0xFFFF);
        //     vm_disassemble(vm);
        //     vm_debug_pause(vm);
        // }

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
        if (type_a > 1)
            opa_bytes = (opa_bytes << 8) | vm->memory[p++];
        if (type_a > 2)
            opa_bytes = (opa_bytes << 8) | vm->memory[p++];

        // Seteo OP1 y OP2
        if (op_code != 0x8 && op_code != 0X0 && op_code != OPC_JMP && op_code != OPC_JZ && op_code != OPC_JP && op_code != OPC_JN && op_code != OPC_JNZ && op_code != OPC_JNP && op_code != OPC_JNN && op_code != OPC_RET && op_code != OPC_PUSH && op_code != OPC_POP && op_code != OPC_CALL) // Si no es NOT o SYS
        {
            vm->registers[REG_OP1] = (type_a << 24) | opa_bytes;
            vm->registers[REG_OP2] = (type_b << 24) | opb_bytes;
            vm->registers[REG_OPC] = op_code;
        }
        else // Si tiene un solo operando ponemos en el registro OP1 opb_bytes y tipo
        {
            vm->registers[REG_OP1] = (type_b << 24) | opb_bytes;
            vm->registers[REG_OPC] = op_code;
        }

        uint16_t current_offset = ip & 0xFFFF;
        uint16_t new_off = current_offset + instr_len;
        uint16_t code_size = vm->segment_table[ip >> 16] >> 16;

        if (new_off > code_size)
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

        if (new_off >= code_size)
        {
            printf("IP fuera de limites del segmento de codigo\n");
            vm->running = false;
        }
    }
}

const char *get_mnemonic(uint8_t op_code)
{
    switch (op_code)
    {
    case OPC_MOV:
        return "MOV";
    case OPC_ADD:
        return "ADD";
    case OPC_SUB:
        return "SUB";
    case OPC_MUL:
        return "MUL";
    case OPC_DIV:
        return "DIV";
    case OPC_CMP:
        return "CMP";
    case OPC_SHL:
        return "SHL";
    case OPC_SHR:
        return "SHR";
    case OPC_SAR:
        return "SAR";
    case OPC_AND:
        return "AND";
    case OPC_OR:
        return "OR";
    case OPC_XOR:
        return "XOR";
    case OPC_SWAP:
        return "SWAP";
    case OPC_LDL:
        return "LDL";
    case OPC_LDH:
        return "LDH";
    case OPC_RND:
        return "RND";
    case OPC_PUSH:
        return "PUSH";
    case OPC_POP:
        return "POP";
    case OPC_CALL:
        return "CALL";
    case OPC_RET:
        return "RET";
    case OPC_SYS:
        return "SYS";
    case OPC_JMP:
        return "JMP";
    case OPC_JZ:
        return "JZ";
    case OPC_JP:
        return "JP";
    case OPC_JN:
        return "JN";
    case OPC_JNZ:
        return "JNZ";
    case OPC_JNP:
        return "JNP";
    case OPC_JNN:
        return "JNN";
    case OPC_NOT:
        return "NOT";
    case OPC_STOP:
        return "STOP";
    default:
        return "???";
    }
}

const char *get_register_name(uint8_t reg_code, uint8_t reg_sec)
{
    switch (reg_code)
    {
    case REG_LAR:
        return "LAR";
    case REG_MAR:
        return "MAR";
    case REG_MBR:
        return "MBR";
    case REG_OPC:
        return "OPC";
    case REG_OP1:
        return "OP1";
    case REG_OP2:
        return "OP2";
    case REG_IP:
        return "IP";
    case REG_SP:
        return "SP";
    case REG_BP:
        return "BP";
    case REG_EAX:
        if (reg_sec == 0)
            return "EAX";
        else if (reg_sec == 1)
            return "AL";
        else if (reg_sec == 2)
            return "AH";
        else
            return "AX";
    case REG_EBX:
        if (reg_sec == 0)
            return "EBX";
        else if (reg_sec == 1)
            return "BL";
        else if (reg_sec == 2)
            return "BH";
        else
            return "BX";
    case REG_ECX:
        if (reg_sec == 0)
            return "ECX";
        else if (reg_sec == 1)
            return "CL";
        else if (reg_sec == 2)
            return "CH";
        else
            return "CX";
    case REG_EDX:
        if (reg_sec == 0)
            return "EDX";
        else if (reg_sec == 1)
            return "DL";
        else if (reg_sec == 2)
            return "DH";
        else
            return "DX";
    case REG_EEX:
        if (reg_sec == 0)
            return "EEX";
        else if (reg_sec == 1)
            return "EL";
        else if (reg_sec == 2)
            return "EH";
        else
            return "EX";
    case REG_EFX:
        if (reg_sec == 0)
            return "EFX";
        else if (reg_sec == 1)
            return "FL";
        else if (reg_sec == 2)
            return "FH";
        else
            return "FX";
    case REG_AC:
        return "AC";
    case REG_CC:
        return "CC";
    case REG_CS:
        return "CS";
    case REG_DS:
        return "DS";
    case REG_ES:
        return "ES";
    case REG_SS:
        return "SS";
    case REG_KS:
        return "KS";
    case REG_PS:
        return "PS";
    default:
        return "R?";
    }
}

void disassemble_operand(VM *vm, uint8_t type, uint32_t value)
{
    switch (type)
    {
    case OP_TYPE_NONE:
        break;

    case OP_TYPE_REGISTER:
        uint8_t reg_sec = (value >> 6) & 0x03;
        uint8_t reg_code = value & 0x3F;
        printf("%s", get_register_name(reg_code, reg_sec));
        break;

    case OP_TYPE_IMMEDIATE:
        printf("%d", (int16_t)(value & 0xFFFF));
        break;

    case OP_TYPE_MEMORY:
    {
        uint8_t reg = (value >> 16) & 0xFF;
        int16_t displacement = (int16_t)(value & 0xFFFF);

        uint8_t reg_code = reg & 0x3F;
        uint8_t cell_size = (reg >> 6) & 0x03;

        if (cell_size == 2)
            printf("w[");
        else if (cell_size == 3)
            printf("b[");
        else
            printf("[");
        if (reg_code != 0)
        {
            printf("%s", get_register_name(reg_code, 0));
            if (displacement != 0)
            {
                printf("%+d", displacement);
            }
        }
        else
        {
            printf("%d", displacement);
        }
        printf("]");
        break;
    }
    }
}

void disassemble_instruction(VM *vm, uint32_t phys_addr, uint8_t op_code, uint8_t type_a, uint8_t type_b)
{
    const char *mnemonic = get_mnemonic(op_code);
    printf("%-4s    ", mnemonic);

    // Leer operandos de la memoria
    uint32_t opa_value = 0, opb_value = 0;
    int offset = 0;

    // Leer operando B (si existe)
    if (type_b > 0)
    {
        for (int i = 0; i < type_b; i++)
        {
            opb_value = (opb_value << 8) | vm->memory[phys_addr + offset + i];
        }
        offset += type_b;
    }

    // Leer operando A (si existe)
    if (type_a > 0)
    {
        for (int i = 0; i < type_a; i++)
        {
            opa_value = (opa_value << 8) | vm->memory[phys_addr + offset + i];
        }
    }

    // Mostrar operandos según el tipo de instrucción
    if (op_code == OPC_SYS || op_code == OPC_NOT || op_code == OPC_CALL || op_code == OPC_RET || op_code == OPC_PUSH || op_code == OPC_POP)
    {
        // Instrucciones de un operando (usan OPB)
        disassemble_operand(vm, type_b, opb_value);
    }
    else
    {
        // Instrucciones de dos operandos
        disassemble_operand(vm, type_a, opa_value);
        if (type_b > 0)
        {
            printf(", ");
            disassemble_operand(vm, type_b, opb_value);
        }
    }
    printf("\n");
}

void vm_disassemble(VM *vm)
{
    // system("cls");
    printf("====================================\n\n");

    uint32_t cs_value = vm->registers[REG_CS];
    uint16_t cs_segment_index = (cs_value >> 16) & 0xFFFF;

    if (cs_segment_index >= SEGMENT_TABLE_SIZE || vm->segment_table[cs_segment_index] == 0)
    {
        printf("Error: Code Segment no válido\n");
        return;
    }

    uint32_t code_entry = vm->segment_table[cs_segment_index];
    uint16_t base_phys = code_entry & 0xFFFF; // Base física del Code Segment
    uint16_t code_size = code_entry >> 16;    // Tamaño del Code Segment

    uint32_t ip = 0;

    while (ip < code_size)
    {

        uint32_t phys_addr = base_phys + ip;
        uint8_t first_byte = vm->memory[phys_addr];

        // Decodificar instrucción
        uint8_t type_b = first_byte >> 6;
        uint8_t type_a = (first_byte >> 4) & 0b0011;
        uint8_t op_code = first_byte & 0x1F;

        int instr_len = 1 + type_a + type_b;

        // Leer bytes completos de la instrucción
        uint8_t instr_bytes[6] = {0};
        for (int i = 0; i < instr_len && i < 6; i++)
        {
            instr_bytes[i] = vm->memory[phys_addr + i];
        }

        // Desensamblar
        if (vm->registers[REG_IP] == (ip | (cs_segment_index << 16)))
            printf(">");
        else
            printf(" ");
        printf(" [%04X] ", phys_addr);
        for (int i = 0; i < instr_len; i++)
        {
            printf("%02X ", instr_bytes[i]);
        }
        for (int i = instr_len; i < 6; i++)
        {
            printf("   ");
        }
        printf("| ");

        // Mostrar mnemónico y operandos
        disassemble_instruction(vm, phys_addr + 1, op_code, type_a, type_b);

        ip += instr_len;
    }
}

int main(int argc, char **argv)
{
    VM vm;
    init_instruction_table();

    bool disassemble = false;
    const char *vmx_filename = NULL;
    const char *vmi_filename = NULL;

    // 1. PRIMERO parsear argumentos
    bool vmi = false;
    int memory_size = 0;
    int param_segment_size = 0;
    char **params = NULL;
    int params_count = 0;
    for (int i = 1; i < argc; i++)
    {
        // -d
        if (strstr(argv[i], "-d") != NULL)
        {
            disassemble = true;
            continue;
        }
        // filename
        if ((strstr(argv[i], ".vmx") != NULL) || (strstr(argv[i], ".VMX") != NULL))
        {
            vmx_filename = argv[i];
            continue;
        }
        if (strstr(argv[i], ".vmi") != NULL || strstr(argv[i], ".VMI") != NULL)
        {
            vmi_filename = argv[i];
            vmi = true;
            continue;
        }
        if (strstr(argv[i], "m=") != NULL)
        {
            char *memory_size_str = argv[i] + 2;
            memory_size = atoi(memory_size_str) * 1024;
            continue;
        }
        if (strstr(argv[i], "-p") != NULL)
        {
            params_count = argc - (i + 1);
            if (params_count > 0)
                params = &argv[i + 1];
            break; // Los argumentos es lo ultimo que se carga
        }
    }

    if (memory_size == 0)
        memory_size = DEFAULT_MEMORY_SIZE;

    vm_init(&vm, memory_size);

    if (vmi && !vmx_filename)
    {
        vm.vmi_enabled = true;
        strncpy(vm.vmi_path, vmi_filename, sizeof(vm.vmi_path) - 1);
        vm.vmi_path[sizeof(vm.vmi_path) - 1] = '\0';
        vm_load_vmi(&vm, vmi_filename);
    }
    else if (vmi && vmx_filename)
    {
        vm.vmi_enabled = true;
        strncpy(vm.vmi_path, vmi_filename, sizeof(vm.vmi_path) - 1);
        vm.vmi_path[sizeof(vm.vmi_path) - 1] = '\0';
    }

    if (vmx_filename && vm_load_program(&vm, vmx_filename, memory_size, params, params_count) <= 0)
    {
        printf("Error: no se pudo cargar el archivo '%s'\n", vmx_filename);
        return 1;
    }

    if (disassemble)
        vm_disassemble(&vm);

    vm_execute(&vm);

    return 0;
}

int vm_load_vmi(VM *vm, const char *path)
{
    FILE *file = fopen(path, "rb");
    if (!file)
    {
        printf("VMI: no se pudo abrir '%s'\n", path);
        return 0;
    }

    char header[6] = {0};
    if (fread(header, 1, 5, file) != 5 || strcmp(header, "VMI25") != 0)
    {
        fclose(file);
        return 0;
    }
    uint8_t version = 0;
    fread(&version, 1, 1, file);
    uint8_t size[2];
    fread(size, 1, 2, file);
    uint32_t mem_bytes = ((uint16_t)size[0] << 8 | (uint16_t)size[1]) * 1024u;

    // Reserva memoria
    if (vm->memory)
    {
        free(vm->memory);
        vm->memory = NULL;
    }
    vm->memory = (uint8_t *)malloc(mem_bytes);

    vm->memory_size = (int)mem_bytes;

    fread(vm->registers, sizeof(uint32_t), NUM_REGISTERS, file);
    fread(vm->segment_table, sizeof(uint32_t), SEGMENT_TABLE_SIZE, file);
    size_t n = fread(vm->memory, 1, mem_bytes, file);
    fclose(file);

    vm->running = true;
    return 1;
}

void create_vmi(VM *vm, char *path)
{
    FILE *file = fopen(path, "wb");
    if (!file)
    {
        printf("Error al abrir el archivo VMI para escritura: %s\n", path);
        return;
    }
    char header[] = "VMI25";
    fwrite(header, 1, strlen(header), file); // En este caso son 5 bytes
    uint8_t version = 1;
    fwrite(&version, 1, 1, file);
    uint8_t seg = vm->registers[REG_SS] >> 16;
    uint16_t memory_size = ((vm->segment_table[seg] >> 16) + (vm->segment_table[seg] & 0xFFFF)); // en KB
    uint16_t memory_size_kb = memory_size / 1024;
    fwrite(&memory_size_kb, 2, 1, file);

    for (int i = 0; i < 32; i++)
        fwrite(&vm->registers[i], sizeof(uint32_t), 1, file);
    for (int i = 0; i < SEGMENT_TABLE_SIZE; i++)
        fwrite(&vm->segment_table[i], sizeof(uint32_t), 1, file);

    fwrite(vm->memory, 1, memory_size, file);

    fclose(file);
}

void vm_debug_pause(VM *vm)
{
    if (!vm->vmi_enabled && vm->vmi_path[0] == '\0')
    {
        return;
    }
    create_vmi(vm, vm->vmi_path);

    fflush(stdout);

    int ch = _getch();
    if (ch == 'g' || ch == 'G')
        vm->debug_step_by_step = false;
    else if (ch == 'q' || ch == 'Q')
        vm->running = false;
    else
        vm->debug_step_by_step = true;
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
    instruction_table[OPC_PUSH] = instr_PUSH;
    instruction_table[OPC_POP] = instr_POP;
    instruction_table[OPC_CALL] = instr_CALL;
    instruction_table[OPC_RET] = instr_RET;
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
        value = (value << 8) | byte;
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
    {
        uint8_t shift = (num_bytes - 1 - i) * 8;
        vm->memory[phys + i] = (uint8_t)((value >> shift) & 0xFF);
    }
    return true;
}

uint32_t get_operand_value(VM *vm, uint32_t op_reg)
{
    uint8_t type = (op_reg >> 24) & 0xFF;
    uint32_t value = op_reg & 0x00FFFFFF;
    if (type == OP_TYPE_REGISTER)
    {
        uint32_t reg_value;
        uint8_t reg_sec = value >> 6 & 0x03;
        reg_value = vm->registers[value & 0x1F];
        if (reg_sec == 0b00) // registro de 4 bytes (EAX)
            return reg_value;
        else if (reg_sec == 0b01) // registro de 1 byte (4to byte del registro) (AL)
            return reg_value & 0xFF;
        else if (reg_sec == 0b10) // registro de 2 bytes (AH)
            return (reg_value >> 8) & 0xFF;
        else if (reg_sec == 0b11) // registro de 2 bytes (AX) segundo byte menos significativo de EAX
            return reg_value & 0xFFFF;
        return reg_value;
    }
    else if (type == OP_TYPE_IMMEDIATE)
    {
        int32_t value2 = op_reg << 16; // Arrastro el signo
        return value2 >> 16;
    }
    else if (type == OP_TYPE_MEMORY)
    {
        uint8_t cell_size = (value >> 22) & 0x03;
        int bytes;
        if (cell_size == 0b00) // 4 bytes
            bytes = 4;
        else if (cell_size == 0b10) // 2 bytes
            bytes = 2;
        else if (cell_size == 0b11) // 1 bytes
            bytes = 1;

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
        return vm_memory_read(vm, logical_addr, bytes); // Por defecto 4 bytes
    }
    return 0; // Error
}

void set_operand_value(VM *vm, uint32_t op_reg, uint32_t value)
{
    uint8_t type = (op_reg >> 24) & 0xFF;
    uint32_t value_field = op_reg & 0x00FFFFFF;
    if (type == OP_TYPE_REGISTER)
    {
        uint8_t reg_sec = value_field >> 6 & 0x03;
        uint32_t reg_value = vm->registers[value_field & 0x1F];
        if (reg_sec == 0b00)
            reg_value = value;
        else if (reg_sec == 0b01)
        {                            // registro de 1 byte (4to byte del registro) (AL)
            reg_value &= 0xFFFFFF00; // Limpio el byte menos significativo
            reg_value |= (value & 0xFF);
        }
        else if (reg_sec == 0b10)
        {                            // registro de 2 bytes (AH)
            reg_value &= 0xFFFF00FF; // Limpio el segundo byte menos significativo
            reg_value |= ((value & 0xFF) << 8);
        }
        else if (reg_sec == 0b11)
        {                            // registro de 2 bytes (AX) segundo byte menos significativo de EAX
            reg_value &= 0xFFFF0000; // Limpio los dos bytes menos significativos
            reg_value |= (value & 0xFFFF);
        }
        vm->registers[value_field & 0x1F] = reg_value;
    }
    else if (type == OP_TYPE_MEMORY)
    {
        uint8_t cell_size = (value_field >> 22) & 0x03;
        int bytes;
        if (cell_size == 0b00) // 4 bytes
            bytes = 4;
        else if (cell_size == 0b10) // 2 bytes
            bytes = 2;
        else if (cell_size == 0b11) // 1 bytes
            bytes = 1;
        uint8_t base_reg_code = (value_field >> 16) & 0xFF;
        int16_t disp = (int16_t)(value_field & 0xFFFF);
        uint32_t base_ptr = vm->registers[base_reg_code];
        uint16_t base_seg = base_ptr >> 16;
        uint16_t base_off = base_ptr & 0xFFFF;
        int32_t logical_off = (int32_t)base_off + disp;
        if (logical_off < 0)
        {
            vm->running = false;
            return;
        }
        uint32_t logical_addr = (base_seg << 16) | (logical_off & 0xFFFF);
        vm_memory_write(vm, logical_addr, bytes, value); // Por defecto 4 bytes
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

// PUSH: Decrementa SP y almacena valor (big-endian)
void push_to_stack(VM *vm, uint32_t value)
{
    vm->registers[REG_SP] -= 4;

    if (vm->registers[REG_SS] > vm->registers[REG_SP]) // 00040000 [ss] < 00040004 [sp]
    {
        printf("STACK OVERFLOW\n");
        vm->running = 0;
        return;
    }

    // Calcular dirección lógica: (REG_SS << 16) | REG_SP
    uint32_t logical_addr = (vm->registers[REG_SS] & 0xFFFF0000) | (vm->registers[REG_SP] & 0xFFFF);

    // Verificar y obtener dirección física
    uint32_t phys_addr = translate_logical(vm, logical_addr, 4);
    if (phys_addr == (uint32_t)-1)
        return;

    vm_memory_write(vm, logical_addr, 4, value);
}

uint32_t pop_from_stack(VM *vm)
{
    uint32_t logical_addr = (vm->registers[REG_SS] & 0xFFFF0000) | (vm->registers[REG_SP] & 0xFFFF);

    uint32_t phys_addr = translate_logical(vm, logical_addr, 4);
    if (phys_addr == (uint32_t)-1)
        return -1;

    uint32_t value = vm_memory_read(vm, logical_addr, 4);

    vm->registers[REG_SP] += 4;

    uint16_t seg = (vm->registers[REG_SS] >> 16) & 0xFFFF;
    if (vm->registers[REG_SP] & 0xFFFF > (vm->segment_table[seg] >> 16))
    {
        printf("STACK UNDERFLOW\n");
        vm->running = 0;
        return -1;
    }

    return value;
}

// Se debe modularizar más ¿?

void instr_MOV(VM *vm)
{
    uint32_t op1 = vm->registers[REG_OP1];
    uint32_t op2 = vm->registers[REG_OP2];

    uint8_t op_code = vm->registers[REG_OPC];

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
    int32_t truncated = (int32_t)result;
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

void instr_PUSH(VM *vm)
{
    uint32_t value = get_operand_value(vm, vm->registers[REG_OP1]); // OP1 contiene dirección lógica del operando
    push_to_stack(vm, value);
}

void instr_POP(VM *vm)
{
    uint32_t value = pop_from_stack(vm);
    set_operand_value(vm, vm->registers[REG_OP1], value);
}

void instr_CALL(VM *vm) // Revisar
{
    push_to_stack(vm, vm->registers[REG_IP]);

    // Saltar a la dirección del OP1
    uint32_t target_address = get_operand_value(vm, vm->registers[REG_OP1]);
    vm->registers[REG_IP] = target_address;
}

void instr_RET(VM *vm)
{
    // POP del IP de retorno
    uint32_t return_ip = pop_from_stack(vm);

    // Saltar a esa dirección
    vm->registers[REG_IP] = return_ip;
}

// Revisar
void instr_SYS(VM *vm)
{
    // SYS es instrucción de un operando - usamos OP1
    uint32_t sys_call = get_operand_value(vm, vm->registers[REG_OP1]);
    uint32_t eax = vm->registers[REG_EAX];
    uint32_t edx = vm->registers[REG_EDX];
    uint32_t ecx = vm->registers[REG_ECX];

    // ECX: high 16 bits = tamaño de celda, low 16 bits = cantidad de celdas
    uint16_t cell_size = (ecx >> 16) & 0xFFFF;
    uint16_t cell_count = ecx & 0xFFFF;

    if (sys_call == 1)
    { // READ
        for (int i = 0; i < cell_count; i++)
        {
            uint32_t current_addr = edx + (i * cell_size);
            uint16_t phys = translate_logical(vm, current_addr, cell_size);
            printf("  [%04X]: ", phys);

            int32_t value = 0;
            int scan_result = 0;

            // Leer según el formato especificado en EAX
            if (eax & 0x01)
            { // Decimal
                scan_result = scanf("%d", &value);
            }
            else if (eax & 0x02)
            { // Caracter
                char c;
                scan_result = scanf(" %c", &c);
                value = (int32_t)c;
            }
            else if (eax & 0x04)
            { // Octal
                scan_result = scanf("%o", &value);
            }
            else if (eax & 0x08)
            { // Hexadecimal
                scan_result = scanf("%x", &value);
            }
            else if (eax & 0x10)
            { // Binario
                char bin_str[33];
                scan_result = scanf("%32s", bin_str);
                if (scan_result == 1)
                {
                    value = (int32_t)strtol(bin_str, NULL, 2);
                }
            }
            else
            {
                printf("ERROR: Formato no soportado 0x%02X\n", eax);
                vm->running = false;
                return;
            }

            if (scan_result != 1)
            {
                printf("ERROR: Entrada inválida\n");
                vm->running = false;
                return;
            }

            // Escribir en memoria
            if (!vm_memory_write(vm, current_addr, cell_size, value))
            {
                printf("ERROR: Escritura en memoria falló\n");
                vm->running = false;
                return;
            }
        }
    }
    else if (sys_call == 2)
    { // WRITE
        for (int i = 0; i < cell_count; i++)
        {
            uint32_t addr = edx + (i * cell_size);
            uint32_t value = vm_memory_read(vm, addr, cell_size);

            uint16_t phys = translate_logical(vm, addr, cell_size);

            printf("  [%04X]: ", phys);

            // Mostrar según el formato especificado en EAX
            if (eax & 0x10)
            { // Binario
                for (int bit = (cell_size * 8) - 1; bit >= 0; bit--)
                    printf("%d ", (value >> bit) & 1);
                printf(" ");
            }
            if (eax & 0x08)
            { // Hexadecimal
                printf("0x%X ", value);
            }
            if (eax & 0x04)
            { // Octal
                printf("0o%o ", value);
            }
            if (eax & 0x02)
            { // Caracter
                if (value >= 32 && value <= 126)
                    printf("%c ", (char)value);
                else
                    printf(". ");
            }
            if (eax & 0x01)
            { // Decimal
                printf("%d ", value);
            }
            printf("\n");
        }
    }
    else if (sys_call == 3)
    {
        uint16_t seg = (edx >> 16) & 0xFFFF;
        uint16_t off = edx & 0xFFFF;

        uint32_t entry = vm->segment_table[seg];
        uint32_t seg_size = (entry >> 16) & 0xFFFF;

        int16_t max_limit = (int16_t)(ecx & 0xFFFF);

        if (max_limit == -1)                // Se supone que si es -1 no hay limite de lectura, pero por las dudas lo limitamos al tamaño del segmento
            max_limit = seg_size - off - 1; // dejar espacio para '\0'

        char *temp_buffer = (char *)malloc(max_limit + 1);
        if (!temp_buffer)
            printf("ERROR: No se pudo asignar memoria para STRING READ\n");

        printf("Ingrese cadena (max %u caracteres): ", max_limit);
        fflush(stdout);
        if (!fgets(temp_buffer, max_limit + 1, stdin))
        {
            printf("ERROR: Fallo al leer cadena\n");
            free(temp_buffer);
            return;
        }

        // Remover salto de línea si está presente
        int len = strlen(temp_buffer);
        if (len > 0 && temp_buffer[len - 1] == '\n')
        {
            temp_buffer[len - 1] = '\0';
            len--;
        }
        else
            temp_buffer[len] = '\0';
        // Escribir en memoria del VM
        for (int i = 0; i <= len; i++)
        {
            uint32_t addr = edx + i;
            vm_memory_write(vm, addr, 1, (uint32_t)temp_buffer[i]);
        }
        free(temp_buffer);
    }
    else if (sys_call == 4)
    { // STRING WRITE
        uint32_t addr = edx;
        // leer char a char hasta '\0' o fin de segmento
        while (true)
        {
            uint32_t ch = vm_memory_read(vm, addr, 1);
            if (!vm->running)
                return; // por si falla translate
            if (ch == 0)
                break;
            putchar((int)ch);
            addr += 1;
        }
        printf("\n");

        fflush(stdout);
    }
    else if (sys_call == 7)
        system("cls");
    else if (sys_call == 0xF)
    {
        vm->debug_step_by_step = true;
        vm_debug_pause(vm);
    }
    else
    {
        printf("ERROR: Llamada al sistema inválida %u\n", sys_call);
        vm->running = false;
    }
}

void instr_JMP(VM *vm)
{
    int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]); // Direccion del salto

    vm->registers[REG_IP] = (vm->registers[REG_IP] & 0xFFFF0000) | direc;
}

// Revisar las condiciones de salto, me maree un poco
void instr_JZ(VM *vm)
{
    if (vm->registers[REG_CC] & 0x40000000) // Z=1
    {                                       // IF Z==1
        int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]);
        vm->registers[REG_IP] = (vm->registers[REG_IP] & 0xFFFF0000) | direc;
    }
}

void instr_JP(VM *vm)
{

    if (!(vm->registers[REG_CC] & 0x40000000) && !(vm->registers[REG_CC] & 0x80000000))
    {
        int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]);
        vm->registers[REG_IP] = (vm->registers[REG_IP] & 0xFFFF0000) | direc;
    }
}

void instr_JN(VM *vm)
{

    if (vm->registers[REG_CC] & 0x80000000) // N =1
    {
        int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]);
        vm->registers[REG_IP] = (vm->registers[REG_IP] & 0xFFFF0000) | direc;
    }
}

void instr_JNZ(VM *vm)
{

    if ((vm->registers[REG_CC] & 0x80000000) || (!(vm->registers[REG_CC] & 0x40000000) && !(vm->registers[REG_CC] & 0x80000000)))
    {
        int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]);
        vm->registers[REG_IP] = (vm->registers[REG_IP] & 0xFFFF0000) | direc;
    }
}

void instr_JNP(VM *vm)
{
    if ((vm->registers[REG_CC] & 0x80000000) || (vm->registers[REG_CC] & 0x40000000))
    { // IF  Z o N activas
        int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]);
        vm->registers[REG_IP] = (vm->registers[REG_IP] & 0xFFFF0000) | direc;
    }
}

void instr_JNN(VM *vm)
{

    if ((vm->registers[REG_CC] & 0x40000000) || (!(vm->registers[REG_CC] & 0x40000000) && !(vm->registers[REG_CC] & 0x80000000)))
    { // IF
        int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]);
        vm->registers[REG_IP] = (vm->registers[REG_IP] & 0xFFFF0000) | direc;
    }
}

// Seria con el operando 2?
void instr_NOT(VM *vm)
{
    uint32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]);

    uint32_t result = ~val1;                               // Negación bit a bit
    set_operand_value(vm, vm->registers[REG_OP1], result); // Guardar el resultado

    update_flags(vm, result); // Actualiza el registro CC.
}

// LO DE LA IP ESTÁ BIEN ¿? Si
void instr_STOP(VM *vm)
{
    vm->registers[REG_IP] = 0xFFFFFFFF; // IP inválida para indicar fin de ejecución
    vm->running = false;
}
