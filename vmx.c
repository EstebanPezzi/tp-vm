#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Memoria principal: 16 KiB
#define MEMORY_SIZE 16384


// Tabla de descriptores de segmentos: 8 entradas de 4 bytes cada una
#define SEGMENT_TABLE_SIZE 8
#define SEG_PS 0  // Param Segment
#define SEG_KS 1  // Const Segment  
#define SEG_CS 2  // Code Segment
#define SEG_DS 3  // Data Segment
#define SEG_ES 4  // Extra Segment
#define SEG_SS 5  // Stack Segment

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
// Códigos de registros PARTE 2
#define REG_SP 7
#define REG_BP 8

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
//Nuevas instrucciones
#define OPC_PUSH 0x0B
#define OPC_POP  0x0C
#define OPC_CALL 0x0D
#define OPC_RET  0x0E

// Tipos de operandos
#define OP_TYPE_NONE 0b00
#define OP_TYPE_REGISTER 0b01
#define OP_TYPE_IMMEDIATE 0b10
#define OP_TYPE_MEMORY 0b11
#define OP_TYPE_NONE 0b00
#define OP_TYPE_REGISTER 0b01
#define OP_TYPE_IMMEDIATE 0b10
#define OP_TYPE_MEMORY 0b11

// Estructura para la VM
typedef struct
{
    uint8_t *memory; // Memoria principal (dinamica)
    size_t memory_size;
   
    // Información de segmentos
    uint32_t segment_table[SEGMENT_TABLE_SIZE]; //tabla de descripctores de segmentos
    uint16_t segment_sizes[6]; // Tamaños: [PS, KS, CS, DS, ES, SS]
    uint16_t segment_bases[6]; // Bases físicas: [PS, KS, CS, DS, ES, SS]
    
    int32_t registers[NUM_REGISTERS];
    bool running;
    bool debug_mode;
    uint32_t entry_point;// Offset del entry point en CS
    int argc; //Cantidad de parámetros
    char **argv;// Parámetros del programa
    const char *vmi_filename; // Para breakpoints
} VM;

// Funciones principales
bool vm_init(VM *vm, size_t memory_size);
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


// AGREGAR ESTAS FUNCIONES QUE FALTAN:

uint16_t read_uint16(FILE *file) {
    uint8_t bytes[2];
    fread(bytes, 1, 2, file);
    return (bytes[0] << 8) | bytes[1];  // Big-endian
}

uint16_t calculate_param_segment_size(char **params, int param_count) {
    if (param_count == 0) return 0;
    
    uint16_t total_size = 0;
    for (int i = 0; i < param_count; i++) {
        total_size += strlen(params[i]) + 1;  // string + \0
    }
    total_size += param_count * 4;  // array de punteros
    return total_size;
}

int vm_load_image(VM *vm, const char *filename) {
    // Implementación básica por ahora
    printf("Cargar imagen .vmi - NO IMPLEMENTADO AÚN\n");
    return 0;
}

bool vm_init(VM *vm, size_t memory_size)
{
    // Reservar memoria principal
    vm->memory = (uint8_t *)malloc(memory_size);
    if (!vm->memory)
    {
        return false;
    }
    
    vm->memory_size = memory_size;
    memset(vm->memory, 0, memory_size);
    
    // Inicializar estructuras
    memset(vm->segment_table, 0, sizeof(vm->segment_table));
    memset(vm->registers, 0, sizeof(vm->registers));
    memset(vm->segment_sizes, 0, sizeof(vm->segment_sizes));
    memset(vm->segment_bases, 0, sizeof(vm->segment_bases));
    
    // Inicializar estado
    vm->running = true;
    vm->debug_mode = false;
    vm->entry_point = 0;
    vm->argc = 0;
    vm->argv = NULL;
    vm->vmi_filename = NULL;
    
    srand(time(NULL));
    return true;
}

void vm_cleanup(VM *vm)
{
    if (vm->memory)
    {
        free(vm->memory);
        vm->memory = NULL;
    }
}

int vm_load_program(VM *vm, const char *filename, char **params, int param_count)
{
    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        printf("Error: No se pudo abrir el archivo '%s'\n", filename);
        return 0;
    }

    // Leer identificador
    char identifier[6];
    fread(identifier, 1, 5, file);
    identifier[5] = '\0';
    
    uint8_t version;
    fread(&version, 1, 1, file);
    
    // Determinar versión del archivo
    if (strcmp(identifier, "VMX25") == 0 && version == 2)
    {
        printf("Cargando archivo VMX v2...\n");
        fclose(file);
        return vm_load_program_v2(vm, filename, params, param_count);
    }
    else if (strcmp(identifier, "VMX") == 0 && version == 1)
    {
        printf("Cargando archivo VMX v1 (compatibilidad)...\n");
        fclose(file);
        return vm_load_program_v1(vm, filename);
    }
    else
    {
        printf("Error: Formato de archivo no reconocido\n");
        fclose(file);
        return -1;
    }
}

void setup_segment_table_v1(VM *vm)
{
    // Limpiar tabla
    memset(vm->segment_table, 0, sizeof(vm->segment_table));
    
    // Solo 2 segmentos en v1:
    // Segmento 0: Code Segment
    vm->segment_table[0] = (vm->segment_sizes[SEG_CS] << 16) | vm->segment_bases[SEG_CS];
    
    // Segmento 1: Data Segment  
    vm->segment_table[1] = (vm->segment_sizes[SEG_DS] << 16) | vm->segment_bases[SEG_DS];
    
    // Los demás segmentos (2-7) quedan en 0 (no existen)
}

bool calculate_memory_layout(VM *vm)
{
    uint16_t current_base = 0;
    
    // Orden: PS, KS, CS, DS, ES, SS
    for (int i = 0; i < 6; i++)
    {
        if (vm->segment_sizes[i] > 0)
        {
            vm->segment_bases[i] = current_base;
            current_base += vm->segment_sizes[i];
            
            // Verificar overflow de memoria
            if (current_base > vm->memory_size)
            {
                printf("Error: Memoria insuficiente. Requerido: %u, Disponible: %zu\n", 
                       current_base, vm->memory_size);
                return false;
            }
        }
        else
        {
            vm->segment_bases[i] = 0xFFFF;  // Indicador de segmento no existente
        }
    }
    
    printf("Layout de memoria calculado:\n");
    for (int i = 0; i < 6; i++)
    {
        const char *seg_names[] = {"PS", "KS", "CS", "DS", "ES", "SS"};
        if (vm->segment_sizes[i] > 0)
        {
            printf("  %s: base=0x%04X, size=%u\n", 
                   seg_names[i], vm->segment_bases[i], vm->segment_sizes[i]);
        }
    }
    
    return true;
}

int vm_load_program_v1(VM *vm, const char *filename)
{
    FILE *file = fopen(filename, "rb");
    if (!file) return 0;

    // Leer header v1
    char identifier[4];
    fread(identifier, 1, 3, file);
    identifier[3] = '\0';
    
    uint8_t version;
    fread(&version, 1, 1, file);
    
    uint8_t code_size_bytes[2];
    fread(code_size_bytes, 1, 2, file);
    uint16_t code_size = (code_size_bytes[0] << 8) | code_size_bytes[1];

    // Configurar como versión 1 (solo Code y Data segments)
    vm->segment_sizes[SEG_CS] = code_size;
    vm->segment_sizes[SEG_DS] = 1024;  // Por defecto
    vm->segment_sizes[SEG_SS] = 0;     // NO EXISTE en v1
    vm->segment_sizes[SEG_PS] = 0;     // Sin parámetros
    vm->segment_sizes[SEG_KS] = 0;     // Sin constantes
    vm->segment_sizes[SEG_ES] = 0;     // Sin extra

    // Calcular layout de memoria
    if (!calculate_memory_layout(vm))
    {
        fclose(file);
        return 0;
    }

    // Cargar código
    fread(&vm->memory[vm->segment_bases[SEG_CS]], 1, code_size, file);
    fclose(file);

    // Configurar registros - VERSIÓN 1
    vm->registers[REG_CS] = (0 << 16) | vm->segment_bases[SEG_CS];  // Seg 0 = CS
    vm->registers[REG_DS] = (1 << 16) | vm->segment_bases[SEG_DS];  // Seg 1 = DS
    vm->registers[REG_SS] = 0xFFFFFFFF;  // NO EXISTE en v1
    vm->registers[REG_ES] = 0xFFFFFFFF;  // No existe
    vm->registers[REG_KS] = 0xFFFFFFFF;  // No existe
    vm->registers[REG_PS] = 0xFFFFFFFF;  // No existe
    
    // Registros de pila NO EXISTEN en v1
    vm->registers[REG_SP] = 0xFFFFFFFF;  // No existe
    vm->registers[REG_BP] = 0xFFFFFFFF;  // No existe
    
    vm->registers[REG_IP] = vm->registers[REG_CS];  // IP al inicio del CS
    vm->entry_point = 0;

    // Configurar tabla de segmentos - SOLO 2 segmentos en v1
    setup_segment_table_v1(vm);

    vm->running = true;
    return 1;
}

void setup_param_segment(VM *vm, char **params, int param_count)
{
    if (param_count == 0) return;
    
    uint16_t base = vm->segment_bases[SEG_PS];
    uint16_t current_offset = 0;
    
    // 1. Guardar todos los strings seguidos
    for (int i = 0; i < param_count; i++)
    {
        const char *param = params[i];
        size_t len = strlen(param);
        
        // Copiar string + \0
        memcpy(&vm->memory[base + current_offset], param, len);
        vm->memory[base + current_offset + len] = 0;
        current_offset += len + 1;
    }
    
    // 2. Después de los strings, guardar el array de punteros
    uint16_t array_start = current_offset;
    uint16_t string_offset = 0;
    
    for (int i = 0; i < param_count; i++)
    {
        // Cada puntero: 0x0000 (segmento) + offset_del_string
        uint32_t pointer = (0x0000 << 16) | string_offset;
        
        // Guardar en memoria (4 bytes)
        uint32_t addr = base + array_start + (i * 4);
        vm->memory[addr + 0] = (pointer >> 24) & 0xFF;
        vm->memory[addr + 1] = (pointer >> 16) & 0xFF; 
        vm->memory[addr + 2] = (pointer >> 8) & 0xFF;
        vm->memory[addr + 3] = pointer & 0xFF;
        
        // Avanzar al próximo string
        string_offset += strlen(params[i]) + 1;
    }
}

void setup_initial_stack(VM *vm, int param_count) {
    if (vm->segment_sizes[SEG_SS] == 0) return;
    
    uint32_t stack_top = vm->registers[REG_SS] + vm->segment_sizes[SEG_SS];
    uint32_t new_sp = stack_top - 12; // 3 valores de 4 bytes
    
    // CALCULAR argv 
    uint32_t argv_value = 0xFFFFFFFF; // sin parámetros por defecto
    
    if (param_count > 0 && vm->segment_sizes[SEG_PS] > 0) {
        // Calcular offset del array de punteros en Param Segment
        uint16_t pointer_offset = 0;
        for (int i = 0; i < param_count; i++) {
            pointer_offset += strlen(vm->argv[i]) + 1; // Usar los parámetros reales
        }
        argv_value = (0x0000 << 16) | pointer_offset; // Segmento 0 + offset
    }
    
    // Escribir en la pila
    vm_memory_write(vm, new_sp,     4, 0xFFFFFFFF);    // return address
    vm_memory_write(vm, new_sp + 4, 4, param_count);   // argc
    vm_memory_write(vm, new_sp + 8, 4, argv_value);    // argv
    
    // Actualizar registros
    vm->registers[REG_SP] = new_sp;
    vm->registers[REG_BP] = new_sp;
}

void setup_segment_registers(VM *vm)
{
    // Cada registro de segmento contiene: (segment_id << 16) | base_physical_address
    // Ejemplo: CS = (2 << 16) | 0x0800 → segmento 2, base física 0x0800
    
    // PS - Si existe, siempre es segmento 0
    if (vm->segment_sizes[SEG_PS] > 0)
        vm->registers[REG_PS] = (0 << 16) | vm->segment_bases[SEG_PS];
    else
        vm->registers[REG_PS] = 0xFFFFFFFF;  // No existe

    // KS - Si existe, segmento 1  
    if (vm->segment_sizes[SEG_KS] > 0)
        vm->registers[REG_KS] = (1 << 16) | vm->segment_bases[SEG_KS];
    else
        vm->registers[REG_KS] = 0xFFFFFFFF;

    // CS - Si existe, segmento 2
    if (vm->segment_sizes[SEG_CS] > 0)
        vm->registers[REG_CS] = (2 << 16) | vm->segment_bases[SEG_CS];
    else
        vm->registers[REG_CS] = 0xFFFFFFFF;

    // DS - Si existe, segmento 3
    if (vm->segment_sizes[SEG_DS] > 0)
        vm->registers[REG_DS] = (3 << 16) | vm->segment_bases[SEG_DS];
    else
        vm->registers[REG_DS] = 0xFFFFFFFF;

    // ES - Si existe, segmento 4
    if (vm->segment_sizes[SEG_ES] > 0)
        vm->registers[REG_ES] = (4 << 16) | vm->segment_bases[SEG_ES];
    else
        vm->registers[REG_ES] = 0xFFFFFFFF;

    // SS - Si existe, segmento 5
    if (vm->segment_sizes[SEG_SS] > 0)
        vm->registers[REG_SS] = (5 << 16) | vm->segment_bases[SEG_SS];
    else
        vm->registers[REG_SS] = 0xFFFFFFFF;
}

void setup_segment_table(VM *vm)
{
    // Limpiar tabla
    memset(vm->segment_table, 0, sizeof(vm->segment_table));
    
    int segment_index = 0;

    // PS - siempre primera posición si existe
    if (vm->segment_sizes[SEG_PS] > 0)
    {
        vm->segment_table[segment_index] = (vm->segment_sizes[SEG_PS] << 16) | vm->segment_bases[SEG_PS];
        segment_index++;
        printf("Segmento %d: PS - base=0x%04X, size=%u\n", 
               segment_index-1, vm->segment_bases[SEG_PS], vm->segment_sizes[SEG_PS]);
    }

    // KS - siguiente posición si existe
    if (vm->segment_sizes[SEG_KS] > 0)
    {
        vm->segment_table[segment_index] = (vm->segment_sizes[SEG_KS] << 16) | vm->segment_bases[SEG_KS];
        segment_index++;
        printf("Segmento %d: KS - base=0x%04X, size=%u\n", 
               segment_index-1, vm->segment_bases[SEG_KS], vm->segment_sizes[SEG_KS]);
    }

    // CS - siguiente posición si existe
    if (vm->segment_sizes[SEG_CS] > 0)
    {
        vm->segment_table[segment_index] = (vm->segment_sizes[SEG_CS] << 16) | vm->segment_bases[SEG_CS];
        segment_index++;
        printf("Segmento %d: CS - base=0x%04X, size=%u\n", 
               segment_index-1, vm->segment_bases[SEG_CS], vm->segment_sizes[SEG_CS]);
    }

    // DS - siguiente posición si existe
    if (vm->segment_sizes[SEG_DS] > 0)
    {
        vm->segment_table[segment_index] = (vm->segment_sizes[SEG_DS] << 16) | vm->segment_bases[SEG_DS];
        segment_index++;
        printf("Segmento %d: DS - base=0x%04X, size=%u\n", 
               segment_index-1, vm->segment_bases[SEG_DS], vm->segment_sizes[SEG_DS]);
    }

    // ES - siguiente posición si existe
    if (vm->segment_sizes[SEG_ES] > 0)
    {
        vm->segment_table[segment_index] = (vm->segment_sizes[SEG_ES] << 16) | vm->segment_bases[SEG_ES];
        segment_index++;
        printf("Segmento %d: ES - base=0x%04X, size=%u\n", 
               segment_index-1, vm->segment_bases[SEG_ES], vm->segment_sizes[SEG_ES]);
    }

    // SS - última posición si existe
    if (vm->segment_sizes[SEG_SS] > 0)
    {
        vm->segment_table[segment_index] = (vm->segment_sizes[SEG_SS] << 16) | vm->segment_bases[SEG_SS];
        segment_index++;
        printf("Segmento %d: SS - base=0x%04X, size=%u\n", 
               segment_index-1, vm->segment_bases[SEG_SS], vm->segment_sizes[SEG_SS]);
    }

    printf("Tabla de segmentos: %d segmentos configurados\n", segment_index);
}


int vm_load_program_v2(VM *vm, const char *filename, char **params, int param_count)
{
    FILE *file = fopen(filename, "rb");
    if (!file) return 0;

    // Leer header v2 completo
    char identifier[6];
    fread(identifier, 1, 5, file);
    identifier[5] = '\0';
    vm->argc = param_count;
    vm->argv = params;
    
    uint8_t version;
    fread(&version, 1, 1, file);
    
    uint16_t code_size = read_uint16(file);
    uint16_t data_size = read_uint16(file);
    uint16_t extra_size = read_uint16(file);
    uint16_t stack_size = read_uint16(file);
    uint16_t const_size = read_uint16(file);
    uint16_t entry_offset = read_uint16(file);

    printf("Header v2: CS=%u, DS=%u, ES=%u, SS=%u, KS=%u, Entry=%u\n",
           code_size, data_size, extra_size, stack_size, const_size, entry_offset);

    // Configurar tamaños de segmentos
    vm->segment_sizes[SEG_CS] = code_size;
    vm->segment_sizes[SEG_DS] = data_size > 0 ? data_size : 1024;
    vm->segment_sizes[SEG_ES] = extra_size;
    vm->segment_sizes[SEG_SS] = stack_size > 0 ? stack_size : 1024;
    vm->segment_sizes[SEG_KS] = const_size;
    
    // Calcular tamaño de Param Segment
    vm->segment_sizes[SEG_PS] = calculate_param_segment_size(params, param_count);

    // Calcular layout de memoria
    if (!calculate_memory_layout(vm))
    {
        fclose(file);
        return 0;
    }

    // Cargar código
    fread(&vm->memory[vm->segment_bases[SEG_CS]], 1, code_size, file);
    
    // Cargar constantes (si existen)
    if (const_size > 0)
    {
        fread(&vm->memory[vm->segment_bases[SEG_KS]], 1, const_size, file);
    }

    fclose(file);

    // Configurar parámetros (si existen)
    if (param_count > 0)
    {
        setup_param_segment(vm, params, param_count);
    }

    // Configurar registros de segmentos
    setup_segment_registers(vm);
    
    // Entry point
    vm->entry_point = entry_offset;
    vm->registers[REG_IP] = vm->registers[REG_CS] + entry_offset;
    
    // Inicializar pila para main
    setup_initial_stack(vm, param_count);

    // Configurar tabla de segmentos
    setup_segment_table(vm);

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
        uint8_t type_b = first_byte >> 6;
        uint8_t type_a = (first_byte >> 4) & 0b0011;
        uint8_t op_code = first_byte & 0x1F;

        if (op_code > 0x1F)
        {
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
        if (op_code != 0x8 && op_code != 0X0 && op_code != OPC_JMP && op_code != OPC_JZ && op_code != OPC_JP && op_code != OPC_JN && op_code != OPC_JNZ && op_code != OPC_JNP && op_code != OPC_JNN) // Si no es NOT o SYS
        {
            // 2 operandos.
            vm->registers[REG_OP1] = (type_a << 24) | opa_bytes;
            vm->registers[REG_OP2] = (type_b << 24) | opb_bytes;
            vm->registers[REG_OPC] = op_code;
        }
        else // Si tiene un solo operando ponemos en el registro OP1 opb_bytes y tipo
        {
            vm->registers[REG_OP1] = (type_b << 24) | opb_bytes;
            vm->registers[REG_OPC] = op_code;
        }

        uint16_t new_off = offset + instr_len;
        uint16_t code_size = vm->segment_table[0] >> 16;
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

const char *get_register_name(uint8_t reg_code)
{
    switch (reg_code)
    {
    case REG_LAR:
        return "LAR";
    case REG_MAR:
        return "MAR";
    case REG_MBR:
        return "MBR";
    case REG_IP:
        return "IP";
    case REG_OPC:
        return "OPC";
    case REG_OP1:
        return "OP1";
    case REG_OP2:
        return "OP2";
    case REG_EAX:
        return "EAX";
    case REG_EBX:
        return "EBX";
    case REG_ECX:
        return "ECX";
    case REG_EDX:
        return "EDX";
    case REG_EEX:
        return "EEX";
    case REG_EFX:
        return "EFX";
    case REG_AC:
        return "AC";
    case REG_CC:
        return "CC";
    case REG_CS:
        return "CS";
    case REG_DS:
        return "DS";
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
        printf("%s", get_register_name(value & 0xFF));
        break;

    case OP_TYPE_IMMEDIATE:
        printf("%d", (int16_t)(value & 0xFFFF));
        break;

    case OP_TYPE_MEMORY:
    {
        uint8_t reg_code = (value >> 16) & 0xFF;
        int16_t displacement = (int16_t)(value & 0xFFFF);

        printf("[");
        if (reg_code != 0)
        {
            printf("%s", get_register_name(reg_code));
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
    int offset = 1;

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
    if (op_code == OPC_SYS || op_code == OPC_NOT)
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
    printf("Disassembling code segment:\n");
    printf("===========================\n\n");

    // CORREGIR: Base en HIGH bits, Tamaño en LOW bits
    uint16_t base_phys = vm->segment_table[0] & 0xFFFF; // Base física
    uint16_t code_size = vm->segment_table[0] >> 16;    // Tamaño del código

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
        printf("[%04X] ", phys_addr);
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
        disassemble_instruction(vm, phys_addr, op_code, type_a, type_b);

        ip += instr_len;
    }
}

int main(int argc, char **argv)
{
    const char *vmx_filename = NULL;
    const char *vmi_filename = NULL;
    const char *memory_size_str = NULL;
    bool disassemble = false;
    bool has_params = false;
    char **program_params = NULL;
    int param_count = 0;
    size_t memory_size = MEMORY_SIZE; 

    // 1. PRIMERO parsear argumentos 
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-d") == 0)
        {
            disassemble = true;
        }
        else if (strncmp(argv[i], "m=", 2) == 0)
        {
            memory_size_str = argv[i] + 2;
        }
        else if (strcmp(argv[i], "-p") == 0)
        {
            has_params = true;
            // Los parámetros siguientes son los del programa
            param_count = argc - i - 1;
            if (param_count > 0)
            {
                program_params = &argv[i + 1];
            }
            break; // -p siempre va al final
        }
        else
        {
            // Determinar si es .vmx o .vmi por la extensión
            const char *ext = strrchr(argv[i], '.');
            if (ext != NULL)
            {
                if (strcmp(ext, ".vmx") == 0)
                {
                    vmx_filename = argv[i];
                }
                else if (strcmp(ext, ".vmi") == 0)
                {
                    vmi_filename = argv[i];
                }
            }
        }
    } // ← CIERRA EL FOR AQUÍ

    // 2. Validaciones básicas (FUERA DEL FOR)
    if (vmx_filename == NULL && vmi_filename == NULL)
    {
        printf("Error: Se requiere al menos un archivo .vmx o .vmi\n");
        printf("Uso: vmx [archivo.vmx] [archivo.vmi] [m=M] [-d] [-p param1 param2 ...]\n");
        return 1;
    }

    if (has_params && vmx_filename == NULL)
    {
        printf("Advertencia: Parámetros -p ignorados sin archivo .vmx\n");
        has_params = false;
        program_params = NULL;
        param_count = 0;
    }

    // 3. Procesar tamaño de memoria
    if (memory_size_str != NULL)
    {
        memory_size = (size_t)atoi(memory_size_str) * 1024; // Convertir KiB a bytes
        if (memory_size == 0)
        {
            printf("Error: Tamaño de memoria inválido\n");
            return 1;
        }
    }

    // 4. Mostrar configuración
    printf("Configuración:\n");
    printf("  Memoria: %zu KiB (%zu bytes)\n", memory_size / 1024, memory_size);
    if (vmx_filename) printf("  Programa: %s\n", vmx_filename);
    if (vmi_filename) printf("  Imagen: %s\n", vmi_filename);
    if (disassemble) printf("  Desensamblar: SI\n");
    if (has_params)
    {
        printf("  Parámetros (%d): ", param_count);
        for (int i = 0; i < param_count; i++)
        {
            printf("\"%s\" ", program_params[i]);
        }
        printf("\n");
    }
    printf("\n");

    // 5. Inicializar máquina virtual
    VM vm;
    init_instruction_table();
    
    // Inicializar con tamaño de memoria específico
    if (!vm_init(&vm, memory_size))
    {
        printf("Error: No se pudo inicializar la máquina virtual\n");
        return 1;
    }

    // 6. Cargar programa o imagen según lo disponible
    int load_result = 0;
    
    if (vmx_filename && vmi_filename)
    {
        // Ambos archivos - cargar programa y configurar imagen para breakpoints
        printf("Modo: Ejecutar programa con breakpoints\n");
        load_result = vm_load_program(&vm, vmx_filename, program_params, param_count);
        vm.vmi_filename = vmi_filename; // Para breakpoints
    }
    else if (vmx_filename)
    {
        // Solo programa - ejecución normal
        printf("Modo: Ejecutar programa nuevo\n");
        load_result = vm_load_program(&vm, vmx_filename, program_params, param_count);
    }
    else if (vmi_filename)
    {
        // Solo imagen - continuar ejecución
        printf("Modo: Continuar desde imagen\n");
        load_result = vm_load_image(&vm, vmi_filename);
    }

    if (load_result <= 0)
    {
        printf("Error: No se pudo cargar el programa/imagen\n");
        vm_cleanup(&vm);
        return 1;
    }

    // 7. Si es modo disassemble, mostrar
    if (disassemble)
    {
        vm_disassemble(&vm);
    }

    // 8. Si no, ejecutar normalmente
    vm_execute(&vm);

    vm_cleanup(&vm);
    printf("Ejecución finalizada\n");
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
        vm->running = false;
        return -1;
    }

    uint32_t entry = vm->segment_table[seg];
    uint16_t base_phys = entry & 0xFFFF;
    uint16_t seg_size = (entry >> 16) & 0xFFFF;
    if (offset + num_bytes > seg_size)
    {
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

    if (cell_size == 0 || cell_size > 4)
    {
        vm->running = false;
        return;
    }

    if (sys_call == 1)
    { // READ
        for (int i = 0; i < cell_count; i++)
        {
            uint32_t current_addr = edx + (i * cell_size);
            printf("[%04X]: ", (uint16_t)current_addr);

            int32_t value = 0;
            int scan_result = 0;

            // Leer según el formato especificado en EAX
            if (eax & 0x01)
            { // Decimal
                scan_result = scanf("%d", &value);
            }
            else if (eax & 0x02)
            { // Carácter
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
                vm->running = false;
                return;
            }

            if (scan_result != 1)
            {
                vm->running = false;
                return;
            }

            // Escribir en memoria
            if (!vm_memory_write(vm, current_addr, cell_size, value))
            {
                vm->running = false;
                return;
            }
        }
    }
    else if (sys_call == 2)
    { // WRITE
        for (int i = 0; i < cell_count; i++)
        {
            uint32_t current_addr = edx + (i * cell_size);
            uint32_t value = vm_memory_read(vm, current_addr, cell_size);

            printf("[%04X]: ", (uint16_t)current_addr);

            // Mostrar según los bits activos en EAX

            bool printed = false;

            if (eax & 0x10)
            { // Binario
                for (int bit = (cell_size * 8) - 1; bit >= 0; bit--)
                    printf("%d ", (value >> bit) & 1);
                printf(" ");
                printed = true;
            }
            if (eax & 0x08)
            { // Hexadecimal
                printf("0x%X ", value);
                printed = true;
            }
            if (eax & 0x04)
            { // Octal
                printf("0o%o ", value);
                printed = true;
            }
            if (eax & 0x02)
            { // Carácter
                if (value >= 32 && value <= 126)
                    printf("%c ", (char)value);
                else
                    printf(". ");
                printed = true;
            }
            if (eax & 0x01)
            { // Decimal
                printf("%d ", value);
                printed = true;
            }

            if (!printed)
            {
                vm->running = false;
                return;
            }
            printf("\n");
        }
    }
    else
    {
        vm->running = false;
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

    if (vm->registers[REG_CC] & 0x40000000) // Z=1
    {                                       // IF Z==1
        int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]);
        vm->registers[REG_IP] = direc;
    }
}

void instr_JP(VM *vm)
{

    if (!(vm->registers[REG_CC] & 0x40000000) && !(vm->registers[REG_CC] & 0x80000000))
    {
        int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]);
        vm->registers[REG_IP] = direc;
    }
}

void instr_JN(VM *vm)
{

    if (vm->registers[REG_CC] & 0x80000000) // N =1
    {
        int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]);
        vm->registers[REG_IP] = direc;
    }
}

void instr_JNZ(VM *vm)
{

    if ((vm->registers[REG_CC] & 0x80000000) || (!(vm->registers[REG_CC] & 0x40000000) && !(vm->registers[REG_CC] & 0x80000000)))
    {
        int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]);
        vm->registers[REG_IP] = direc;
    }
}

void instr_JNP(VM *vm)
{
    if ((vm->registers[REG_CC] & 0x80000000) || (vm->registers[REG_CC] & 0x40000000))
    { // IF  Z o N activas
        int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]);
        vm->registers[REG_IP] = direc;
    }
}

void instr_JNN(VM *vm)
{

    if ((vm->registers[REG_CC] & 0x40000000) || (!(vm->registers[REG_CC] & 0x40000000) && !(vm->registers[REG_CC] & 0x80000000)))
    { // IF
        int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]);
        vm->registers[REG_IP] = direc;
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

// LO DE LA IP ESTÁ BIEN ¿?
void instr_STOP(VM *vm)
{
    vm->registers[REG_IP] = 0xFFFFFFFF; // IP inválida para indicar fin de ejecución
    vm->running = false;
}