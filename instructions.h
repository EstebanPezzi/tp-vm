#ifndef INSTRUCTIONS_H
#define INSTRUCTIONS_H

#include "vmx.h"

// Declarar todas las funciones de instrucciones
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



// Declarar la tabla y función de inicialización
extern InstructionFunc instruction_table[0x20];
void init_instruction_table();

// Prototipos de funciones auxiliares usadas en instructions.c
uint32_t translate_logical(VM *vm, uint32_t logical_addr, uint16_t num_bytes);
uint32_t vm_memory_read(VM *vm, uint32_t logical_addr, uint8_t num_bytes);
uint32_t vm_memory_write(VM *vm, uint32_t logical_addr, uint8_t num_bytes, uint32_t value);
#endif