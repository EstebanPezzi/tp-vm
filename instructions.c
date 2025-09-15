#include "vmx.h"



//Vector punto a funcion
InstructionFunc instruction_table[0x20]; // 32 instrucciones posibles
void init_instruction_table() {
    instruction_table[OPC_MOV] = instr_MOV;
    instruction_table[OPC_ADD]  = instr_ADD;
    instruction_table[OPC_SUB]  = instr_SUB;
    instruction_table[OPC_MUL] = instr_MUL;
    instruction_table[OPC_DIV]  = instr_DIV;
    instruction_table[OPC_CMP]  = instr_CMP;
    instruction_table[OPC_SHL] = instr_SHL;
    instruction_table[OPC_SHR]  = instr_SHR;
    instruction_table[OPC_SAR]  = instr_SAR;
    instruction_table[OPC_AND]  = instr_AND;
    instruction_table[OPC_OR] = instr_OR;
    instruction_table[OPC_XOR]  = instr_XOR;
    instruction_table[OPC_SWAP]  = instr_SWAP;
    instruction_table[OPC_LDL] = instr_LDL;
    instruction_table[OPC_LDH]  = instr_LDH;
    instruction_table[OPC_RND]  = instr_RND;
    instruction_table[OPC_SYS] = instr_SYS;
    instruction_table[OPC_JMP]  = instr_JMP;
    instruction_table[OPC_JZ]  = instr_JZ;
    instruction_table[OPC_JP]  = instr_JP;
    instruction_table[OPC_JN]  = instr_JN;
    instruction_table[OPC_JNZ]  = instr_JNZ;
    instruction_table[OPC_JNP]  = instr_JNP;
    instruction_table[OPC_JNN]  = instr_JNN;
    instruction_table[OPC_NOT]  = instr_NOT;
    instruction_table[OPC_STOP]  = instr_STOP;
}



// Leer el valor de un operando
int32_t read_operand(VM *vm, Operand op) {
    switch (op.tipo) {
        case OP_TYPE_REGISTER: // su valor es el código del registro al cual se accede.
            return vm->registers[op.valor];
        case OP_TYPE_IMMEDIATE: //su valor es directamente el valor del operando.
            return op.valor;
        case OP_TYPE_MEMORY: //REVISAR!!!!!!!!!!
            uint8_t reg_base = (op.valor >> 16) & 0xFF; 
            uint16_t offset = op.valor & 0xFFFF;
            uint32_t addr = vm->registers[reg_base] + offset; // dirección lógica
            return vm->memory[addr]; 
        default:
            return 0;
    }
}


// Escribir valor en un operando
void write_operand(VM *vm, Operand op, int32_t value) {
    switch (op.tipo) {
        case OP_TYPE_REGISTER:
            vm->registers[op.valor] = value;
            break;
        case OP_TYPE_MEMORY: //Revisar...
            uint8_t reg_base = (op.valor >> 16) & 0xFF;
            uint16_t offset = op.valor & 0xFFFF;
            uint32_t addr = vm->registers[reg_base] + offset; // dirección lógica
            vm->memory[addr] = value & 0xFF; // por ahora 1 byte
            break;
        default:
            printf("No se puede escribir en este tipo de operando\n");
            vm->running = false;
            break;
    }
}

 Operand decode_operand(uint32_t raw) {
    Operand op;
    op.tipo  = (raw >> 24) & 0xFF;   // los 8 bits altos guardan el tipo
    op.valor = raw & 0xFFFFFF;       // los 24 bits bajos guardan el valor
    return op;
}

//bits mas significativos?
void update_flags(VM *vm, int32_t result) {
    vm->registers[REG_CC] = 0;

    if (result == 0) 
        vm->registers[REG_CC] |= 0x01;   // Zero flag (bit 0)
    if (result < 0)  
        vm->registers[REG_CC] |= 0x02;   // Negative flag (bit 1)
}


//Se debe modularizar más ¿?

void instr_MOV(VM *vm) {
    Operand op1 = decode_operand(vm->registers[REG_OP1]);
    Operand op2 = decode_operand(vm->registers[REG_OP2]);

    int32_t value = read_operand(vm, op2);     // leer OP2
    write_operand(vm, op1, value);             // escribir en OP1
}

void instr_ADD(VM *vm){
    Operand op1 = decode_operand(vm->registers[REG_OP1]);
    Operand op2 = decode_operand(vm->registers[REG_OP2]);

    int32_t val1 = read_operand(vm, op1);
    int32_t val2 = read_operand(vm, op2);

    int32_t result = val1 + val2; //Hay que tener en cuenta Overflow??? hacerlo con int64 x si acaso??

    write_operand(vm, op1, result); 

    update_flags(vm, result); //Actualiza el registro CC. 
}

void instr_SUB(VM *vm){
    Operand op1 = decode_operand(vm->registers[REG_OP1]);
    Operand op2 = decode_operand(vm->registers[REG_OP2]);

    int32_t val1 = read_operand(vm, op1);
    int32_t val2 = read_operand(vm, op2);

    int32_t result = val1 - val2;

    write_operand(vm, op1, result); 

    update_flags(vm, result); //Actualiza el registro CC. 
}

void instr_MUL(VM *vm){
    Operand op1 = decode_operand(vm->registers[REG_OP1]);
    Operand op2 = decode_operand(vm->registers[REG_OP2]);

    int32_t val1 = read_operand(vm, op1);
    int32_t val2 = read_operand(vm, op2);

    int64_t result = (int64_t)val1 * (int64_t)val2;  // para detectar overflow
    int32_t truncated = (int32_t)result; //si hubo overflow perdes datos. analizar

    write_operand(vm, op1, truncated); 

    update_flags(vm, truncated); //Actualiza el registro CC. 
}

void instr_DIV(VM *vm){
    Operand op1 = decode_operand(vm->registers[REG_OP1]);
    Operand op2 = decode_operand(vm->registers[REG_OP2]);

    int32_t val1 = read_operand(vm, op1);
    int32_t val2 = read_operand(vm, op2);

    if (val2 == 0) {
        printf("Error: división por cero\n");
        vm->running = false;
        return;
    }

    int32_t cociente = val1 / val2; //Division entera
    uint32_t resto = val1 % val2;  // resto

    write_operand(vm, op1, cociente); 
    vm->registers[REG_AC] = resto;     // resto en AC

    update_flags(vm, cociente); //Actualiza el registro CC. 
}

void instr_CMP(VM *vm){
    Operand op1 = decode_operand(vm->registers[REG_OP1]);
    Operand op2 = decode_operand(vm->registers[REG_OP2]);

    int32_t val1 = read_operand(vm, op1);
    int32_t val2 = read_operand(vm, op2);

    int32_t result = val1 - val2;

    update_flags(vm, result); //Actualiza el registro CC. 
}

void instr_SHL(VM *vm){
    Operand op1 = decode_operand(vm->registers[REG_OP1]);
    Operand op2 = decode_operand(vm->registers[REG_OP2]);

    int32_t val = read_operand(vm, op1);
    int32_t shift = read_operand(vm, op2);

    int32_t result = val << shift;

    write_operand(vm, op1, result); 

    update_flags(vm, result); //Actualiza el registro CC. 
}

void instr_SHR(VM *vm){
    Operand op1 = decode_operand(vm->registers[REG_OP1]);
    Operand op2 = decode_operand(vm->registers[REG_OP2]);

    int32_t val = read_operand(vm, op1);
    int32_t shift = read_operand(vm, op2);

    //Revisar ->. mascara?
    uint32_t uval = (uint32_t)val;   // convertir a unsigned para shift lógico
    uint32_t result = uval >> shift; // corrimiento lógico

    write_operand(vm, op1, (int32_t)result); 

    update_flags(vm, result); //Actualiza el registro CC. 
}

void instr_SAR(VM *vm){
    Operand op1 = decode_operand(vm->registers[REG_OP1]);
    Operand op2 = decode_operand(vm->registers[REG_OP2]);

    int32_t val = read_operand(vm, op1);
    int32_t shift = read_operand(vm, op2);

    int32_t result = val >> shift; // en C el shift es aritmético

    write_operand(vm, op1, result); 

    update_flags(vm, result); // Actualiza el registro CC. 
}

void instr_AND(VM *vm){
    Operand op1 = decode_operand(vm->registers[REG_OP1]);
    Operand op2 = decode_operand(vm->registers[REG_OP2]);

    int32_t val1 = read_operand(vm, op1);
    int32_t val2 = read_operand(vm, op2);

    int32_t result = val1 & val2; 

    write_operand(vm, op1, result); 

    update_flags(vm, result); //Actualiza el registro CC. 
}

void instr_OR(VM *vm){
    Operand op1 = decode_operand(vm->registers[REG_OP1]);
    Operand op2 = decode_operand(vm->registers[REG_OP2]);

    int32_t val1 = read_operand(vm, op1);
    int32_t val2 = read_operand(vm, op2);

    int32_t result = val1 | val2; 

    write_operand(vm, op1, result); 

    update_flags(vm, result); //Actualiza el registro CC. 
}

void instr_XOR(VM *vm){
    Operand op1 = decode_operand(vm->registers[REG_OP1]);
    Operand op2 = decode_operand(vm->registers[REG_OP2]);

    int32_t val1 = read_operand(vm, op1);
    int32_t val2 = read_operand(vm, op2);

    int32_t result = val1 ^ val2; 

    write_operand(vm, op1, result); 

    update_flags(vm, result); //Actualiza el registro CC. 
}

void instr_SWAP(VM *vm) {
    Operand op1 = decode_operand(vm->registers[REG_OP1]);
    Operand op2 = decode_operand(vm->registers[REG_OP2]);

    int32_t val1 = read_operand(vm, op1);
    int32_t val2 = read_operand(vm, op2);

    // Intercambiar
    write_operand(vm, op1, val2);
    write_operand(vm, op2, val1);

    // No modifica CC
}

void instr_LDH(VM *vm) {
    Operand op1 = decode_operand(vm->registers[REG_OP1]); // destino
    Operand op2 = decode_operand(vm->registers[REG_OP2]); // fuente

    int32_t val1 = read_operand(vm, op1);
    int32_t val2 = read_operand(vm, op2);

    // Tomamos los 16 bits menos significativos de val2
    int32_t low16 = val2 & 0xFFFF;

    // Limpiamos los 16 bits más significativos de val1 y los reemplazamos con low16
    int32_t result = (low16 << 16) | (val1 & 0xFFFF);

    write_operand(vm, op1, result);

    // No modificamos CC
}

void instr_LDL(VM *vm) {
    Operand op1 = decode_operand(vm->registers[REG_OP1]); // destino
    Operand op2 = decode_operand(vm->registers[REG_OP2]); // fuente

    int32_t val1 = read_operand(vm, op1);
    int32_t val2 = read_operand(vm, op2);

    // Tomamos los 16 bits menos significativos de val2
    int32_t low16 = val2 & 0xFFFF;

    // Conservo los 16 bits altos de val1, y meto los 16 bits bajos de val2
    int32_t result = (val1 & 0xFFFF0000) | low16;

    write_operand(vm, op1, result);

    // No modificamos CC
}

void instr_RND(VM *vm){
    Operand op1 = decode_operand(vm->registers[REG_OP1]);
    Operand op2 = decode_operand(vm->registers[REG_OP2]);

    int32_t max = read_operand(vm, op2);

    if (max < 0) {
        max = -max;  // aseguramos que sea positivo
    }

    int32_t rnd = (max == 0) ? 0 : rand() % (max + 1); //numero entre 0 y max. el +1 incluye a max

    write_operand(vm, op1, rnd); 
}

//FALTA HACER SYS ME DIO FIACA
void instr_SYS(VM *vm){ 

}

void instr_JMP(VM *vm){
    Operand op1 = decode_operand(vm->registers[REG_OP1]);
    int32_t direc = read_operand(vm, op1); //Direccion del salto

    vm->registers[REG_IP] = direc;
}

//Revisar las condiciones de salto, me maree un poco
void instr_JZ(VM *vm){
    Operand op1 = decode_operand(vm->registers[REG_OP1]);

    if (vm->registers[REG_CC] & 0x01){ //IF Z==1
        int32_t direc = read_operand(vm, op1); //Direccion del salto
        vm->registers[REG_IP] = direc;
    }
}

void instr_JP(VM *vm){ //solo si N no es 1 revisar
    Operand op1 = decode_operand(vm->registers[REG_OP1]);

     if ((vm->registers[REG_CC] & 0x03) == 0) {  // N = 0 y Z = 0
        int32_t direc = read_operand(vm, op1); //Direccion del salto
        vm->registers[REG_IP] = direc;
    }
}

void instr_JN(VM *vm){
    Operand op1 = decode_operand(vm->registers[REG_OP1]);

    if (vm->registers[REG_CC] & 0x02){ //IF N=1
        int32_t direc = read_operand(vm, op1); //Direccion del salto
        vm->registers[REG_IP] = direc;
    }
}

void instr_JNZ(VM *vm){
    Operand op1 = decode_operand(vm->registers[REG_OP1]);

    if ((vm->registers[REG_CC] & 0x01) == 0){ //IF Z==0
        int32_t direc = read_operand(vm, op1); //Direccion del salto
        vm->registers[REG_IP] = direc;
    }
}

void instr_JNP(VM *vm){
    Operand op1 = decode_operand(vm->registers[REG_OP1]);

    if ((vm->registers[REG_CC] & 0x03) != 0){  //IF  Z o N activas
        int32_t direc = read_operand(vm, op1); //Direccion del salto
        vm->registers[REG_IP] = direc;
    }
}

void instr_JNN(VM *vm){
    Operand op1 = decode_operand(vm->registers[REG_OP1]);

    if ((vm->registers[REG_CC] & 0x02) == 0){ //IF
        int32_t direc = read_operand(vm, op1); //Direccion del salto
        vm->registers[REG_IP] = direc;
    }
}

void instr_NOT(VM *vm){
    Operand op1 = decode_operand(vm->registers[REG_OP1]);

    int32_t val1 = read_operand(vm, op1);

    int32_t result = ~val1 ;                 // Negación bit a bit
    write_operand(vm, op1, result);           // Guardar el resultado 

    update_flags(vm, result); //Actualiza el registro CC. 
}

//LO DE LA IP ESTÁ BIEN ¿?
void instr_STOP(VM *vm) {
    vm->registers[REG_IP] = 0xFFFFFFFF;  // IP inválida para indicar fin de ejecución
    vm->running = false;
}

