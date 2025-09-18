#include "vmx.h"
#include "instructions.h"


InstructionFunc instruction_table[0x20];

void init_instruction_table() {
    // Inicializar a NULL
    for (int i = 0; i < 0x20; i++) {
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
    printf("[DEBUG] tipo = %02X\n", type);

    if (type == OP_TYPE_REGISTER) {
        return vm->registers[value];
    }
    else if (type == OP_TYPE_IMMEDIATE || type == 0x02) {
        return value;
    }
    else if (type == OP_TYPE_MEMORY || type == 0x0B) {
        // --- NUEVO: tomar byte bajo como registro base ---
        uint8_t base_reg_code = value & 0xFF;           // último byte
        int16_t disp = (int16_t)((value >> 8) & 0xFFFF); // los otros 2 bytes
        uint32_t base_ptr = vm->registers[base_reg_code];
        uint16_t base_seg = base_ptr >> 16;
        uint16_t base_off = base_ptr & 0xFFFF;
        int32_t logical_off = (int32_t)base_off + disp;
        if (logical_off < 0) {
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
    printf("\n tipo = %x \n", type);

    if (type == OP_TYPE_REGISTER) {
        vm->registers[value_field] = value;
    }
    else if (type == OP_TYPE_MEMORY || type == 0x0B) {
        uint8_t base_reg_code = value_field & 0xFF;             // último byte
        int16_t disp = (int16_t)((value_field >> 8) & 0xFFFF);  // los otros 2 bytes
        uint32_t base_ptr = vm->registers[base_reg_code];       // por ej, EAX o DS
        uint16_t base_seg = base_ptr >> 16;
        uint16_t base_off = base_ptr & 0xFFFF;
        int32_t logical_off = (int32_t)base_off + disp;
        if (logical_off < 0) {
            vm->running = false;
            return;
        }
        uint32_t logical_addr = (base_seg << 16) | (logical_off & 0xFFFF);
        vm_memory_write(vm, logical_addr, 4, value); // Por defecto 4 bytes
    }
}


//bits mas significativos?
void update_flags(VM *vm, int32_t result) {
 // Actualizar el cc
            uint32_t cc = vm->registers[REG_CC];
            cc &= 0x3FFFFFFF;
            cc |= (result & 0x80000000) ? 0x80000000 : 0; // Bit 31 = N (signo)
            cc |= (result == 0) ? 0x40000000 : 0;         // Bit 30 = Z (cero)
            vm->registers[REG_CC] = cc;
}


//Se debe modularizar más ¿?

void instr_MOV(VM *vm) {
    int32_t value = get_operand_value(vm, vm->registers[REG_OP2]);
    set_operand_value( vm, vm->registers[REG_OP1], value);
}

void instr_ADD(VM *vm){
    int32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]);
    int32_t val2 = get_operand_value(vm, vm->registers[REG_OP2]);

    
    int32_t result = val1 + val2;

    set_operand_value( vm, vm->registers[REG_OP1], result);

    update_flags(vm, result); //Actualiza el registro CC. 
}

void instr_SUB(VM *vm){
    int32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]);
    int32_t val2 = get_operand_value(vm, vm->registers[REG_OP2]);

    int32_t result = val1 - val2;

    set_operand_value( vm, vm->registers[REG_OP1], result);

    update_flags(vm, result); //Actualiza el registro CC. 
}

void instr_MUL(VM *vm){
    int32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]);
    int32_t val2 = get_operand_value(vm, vm->registers[REG_OP2]);

    int64_t result = (int64_t)val1 * (int64_t)val2;  // para detectar overflow
    int32_t truncated = (int32_t)result; //si hubo overflow perdes datos. analizar

    set_operand_value( vm, vm->registers[REG_OP1], result); 

    update_flags(vm, truncated); //Actualiza el registro CC. 
}

void instr_DIV(VM *vm){
    int32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]);
    int32_t val2 = get_operand_value(vm, vm->registers[REG_OP2]);

    if (val2 == 0) {
        printf("Error: división por cero\n");
        vm->running = false;
        return;
    }

    int32_t cociente = val1 / val2; //Division entera
    uint32_t resto = val1 % val2;  // resto

    set_operand_value( vm, vm->registers[REG_OP1], cociente); 
    vm->registers[REG_AC] = resto;     // resto en AC

    update_flags(vm, cociente); //Actualiza el registro CC. 
}

void instr_CMP(VM *vm){
    int32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]);
    int32_t val2 = get_operand_value(vm, vm->registers[REG_OP2]);

    int32_t result = val1 - val2;

    update_flags(vm, result); //Actualiza el registro CC. 
}

void instr_SHL(VM *vm){
    int32_t val = get_operand_value(vm, vm->registers[REG_OP1]);
    int32_t shift = get_operand_value(vm, vm->registers[REG_OP2]);

    int32_t result = val << shift;

    set_operand_value( vm, vm->registers[REG_OP1], result);  

    update_flags(vm, result); //Actualiza el registro CC. 
}

void instr_SHR(VM *vm){
    int32_t val = get_operand_value(vm, vm->registers[REG_OP1]);
    int32_t shift = get_operand_value(vm, vm->registers[REG_OP2]);

    //Revisar ->. mascara?
    uint32_t uval = (uint32_t)val;   // convertir a unsigned para shift lógico
    uint32_t result = uval >> shift; // corrimiento lógico

    set_operand_value( vm, vm->registers[REG_OP1], (int32_t)result);

    update_flags(vm, result); //Actualiza el registro CC. 
}

void instr_SAR(VM *vm){
    int32_t val = get_operand_value(vm, vm->registers[REG_OP1]);
    int32_t shift = get_operand_value(vm, vm->registers[REG_OP2]);

    int32_t result = val >> shift; // en C el shift es aritmético

    set_operand_value(vm, vm->registers[REG_OP1], result); 

    update_flags(vm, result); // Actualiza el registro CC. 
}

void instr_AND(VM *vm){
    int32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]);
    int32_t val2 = get_operand_value(vm, vm->registers[REG_OP2]);

    int32_t result = val1 & val2; 

    set_operand_value(vm, vm->registers[REG_OP1], result);

    update_flags(vm, result); //Actualiza el registro CC. 
}

void instr_OR(VM *vm){
    int32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]);
    int32_t val2 = get_operand_value(vm, vm->registers[REG_OP2]);

    int32_t result = val1 | val2; 

    set_operand_value(vm, vm->registers[REG_OP1], result); 

    update_flags(vm, result); //Actualiza el registro CC. 
}

void instr_XOR(VM *vm){
    int32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]);
    int32_t val2 = get_operand_value(vm, vm->registers[REG_OP2]);

    int32_t result = val1 ^ val2; 

    set_operand_value(vm, vm->registers[REG_OP1], result); 

    update_flags(vm, result); //Actualiza el registro CC. 
}

void instr_SWAP(VM *vm) {
    int32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]);
    int32_t val2 = get_operand_value(vm, vm->registers[REG_OP2]);


    // Intercambiar
   set_operand_value(vm, vm->registers[REG_OP1], val2);
   set_operand_value(vm, vm->registers[REG_OP2], val1);

    // No modifica CC
}

void instr_LDH(VM *vm) {
    int32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]); //destino
    int32_t val2 = get_operand_value(vm, vm->registers[REG_OP2]); //fuente

    // Tomamos los 16 bits menos significativos de val2
    int32_t low16 = val2 & 0xFFFF;

    // Limpiamos los 16 bits más significativos de val1 y los reemplazamos con low16
    int32_t result = (low16 << 16) | (val1 & 0xFFFF);

    set_operand_value(vm, vm->registers[REG_OP1], result);

    // No modificamos CC
}

//hay algo que no anda
void instr_LDL(VM *vm) {
    int32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]); //destino
    int32_t val2 = get_operand_value(vm, vm->registers[REG_OP2]); //fuente

    // Tomamos los 16 bits menos significativos de val2
    int32_t low16 = val2 & 0xFFFF;

    // Conservo los 16 bits altos de val1, y meto los 16 bits bajos de val2
    int32_t result = (val1 & 0xFFFF0000) | low16;

    set_operand_value(vm, vm->registers[REG_OP1], result);

    // No modificamos CC
}

void instr_RND(VM *vm){
    int32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]); 
    int32_t max = get_operand_value(vm, vm->registers[REG_OP2]); 

    if (max < 0) {
        max = -max;  // aseguramos que sea positivo
    }

    int32_t rnd = (max == 0) ? 0 : rand() % (max + 1); //numero entre 0 y max. el +1 incluye a max

    set_operand_value(vm, vm->registers[REG_OP1], rnd); 
}

//Revisar
void instr_SYS(VM *vm){ 
    uint32_t op_mode = get_operand_value(vm, vm->registers[REG_OP2]); // 1=READ, 2=WRITE
    uint32_t fmt = vm->registers[REG_EAX];  // formato: 0x01 DEC, 0x10 BIN, 0x08 HEX, 0x04 OCT, 0x02 CHAR
    uint32_t start_addr = vm->registers[REG_EDX];
    uint32_t ecx = vm->registers[REG_ECX];

    uint16_t cell_size = ecx >> 16;
    uint16_t cell_count = ecx & 0xFFFF;

    for (int i = 0; i < cell_count; i++) {
        uint32_t logical_addr = start_addr + i * cell_size;
        uint32_t phys_addr = translate_logical(vm, logical_addr, cell_size);
        if (phys_addr == (uint32_t)-1) return;

        if (op_mode == 1) { // READ
            int value;
            scanf("%d", &value);
            vm_memory_write(vm, logical_addr, cell_size, value);
        } 
        else if (op_mode == 2) { // WRITE
            uint32_t value = vm_memory_read(vm, logical_addr, cell_size);
            switch(fmt){
                case 0x01: printf("%u\n", value); break; // DEC
                case 0x10: { // BIN
                    for(int b=cell_size*8-1;b>=0;b--) printf("%u",(value>>b)&1);
                    printf("\n");
                    break;
                }
                case 0x08: printf("%X\n", value); break; // HEX
                case 0x04: printf("%o\n", value); break; // OCT
                case 0x02: printf("%c\n", (char)value); break; // CHAR
                default: printf("Formato inválido: 0x%X\n", fmt); vm->running=false; return;
            }
        } 
        else {
            printf("Modo SYS inválido: %u\n", op_mode);
            vm->running = false;
            return;
        }
    }
}


void instr_JMP(VM *vm){
    int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]); //Direccion del salto

    vm->registers[REG_IP] = direc;
}

//Revisar las condiciones de salto, me maree un poco
void instr_JZ(VM *vm){
    

    if (vm->registers[REG_CC] & 0x40000000){ //IF Z==1
        int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]);
        vm->registers[REG_IP] = direc;
    }
}

void instr_JP(VM *vm){ //solo si N no es 1 revisar
    

     if (!(vm->registers[REG_CC] & 0x80000000)) {  // N = 0 y Z = 0
        int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]);
        vm->registers[REG_IP] = direc;
    }
}

void instr_JN(VM *vm){
    
    if (vm->registers[REG_CC] & 0x80000000){ 
        int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]);
        vm->registers[REG_IP] = direc;
    }
}

void instr_JNZ(VM *vm){
    

    if (!(vm->registers[REG_CC] & 0x40000000)){ 
        int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]);
        vm->registers[REG_IP] = direc;
    }
}

//????
void instr_JNP(VM *vm){
    

    if ((vm->registers[REG_CC] & 0x03) != 0){  //IF  Z o N activas
        int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]);
        vm->registers[REG_IP] = direc;
    }
}

void instr_JNN(VM *vm){
    

    if (! (vm->registers[REG_CC] & 0x80000000)){ //IF
        int32_t direc = get_operand_value(vm, vm->registers[REG_OP1]);
        vm->registers[REG_IP] = direc;
    }
}

//Seria con el operando 2?
void instr_NOT(VM *vm){
    int32_t val1 = get_operand_value(vm, vm->registers[REG_OP1]);


    int32_t result = ~val1 ;                 // Negación bit a bit
    set_operand_value(vm, vm->registers[REG_OP1], result); // Guardar el resultado 

    update_flags(vm, result); //Actualiza el registro CC. 
}

//LO DE LA IP ESTÁ BIEN ¿?
void instr_STOP(VM *vm) {
    vm->registers[REG_IP] = 0xFFFFFFFF;  // IP inválida para indicar fin de ejecución
    vm->running = false;
}