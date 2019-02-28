/* Simulate EM traces */
/* Based on code example by Nguyen Anh Quynh */

#include <unicorn/unicorn.h>
#include <string.h>
#include <assert.h>
#include "simulate.h"

#define ARM_CODE "\x37\x00\xa0\xe3\x03\x10\x42\xe0" // mov r0, #0x37; sub r1, r2, r3
#define THUMB_CODE "\x83\xb0" // sub    sp, #0xc
#define PAGE_SIZE 4096
#define NUM_HAMMING_REGISTERS 174
#define NUM_REGISTERS UC_X86_REG_ENDING-1

uint64_t unicorn_execute(uc_engine* uc, uint8_t* memory, uint64_t memory_size, uint64_t* registers, uint64_t registers_size, uint64_t entrypoint, uint64_t stop_addr, uint64_t max_instructions);
uint64_t run_emulation(uint8_t* memory, uint64_t memory_size, uint64_t* registers, uint64_t registers_size, uint64_t entrypoint, uint64_t stop_addr, uint64_t max_instructions);

/*
int hamming_registers[] = { // ARM
    UC_ARM_REG_SB,
    UC_ARM_REG_SL,
    UC_ARM_REG_FP,
    UC_ARM_REG_IP,
    UC_ARM_REG_SP,
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_R4,
    UC_ARM_REG_R5,
    UC_ARM_REG_R6,
    UC_ARM_REG_R7,
    UC_ARM_REG_R8,
    UC_ARM_REG_R9,
    UC_ARM_REG_R10,
    UC_ARM_REG_R11,
    UC_ARM_REG_R12,
    UC_ARM_REG_R13,
    UC_ARM_REG_R14,
    UC_ARM_REG_R15,
    UC_ARM_REG_CPSR
};
*/
int hamming_registers[] = { // X86
	UC_X86_REG_FPSW,
	UC_X86_REG_FS,
	UC_X86_REG_GS,
	UC_X86_REG_RAX,
	UC_X86_REG_RBP,
	UC_X86_REG_RBX,
	UC_X86_REG_RCX,
	UC_X86_REG_RDI,
	UC_X86_REG_RDX,
	UC_X86_REG_RIZ,
	UC_X86_REG_RSI,
	UC_X86_REG_RSP,
	UC_X86_REG_RIP,
	UC_X86_REG_SS,
	UC_X86_REG_CR0,
	UC_X86_REG_CR1,
	UC_X86_REG_CR2,
	UC_X86_REG_CR3,
	UC_X86_REG_CR4,
	UC_X86_REG_CR5,
	UC_X86_REG_CR6,
	UC_X86_REG_CR7,
	UC_X86_REG_CR8,
	UC_X86_REG_CR9,
	UC_X86_REG_CR10,
	UC_X86_REG_CR11,
	UC_X86_REG_CR12,
	UC_X86_REG_CR13,
	UC_X86_REG_CR14,
	UC_X86_REG_CR15,
	UC_X86_REG_FP0,
	UC_X86_REG_FP1,
	UC_X86_REG_FP2,
	UC_X86_REG_FP3,
	UC_X86_REG_FP4,
	UC_X86_REG_FP5,
	UC_X86_REG_FP6,
	UC_X86_REG_FP7,
	UC_X86_REG_K0,
	UC_X86_REG_K1,
	UC_X86_REG_K2,
	UC_X86_REG_K3,
	UC_X86_REG_K4,
	UC_X86_REG_K5,
	UC_X86_REG_K6,
	UC_X86_REG_K7,
	UC_X86_REG_MM0,
	UC_X86_REG_MM1,
	UC_X86_REG_MM2,
	UC_X86_REG_MM3,
	UC_X86_REG_MM4,
	UC_X86_REG_MM5,
	UC_X86_REG_MM6,
	UC_X86_REG_MM7,
	UC_X86_REG_R8,
	UC_X86_REG_R9,
	UC_X86_REG_R10,
	UC_X86_REG_R11,
	UC_X86_REG_R12,
	UC_X86_REG_R13,
	UC_X86_REG_R14,
	UC_X86_REG_R15,
	UC_X86_REG_ST0,
	UC_X86_REG_ST1,
	UC_X86_REG_ST2,
	UC_X86_REG_ST3,
	UC_X86_REG_ST4,
	UC_X86_REG_ST5,
	UC_X86_REG_ST6,
	UC_X86_REG_ST7,
	UC_X86_REG_XMM0,
	UC_X86_REG_XMM1,
	UC_X86_REG_XMM2,
	UC_X86_REG_XMM3,
	UC_X86_REG_XMM4,
	UC_X86_REG_XMM5,
	UC_X86_REG_XMM6,
	UC_X86_REG_XMM7,
	UC_X86_REG_XMM8,
	UC_X86_REG_XMM9,
	UC_X86_REG_XMM10,
	UC_X86_REG_XMM11,
	UC_X86_REG_XMM12,
	UC_X86_REG_XMM13,
	UC_X86_REG_XMM14,
	UC_X86_REG_XMM15,
	UC_X86_REG_XMM16,
	UC_X86_REG_XMM17,
	UC_X86_REG_XMM18,
	UC_X86_REG_XMM19,
	UC_X86_REG_XMM20,
	UC_X86_REG_XMM21,
	UC_X86_REG_XMM22,
	UC_X86_REG_XMM23,
	UC_X86_REG_XMM24,
	UC_X86_REG_XMM25,
	UC_X86_REG_XMM26,
	UC_X86_REG_XMM27,
	UC_X86_REG_XMM28,
	UC_X86_REG_XMM29,
	UC_X86_REG_XMM30,
	UC_X86_REG_XMM31,
	UC_X86_REG_YMM0,
	UC_X86_REG_YMM1,
	UC_X86_REG_YMM2,
	UC_X86_REG_YMM3,
	UC_X86_REG_YMM4,
	UC_X86_REG_YMM5,
	UC_X86_REG_YMM6,
	UC_X86_REG_YMM7,
	UC_X86_REG_YMM8,
	UC_X86_REG_YMM9,
	UC_X86_REG_YMM10,
	UC_X86_REG_YMM11,
	UC_X86_REG_YMM12,
	UC_X86_REG_YMM13,
	UC_X86_REG_YMM14,
	UC_X86_REG_YMM15,
	UC_X86_REG_YMM16,
	UC_X86_REG_YMM17,
	UC_X86_REG_YMM18,
	UC_X86_REG_YMM19,
	UC_X86_REG_YMM20,
	UC_X86_REG_YMM21,
	UC_X86_REG_YMM22,
	UC_X86_REG_YMM23,
	UC_X86_REG_YMM24,
	UC_X86_REG_YMM25,
	UC_X86_REG_YMM26,
	UC_X86_REG_YMM27,
	UC_X86_REG_YMM28,
	UC_X86_REG_YMM29,
	UC_X86_REG_YMM30,
	UC_X86_REG_YMM31,
	UC_X86_REG_ZMM0,
	UC_X86_REG_ZMM1,
	UC_X86_REG_ZMM2,
	UC_X86_REG_ZMM3,
	UC_X86_REG_ZMM4,
	UC_X86_REG_ZMM5,
	UC_X86_REG_ZMM6,
	UC_X86_REG_ZMM7,
	UC_X86_REG_ZMM8,
	UC_X86_REG_ZMM9,
	UC_X86_REG_ZMM10,
	UC_X86_REG_ZMM11,
	UC_X86_REG_ZMM12,
	UC_X86_REG_ZMM13,
	UC_X86_REG_ZMM14,
	UC_X86_REG_ZMM15,
	UC_X86_REG_ZMM16,
	UC_X86_REG_ZMM17,
	UC_X86_REG_ZMM18,
	UC_X86_REG_ZMM19,
	UC_X86_REG_ZMM20,
	UC_X86_REG_ZMM21,
	UC_X86_REG_ZMM22,
	UC_X86_REG_ZMM23,
	UC_X86_REG_ZMM24,
	UC_X86_REG_ZMM25,
	UC_X86_REG_ZMM26,
	UC_X86_REG_ZMM27,
	UC_X86_REG_ZMM28,
	UC_X86_REG_ZMM29,
	UC_X86_REG_ZMM30,
	UC_X86_REG_ZMM31,
	UC_X86_REG_IDTR,
	UC_X86_REG_GDTR,
	UC_X86_REG_LDTR,
	UC_X86_REG_TR,
	UC_X86_REG_FPCW,
	UC_X86_REG_FPTAG,
	UC_X86_REG_MSR,
	UC_X86_REG_ENDING,
};

uint64_t old_vals[NUM_HAMMING_REGISTERS];
uint64_t vals[NUM_HAMMING_REGISTERS];
void *ptrs[NUM_HAMMING_REGISTERS];
uint64_t zero = 0;
int instrcnt = 0;

static void hook_code_debug(uc_engine *uc, uint64_t address, uint32_t size, void *memory) {
    uc_reg_read_batch(uc, hamming_registers, ptrs, NUM_HAMMING_REGISTERS);

    for(uint32_t i = 0; i < NUM_HAMMING_REGISTERS; i++) {
        printf("\t0x%016lx\n", vals[i]);
    }

    printf("0x%"PRIx64 ": ", address);
    for(uint32_t i = 0; i < size; i++) {
        printf("%02x", *((uint8_t *)memory + address + i));
    }
    printf("\n");

    /*
    if(address == 0x00418ce0 || address == 0x0040129e) { // free
        printf("HIT free!\n");

        // Write return value 0 (success)
        uc_reg_write(uc, UC_X86_REG_RAX, &zero);

        // Get next RIP from stack
        uint64_t current_stack_pointer;
        uint64_t next_rip;
        uc_reg_read(uc, UC_X86_REG_RSP, &current_stack_pointer);
        uc_mem_read(uc, current_stack_pointer, &next_rip, sizeof(uint64_t));
        uc_reg_write(uc, UC_X86_REG_RIP, &next_rip);

        // Pop stack
        current_stack_pointer += sizeof(uint64_t);
        uc_reg_write(uc, UC_X86_REG_RSP, &current_stack_pointer);
    }
    */

    instrcnt += 1;
}

static uint16_t hamming_distance_64(uint64_t v1, uint64_t v2) {
    uint64_t xor = v1 ^ v2;
    uint64_t mask = 0x1;

    uint16_t hd = 0;
    for(uint64_t i = 0; i < sizeof(uint64_t)*8; i++) {
        if(xor & (mask << i))
            hd++;
    }

    return hd;
}

/**
 * Find Hamming distance between old set of registers and new set. Updates old set.
 */
static uint16_t hamming_distance_registers(uint64_t* old_regs, uint64_t* new_regs) {
    uint16_t sum = 0;

    for(int i = 0; i < NUM_HAMMING_REGISTERS; i++) {
        sum += hamming_distance_64(old_regs[i], new_regs[i]);
        old_regs[i] = new_regs[i];
    }

    return sum;
}

static void hook_code(uc_engine* uc, uint64_t address, uint32_t size, uint16_t* results) {
    uc_reg_read_batch(uc, hamming_registers, ptrs, NUM_HAMMING_REGISTERS);

    uint16_t hw_dist_sum = hamming_distance_registers(old_vals, vals);
    //printf("HW: %hu\n", hw_dist_sum);
    results[instrcnt] = hw_dist_sum;

    instrcnt += 1;
}

bool hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user_data) {
    switch (type) {
    default:
        printf("hook_mem_invalid: UC_HOOK_MEM_INVALID type: %d at 0x%" PRIx64 "\n", type, addr);
        break;
    case UC_MEM_READ_UNMAPPED:
        printf("hook_mem_invalid: Read from invalid memory at 0x%" PRIx64 ", data size = %u\n", addr, size);
        break;
    case UC_MEM_WRITE_UNMAPPED:
        printf("hook_mem_invalid: Write to invalid memory at 0x%" PRIx64 ", data size = %u, data value = 0x%" PRIx64 "\n", addr, size, value);
        break;
    case UC_MEM_FETCH_PROT:
        printf("hook_mem_invalid: Fetch from non-executable memory at 0x%" PRIx64 "\n", addr);
        break;
    case UC_MEM_WRITE_PROT:
        printf("hook_mem_invalid: Write to non-writeable memory at 0x%" PRIx64 ", data size = %u, data value = 0x%" PRIx64 "\n", addr, size, value);
        break;
    case UC_MEM_READ_PROT:
        printf("hook_mem_invalid: Read from non-readable memory at 0x%" PRIx64 ", data size = %u\n", addr, size);
        break;
    }
    return false;
}

uint64_t round_down(uint64_t number) {
    return number & (~(PAGE_SIZE - 1));
}

uint64_t round_up(uint64_t number) {
    return round_down(number + PAGE_SIZE);
}


uint64_t run_trace_register_hws(uint16_t* results, uint8_t* memory, uint64_t memory_size, uint64_t entrypoint, uint64_t sp, uint64_t stop_addr) {
    printf("Memory size: %lu\n", memory_size);
    printf("Entrypoint : %lu\n", entrypoint);
    printf("Stop addr  : %lu\n", stop_addr);
    printf("SP         : %lu\n", sp);
    printf("Page size  : %d\n", PAGE_SIZE);

    assert(hamming_distance_64(0x0, 0x8000000000000000) == 2);
    assert(hamming_distance_64(0x1, 0x0) == 1);
    assert(hamming_distance_64(0xffffffffffffffff, 0x0) == 64);
    assert((sizeof(hamming_registers) / sizeof(int)) == NUM_HAMMING_REGISTERS);

    uc_engine *uc;
    uc_err err;
    uc_hook instruction_hook;

    // Initialize emulator in ARM mode
    //err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err, uc_strerror(err));
        return 0;
    }

	// Assign register pointers
	for (int i = 0; i < NUM_HAMMING_REGISTERS; i++) {
        ptrs[i] = &vals[i];
        old_vals[i] = 0;
    }

	// Setup hooks
	uc_hook_add(uc, &instruction_hook, UC_HOOK_CODE, hook_code, results, 0, memory_size);
	uc_hook_add(uc, &instruction_hook, UC_HOOK_MEM_INVALID, hook_mem_invalid, NULL, 0, 0);

    // Setup registers
    uint64_t registers[NUM_REGISTERS];
    for(uint64_t i = 0; i < NUM_REGISTERS; i++)
        registers[i] = 0;
    registers[UC_X86_REG_RSP] = sp;
    // TODO use registers[] array for this
	//int rflags = 0x00000200; // X86
    //uc_reg_write(uc, UC_X86_REG_EFLAGS, &rflags); // X86
    //uc_reg_write(uc, UC_ARM_REG_SP, &sp); // ARM
    //int apsr = 0xFFFFFFFF;
	//uc_reg_write(uc, UC_ARM_REG_APSR, &apsr);

    uint64_t num_instructions = unicorn_execute(uc, memory, memory_size, registers, NUM_REGISTERS, entrypoint, stop_addr, 0);

    printf("Emulation completed\n");
    printf("Instructions: %ld\n", num_instructions);

    uc_close(uc);

    return num_instructions;
}

/**
 * Just emulate a binary until max_instructions, without hooks.
 */
uint64_t run_emulation(uint8_t* memory, uint64_t memory_size, uint64_t* registers, uint64_t registers_size, uint64_t entrypoint, uint64_t stop_addr, uint64_t max_instructions) {
    uc_engine *uc;
    uc_err err;

    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err, uc_strerror(err));
        return 0;
    }

    uint64_t num_instructions = unicorn_execute(uc, memory, memory_size, registers, registers_size, entrypoint, stop_addr, max_instructions);

    uc_close(uc);

    return num_instructions;
}

uint64_t unicorn_execute(uc_engine* uc, uint8_t* memory, uint64_t memory_size, uint64_t* registers, uint64_t registers_size, uint64_t entrypoint, uint64_t stop_addr, uint64_t max_instructions) {
    uc_err err;
	uint64_t aligned_memory_size = round_up(memory_size);

    // Setup memory
    uc_mem_map(uc, 0, aligned_memory_size, UC_PROT_ALL);
    uc_mem_write(uc, 0, memory, memory_size); // Copy memory to internal Unicorn memory

    // Setup registers
    for(uint64_t i = 0; i < registers_size; i++) {
        uc_reg_write(uc, i, &registers[i]);
    }

    // Run!
    instrcnt = 0;
    err = uc_emu_start(uc, entrypoint, stop_addr, 0, max_instructions);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u (%s)\n", err, uc_strerror(err));
        return 0;
    }

    // Copy internal Unicorn memory to memory
    uc_mem_read(uc, 0, memory, memory_size);

    // Copy internal Unicorn registers to registers
    for(uint64_t i = 0; i < registers_size; i++) {
        uc_reg_read(uc, i, &registers[i]);
    }


    return instrcnt;
}


int main(int argc, char **argv, char **envp) {
    return 0;
}