#include <unistd.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <libkern/OSCacheControl.h>
#include "mach/mach_exc.h"
#include <mach-o/loader.h>
#include <mach-o/arch.h>
#include <assert.h>
#include <pthread.h>
#include <mach/mach_time.h>
#include "reductant.h"
#include "arm64.h"

#if ENABLE_DOBBY_HOOK
#include "dobby.h"
#endif

mach_msg_return_t
mach_msg_server(
	boolean_t (*demux)(mach_msg_header_t *, mach_msg_header_t *),
	mach_msg_size_t max_size,
	mach_port_t rcv_name,
	mach_msg_options_t options);

#ifndef IN_PROCESS 
#define IN_PROCESS 0
#endif

boolean_t mach_exc_server(
		mach_msg_header_t *InHeadP,
		mach_msg_header_t *OutHeadP);

static vm_size_t _page_size = 0;

static const char *
mach_exc_string(exception_type_t exc) {
    switch (exc) {
        case EXC_BAD_ACCESS:
            return "EXC_BAD_ACCESS";
        case EXC_BAD_INSTRUCTION:
            return "EXC_BAD_INSTRUCTION";
        case EXC_ARITHMETIC:
            return "EXC_ARITHMETIC";
        case EXC_EMULATION:
            return "EXC_EMULATION";
        case EXC_SOFTWARE:
            return "EXC_SOFTWARE";
        case EXC_BREAKPOINT:
            return "EXC_BREAKPOINT";
        case EXC_SYSCALL:
            return "EXC_SYSCALL";
        case EXC_MACH_SYSCALL:
            return "EXC_MACH_SYSCALL";
        case EXC_RPC_ALERT:
            return "EXC_RPC_ALERT";
        default:
            return "EXC_UNKNOWN";
    }
}

const uint16_t catch_mach_exception_raise;
const uint16_t catch_mach_exception_raise_state;

static inline bool 
_patch_current_code_as(task_t task, arm_thread_state64_t *state, uint32_t code) {
    vm_address_t addr = 0;
    mach_vm_address_t inst_page = state->__pc & ~(_page_size - 1);
    const vm_address_t inst_offset = state->__pc & (_page_size - 1);
    mach_vm_size_t sz;

    kern_return_t rc = vm_allocate(mach_task_self(), &addr, _page_size, VM_FLAGS_ANYWHERE);
    bool ret = false;
    if (rc != KERN_SUCCESS) {
        fprintf(stderr, "vm_allocate: %s\n", mach_error_string(rc));
        goto failed;
    }
    rc = mach_vm_read_overwrite(task, inst_page, _page_size, addr, &sz);
    if (rc != KERN_SUCCESS || sz != _page_size) {
        fprintf(stderr, "mach_vm_read_overwrite: %s\n", mach_error_string(rc));
        goto failed;
    }

    *(uint32_t*)(addr + inst_offset) = code;

    rc = vm_protect(mach_task_self(), addr, _page_size, 0, VM_PROT_READ | VM_PROT_EXECUTE);
    if (rc != KERN_SUCCESS) {
        fprintf(stderr, "vm_protect: %s\n", mach_error_string(rc));
        goto failed;
    }
    vm_prot_t cur, max;
    rc = mach_vm_remap(task, &inst_page, _page_size, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, mach_task_self(), addr, false, &cur, &max, VM_INHERIT_SHARE);
    if (rc != KERN_SUCCESS) {
        fprintf(stderr, "mach_vm_remap: %s\n", mach_error_string(rc));
        goto failed;
    }
    ret = true;
failed:
    if (addr != 0) {
        vm_deallocate(mach_task_self(), addr, _page_size);
    }
    return ret;
}

#define _SLE_simulate_order(A, R, data, atomic_func, ptr, value) \
    if (A) { \
        if (R) { \
            data = atomic_func(ptr, value, __ATOMIC_ACQ_REL); \
        } else { \
            data = atomic_func(ptr, value, __ATOMIC_ACQUIRE); \
        } \
    } else { \
        if (R) { \
            data = atomic_func(ptr, value, __ATOMIC_RELEASE); \
        } else { \
            data = atomic_func(ptr, value, __ATOMIC_RELAXED); \
        } \
    }
#if IN_PROCESS
#define _SLE_simulate_remap(result, target) (result) = (target)
#define _SLE_simulate_unmap(addr, size)
#else
#define _SLE_simulate_remap(result, target) { \
    vm_prot_t cur, max; \
    kern_return_t rc = vm_remap(mach_task_self(), &tmp_buf, _page_size, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_OVERWRITE, task, target_page, false, &cur, &max, VM_INHERIT_SHARE); \
    if (rc != KERN_SUCCESS) { \
        fprintf(stderr, "vm_remap: %s\n", mach_error_string(rc)); \
        goto failed; \
    } \
}
#define _SLE_simulate_unmap(addr, size) vm_deallocate(mach_task_self(), addr, size)
#endif

#define SLE_simulate(task, state, instr, atomic_func) ({ \
    uint32_t size = (instr >> 30) & 0b11; \
    uint32_t Rs = (instr >> 16) & ARMv8_REG_MASK; \
    uint32_t Rn = (instr >> 5) & ARMv8_REG_MASK; \
    uint32_t Rt = instr & ARMv8_REG_MASK; \
    uint32_t A = (instr >> 23) & 0b1; \
    uint32_t R = (instr >> 22) & 0b1; \
    \
    vm_address_t target_page = state->__x[Rn] & ~(_page_size - 1); \
    vm_address_t target_offset = state->__x[Rn] & (_page_size - 1); \
    vm_address_t tmp_buf = 0; \
    _SLE_simulate_remap(tmp_buf, target_page); \
    switch (size) { \
        case 0b00: { \
            uint8_t value = (Rs != 31) ? state->__x[Rs] : 0; \
            uint8_t *ptr = (uint8_t *)(tmp_buf + target_offset); \
            uint8_t data; \
            _SLE_simulate_order(A, R, data, atomic_func, ptr, value); \
            if (Rt != 31) { \
                state->__x[Rt] = data; \
            } \
            break; \
        } \
        case 0b01: { \
            uint16_t value = (Rs != 31) ? state->__x[Rs] : 0; \
            uint16_t *ptr = (uint16_t *)(tmp_buf + target_offset); \
            uint16_t data; \
            _SLE_simulate_order(A, R, data, atomic_func, ptr, value); \
            if (Rt != 31) { \
                state->__x[Rt] = data; \
            } \
            break; \
        } \
        case 0b10: { \
            uint32_t value = (Rs != 31) ? state->__x[Rs] : 0; \
            uint32_t *ptr = (uint32_t *)(tmp_buf + target_offset); \
            uint32_t data; \
            _SLE_simulate_order(A, R, data, atomic_func, ptr, value); \
            if (Rt != 31) { \
                state->__x[Rt] = data; \
            } \
            break; \
        } \
        case 0b11: { \
            uint64_t value = (Rs != 31) ? state->__x[Rs] : 0; \
            uint64_t *ptr = (uint64_t *)(tmp_buf + target_offset); \
            uint64_t data; \
            _SLE_simulate_order(A, R, data, atomic_func, ptr, value); \
            if (Rt != 31) { \
                state->__x[Rt] = data; \
            } \
            break; \
        } \
    } \
    _SLE_simulate_unmap(tmp_buf, _page_size); \
})

#if ENABLE_DOBBY_HOOK

#define IMPLEMENT_HOOK_CAS_FAMILY(func, int_type_t) \
static uintptr_t \
func(RegisterContext *reg_ctx, const HookEntryInfo *info) { \
    uint32_t instr = *(uint32_t*)info->relocated_origin_instructions; \
    uint32_t Rs = (instr >> 16) & ARMv8_REG_MASK; \
    uint32_t Rn = (instr >> 5) & ARMv8_REG_MASK; \
    uint32_t Rt = instr & ARMv8_REG_MASK; \
    uint64_t result; \
    int_type_t *ptr =  (Rn != 31) ? (int_type_t *)(reg_ctx->general.x[Rn]) : (int_type_t *)(reg_ctx->sp); \
    int_type_t expected = (Rs != 31) ? reg_ctx->general.x[Rs] : 0; \
    int_type_t desired = (Rt != 31) ? reg_ctx->general.x[Rt] : 0; \
    __atomic_compare_exchange_n(ptr, &expected, desired, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); \
    result = expected; \
    if (Rs != 31) { \
        reg_ctx->general.x[Rs] = result; \
    } \
    return 4; \
}

IMPLEMENT_HOOK_CAS_FAMILY(_hook_cas_family64, uint64_t)
IMPLEMENT_HOOK_CAS_FAMILY(_hook_cas_family32, uint32_t)
IMPLEMENT_HOOK_CAS_FAMILY(_hook_cas_family16, uint16_t)
IMPLEMENT_HOOK_CAS_FAMILY(_hook_cas_family8, uint8_t)
#undef IMPLEMENT_HOOK_CAS_FAMILY

static thread_t translator_thread; 

static int _DobbyInstructionHookCASCMP(void *address, int inst_size) {
    static const DBICallTy _hooker_by_inst_size[] = {
        _hook_cas_family8,
        _hook_cas_family16,
        _hook_cas_family32,
        _hook_cas_family64,
    };
    DBICallTy func = _hooker_by_inst_size[inst_size];
    
    return DobbyInstructionHookCASCMP(address, func);
}

static bool disable_dobby_hook = false;

#endif

kern_return_t catch_mach_exception_raise_state_identity(mach_port_t exception_port, mach_port_t thread, mach_port_t task, exception_type_t exception, exception_data_t code, mach_msg_type_number_t code_count, int *flavor, thread_state_t in_state, mach_msg_type_number_t in_state_count, thread_state_t out_state, mach_msg_type_number_t *out_state_count) {
    arm_thread_state64_t * const state = (arm_thread_state64_t *)out_state;
#define patch_current_code_as(code) if (!_patch_current_code_as(task, state, (code))) {goto failed;}
    memcpy(state, in_state, sizeof(*state));
    *out_state_count = in_state_count;
    uint32_t instr = (uint32_t)*((uint64_t*)code + 1);
#if !IN_PROCESS
    mach_vm_size_t sz;

    kern_return_t rc;
#else 
    if (instr != *(uint32_t*)(state->__pc)) {
        // instruction has been patched.
        goto end;
    }
#endif
    if (ARMv8_is_BLR(instr) || ARMv8_is_BR(instr) || ARMv8_is_LDAR(instr) || ARMv8_is_LDRi64_preindex(instr) || ARMv8_is_LDRiu64(instr) || ARMv8_is_LDUR64(instr) || ARMv8_is_NOP(instr) || ARMv8_is_RET(instr)) {
        // instruction has been patched.
        goto end;
    }

    if (exception != EXC_BAD_INSTRUCTION) {
        goto failed;
    }

    if (ARMv8_is_CAS_family(instr)) { //casa, casa, casal, casl casb casab no offset
        uint32_t size = (instr >> 30) & 0b11;
        uint32_t Rs = (instr >> 16) & ARMv8_REG_MASK;
        uint32_t Rn = (instr >> 5) & ARMv8_REG_MASK;
        uint32_t Rt = instr & ARMv8_REG_MASK;
        vm_address_t target_page = state->__x[Rn] & ~(_page_size - 1);
        vm_address_t target_offset = state->__x[Rn] & (_page_size - 1);
        vm_address_t tmp_buf = 0;
        _SLE_simulate_remap(tmp_buf, target_page);
        
#if ENABLE_DOBBY_HOOK
        uint32_t next_inst = *(uint32_t*)(state->__pc + 4);
        
        bool is_cmp = ARMv8_is_CMP_er(next_inst) || ARMv8_is_CMP_i(next_inst) || ARMv8_is_CMP_sr(next_inst);
        if (*(uint32_t*)(state->__pc - 4) == 0x14000002) {
            is_cmp = false;
        }
        if (is_cmp) {
            is_cmp = (Rs == ((next_inst >> 5) & ARMv8_REG_MASK));
        }
        
        if (thread == translator_thread || !is_cmp || disable_dobby_hook || RS_FAILED == _DobbyInstructionHookCASCMP((void*)state->__pc, size)) 
#endif
        {
            uint64_t result;
            switch (size) {
                case 0b00: {
                    uint8_t *ptr = (uint8_t *)(tmp_buf + target_offset);
                    uint8_t expected = (Rs != 31) ? state->__x[Rs] : 0;
                    uint8_t desired = (Rt != 31) ? state->__x[Rt] : 0;
                    result = __sync_val_compare_and_swap(ptr, expected, desired);
                    break;
                }
                case 0b01: {
                    uint16_t *ptr = (uint16_t *)(tmp_buf + target_offset);
                    uint16_t expected = (Rs != 31) ? state->__x[Rs] : 0;
                    uint16_t desired = (Rt != 31) ? state->__x[Rt] : 0;
                    result = __sync_val_compare_and_swap(ptr, expected, desired);
                    break;
                }
                case 0b10: {
                    uint32_t *ptr = (uint32_t *)(tmp_buf + target_offset);
                    uint32_t expected = (Rs != 31) ? state->__x[Rs] : 0;
                    uint32_t desired = (Rt != 31) ? (uint32_t)state->__x[Rt] : 0;
                    result = __sync_val_compare_and_swap(ptr, expected, desired);
                    break;
                }
                case 0b11: {
                    uint64_t *ptr = (uint64_t *)(tmp_buf + target_offset);
                    uint64_t expected = (Rs != 31) ? state->__x[Rs] : 0;
                    uint64_t desired = (Rt != 31) ? state->__x[Rt] : 0;
                    result = __sync_val_compare_and_swap(ptr, expected, desired);
                    break;
                }
            }
            if (Rs != 31) {
                state->__x[Rs] = result;
            }
            _SLE_simulate_unmap(tmp_buf, _page_size);
            goto next_pc;
        }
    } else if (ARMv8_is_CASP_family(instr)) { //casp, caspa, caspal, caspl: LSE
        uint32_t size = (instr >> 30) & 0b1;
        uint32_t Rs = (instr >> 16) & ARMv8_REG_MASK;
        uint32_t Rn = (instr >> 5) & ARMv8_REG_MASK;
        uint32_t Rt = instr & ARMv8_REG_MASK;
        vm_address_t target_page = state->__x[Rn] & ~(_page_size - 1);
        vm_address_t target_offset = state->__x[Rn] & (_page_size - 1);
        vm_address_t tmp_buf = 0;
        _SLE_simulate_remap(tmp_buf, target_page);
        if (size) {
            //64bit
            __uint128_t *ptr = (__uint128_t *)(tmp_buf + target_offset);
            __uint128_t expected = ((__uint128_t)state->__x[Rs + 1] << 64) | (__uint128_t)state->__x[Rs];
            __uint128_t desired = ((__uint128_t)state->__x[Rt + 1] << 64) | (__uint128_t)state->__x[Rt];
            __uint128_t ret = __sync_val_compare_and_swap(ptr, expected, desired);
            state->__x[Rs] = ret;
            state->__x[Rs + 1] = ret >> 64;
        } else {
            //32bit
            uint64_t *ptr = (uint64_t *)(tmp_buf + target_offset);
            uint64_t expected = ((uint64_t)(uint32_t)state->__x[Rs + 1] << 32) | (uint64_t)(uint32_t)state->__x[Rs];
            uint64_t desired = ((uint64_t)(uint32_t)state->__x[Rt + 1] << 32) | (uint64_t)(uint32_t)state->__x[Rt];
            uint64_t ret = __sync_val_compare_and_swap(ptr, expected, desired);
            state->__x[Rs] = (uint32_t)ret;
            state->__x[Rs + 1] = (uint32_t)(ret >> 32);
        }
        _SLE_simulate_unmap(tmp_buf, _page_size);
        goto next_pc;
    } else if (ARMv8_is_SWP_family(instr)) { // swp, swpa, swpal, swpl，swpb, swpab, swpalb swplb LSE
        SLE_simulate(task, state, instr, __atomic_exchange_n);
        goto next_pc;
    } else if (ARMv8_is_ldadd_family(instr)) { //ldadd, ldadda, ldaddal, ldaddl LSE
        SLE_simulate(task, state, instr, __atomic_fetch_add);
        goto next_pc;
    } else if (ARMv8_is_LDSET_family(instr)) { //ldsetb, ldsetab, ldsetalb, ldsetlb ldseth, ldsetah, ldsetalh, ldsetlh ldset ldseta ldsetal ldsetl  //LSE
        SLE_simulate(task, state, instr, __atomic_fetch_or);
        goto next_pc;
    } else if (ARMv8_is_LDCLR_family(instr)) { //ldclrb, ldclrab, ldclralb, ldclrlb ldclrh, ldclrah, ldclralh, ldclrlh ldclr ldclra ldclral ldclrl  //LSE
#define __SLE_atomic_fetch_clr(ptr, value, order) __atomic_fetch_and(ptr, ~value, order)
        SLE_simulate(task, state, instr, __SLE_atomic_fetch_clr);
#undef __SLE_atomic_fetch_clr
        goto next_pc;
    } else if (ARMv8_is_LDEOR_family(instr)) { //ldeor ldeora ldeoral ldeorl ldeor*b ldeor*h LSE
        SLE_simulate(task, state, instr, __atomic_fetch_xor);
        goto next_pc;
    } else if ((instr & ~ARMv8_REG_MASK) == 0xd53be040) { //mrs xt, CNTVCT_EL0
        // pre-iOS 13 do not support this privileged instruction. Simulate it with mach time.
        uint32_t Rt = instr & ARMv8_REG_MASK;
        if (Rt != 31) {
            if (__builtin_available(iOS 10, *)) {
#if IN_PROCESS
                uint64_t mach_continuous_time_iOS13(void);
                state->__x[Rt] = mach_continuous_time_iOS13();
#else
                state->__x[Rt] = mach_continuous_time();
#endif
            } else {
                state->__x[Rt] = mach_absolute_time();
            }
        }
        goto next_pc;
    } else if (instr == 0xd65f0bff || //retaa
        instr == 0xd65f0fff) { //retab
        patch_current_code_as(ARMv8_RET());
    } else if ((instr & 0xfffffc00) == 0xdac10800 || //pacda
               (instr & 0xfffffc00) == 0xdac10000 || //pacia
               (instr & 0xfffffc00) == 0xdac10400 || //pacib
               (instr & 0xfffffc00) == 0xdac10c00 || //pacdb
               (instr & 0xfffffc00) == 0xdac11000 || //autia
               (instr & 0xfffffc00) == 0xdac11400 || //autib
               (instr & 0xfffffc00) == 0xdac11800 || //autda
               (instr & 0xfffffc00) == 0xdac11c00 || //autdb
               (instr & 0xfffffc00) == 0xdac11000 || //autia
               (instr & 0xffffffe0) == 0xdac123e0 || //paciza
               (instr & 0xffffffe0) == 0xdac127e0 || //pacizb
               (instr & 0xffffffe0) == 0xdac12be0 || //pacdza
               (instr & 0xffffffe0) == 0xdac12fe0 || //pacdzb
               (instr & 0xffffffe0) == 0xdac133e0 || //autiza
               (instr & 0xffffffe0) == 0xdac137e0 || //autizb
               (instr & 0xffffffe0) == 0xdac13be0 || //autdza
               (instr & 0xffffffe0) == 0xdac13fe0 || //autdzb
               (instr & 0xffffffe0) == 0xdac143e0 || //xpaci
               (instr & 0xffffffe0) == 0xdac147e0 || //xpacd
               instr == 0xd503233f || //paciasp
               instr == 0xd503237f || //pacibsp
               instr == 0xd50323bf || //autiasp
               instr == 0xd50323ff //autibsp
            ) {
        patch_current_code_as(ARMv8_NOP());
    } else if ((instr & 0xfffffc00) == 0xd73f0800 || //blraa
               (instr & 0xfffffc00) == 0xd73f0c00 || //blrab
               (instr & 0xfffffc1f) == 0xd63f081f || //blraaz
               (instr & 0xfffffc1f) == 0xd63f0c1f) { //blrabz
        patch_current_code_as(ARMv8_BLR((instr >> ARMv8_REG_BITS) & ARMv8_REG_MASK));
    } else if ((instr & 0xfffffc00) == 0xd71f0800 || //braa
               (instr & 0xfffffc00) == 0xd71f0c00 || //brab
               (instr & 0xfffffc1f) == 0xd61f081f || //braaz
               (instr & 0xfffffc1f) == 0xd61f0c1f) { //brabz
         patch_current_code_as(ARMv8_BR((instr >> ARMv8_REG_BITS) & ARMv8_REG_MASK));
    } else if ((instr & 0xffa00400) == 0xf8200400 || //ldraa
               (instr & 0xffa00400) == 0xf8a00400) { //ldrab
        uint32_t sign = (instr & (0b1 << 22)) >> 22;
        uint32_t imm = (instr & (0b111111111 << 12)) >> 12;
        uint32_t rs_rd = (instr & 0b1111111111);
        uint32_t rd = rs_rd & 0b11111;
        uint32_t rs = (rs_rd >> 5) & 0b11111;
        uint32_t is_pre = (instr & (0x800)) >> 11;
        if (is_pre) { //ldra* xd, [xc, #xxx]!
                imm <<= 3;
                uint32_t real_imm = (sign == 0) ? imm : ((0xffffffff << 12) | imm);
                if ((real_imm >> 8) == 0 || ((int32_t)real_imm >> 8) == 0xffffffff) {
                    real_imm = real_imm & 0b111111111;
                    patch_current_code_as(ARMv8_LDRi64_preindex(rs, rd, real_imm));
                } else {
                    uint32_t rd = rs_rd & 0b11111;
                    uint32_t rs = (rs_rd >> 5) & 0b11111;
                    state->__x[rs] += (int64_t)(int32_t)real_imm;
#if IN_PROCESS
                    state->__x[rd] = *(uint64_t *)state->__x[rs];
#else
                    rc = mach_vm_read_overwrite(task, state->__x[rs], sizeof(uint64_t), (vm_address_t)&state->__x[rd], &sz);
                    if (rc != KERN_SUCCESS || sz != sizeof(uint64_t)) {
                        fprintf(stderr, "mach_vm_read_overwrite: %s\n", mach_error_string(rc));
                        goto failed;
                    }
#endif
                    goto next_pc;
                }
        } else { //ldra* xd, [xc, #xxx]
            uint32_t rd = rs_rd & 0b11111;
            uint32_t rs = (rs_rd >> 5) & 0b11111;
            if (sign == 0) {
                uint32_t imm12 = ((instr & ~0xffa00400) >> 10) & BIT_MASK(12);
                patch_current_code_as(ARMv8_LDRiu64(rd, rs, imm12));
            } else {
                imm <<= 3;
                uint32_t real_imm = ((0xffffffff << 12) | imm);
                if (((int32_t)real_imm >> 8) == 0xffffffff) {
                    real_imm = real_imm & 0b111111111;
                    patch_current_code_as(ARMv8_LDUR64(rd, rs, real_imm));
                } else {
#if IN_PROCESS
                    state->__x[rd] = *(uint64_t *)(state->__x[rs] + (int64_t)(int32_t)real_imm);
#else
                    rc = mach_vm_read_overwrite(task, state->__x[rs] + (int64_t)(int32_t)real_imm, sizeof(uint64_t), (vm_address_t)&state->__x[rd], &sz);
                    if (rc != KERN_SUCCESS || sz != sizeof(uint64_t)) {
                        fprintf(stderr, "mach_vm_read_overwrite: %s\n", mach_error_string(rc));
                        goto failed;
                    }
#endif
                    goto next_pc;
                }
            }
            
        }
    //} else if ((instr & 0b00111111111111111111110000000000) == 0b00111000101111111100000000000000) { //ldapr ldaprb ldaprh
    } else if (ARMv8_is_LDAPR_family(instr)) { //ldapr ldaprb ldaprh
        uint32_t size = (instr >> 30) & 0b11;
        uint32_t Rn = (instr >> 5) & 0b11111;
        uint32_t Rt = instr & 0b11111;
        patch_current_code_as(ARMv8_LDAR(size, Rn, Rt));
    } else {
        goto failed;
    }

    
    goto end;
next_pc:
    //sys_icache_invalidate(hhh, 8);
    state->__pc += 4;
end:

    return KERN_SUCCESS;
failed:
    if (exception == EXC_BAD_INSTRUCTION) {
        printf("bad instruction: %x\n", instr);
    }
    printf( "%s: \n"
            "codes %llx\t"
            "%llx\n"
            "x0 %llx\t" "x1 %llx\n"
            "x2 %llx\t" "x3 %llx\n"
            "x4 %llx\t" "x5 %llx\n"
            "x6 %llx\t" "x7 %llx\n"
            "x8 %llx\t" "x9 %llx\n"
            "x10 %llx\t" "x11 %llx\n"
            "x12 %llx\t" "x13 %llx\n"
            "x14 %llx\t" "x15 %llx\n"
            "x16 %llx\t" "x17 %llx\n"
            "x18 %llx\t" "x19 %llx\n"
            "x20 %llx\t" "x21 %llx\n"
            "x22 %llx\t" "x23 %llx\n"
            "x24 %llx\t" "x25 %llx\n"
            "x26 %llx\t" "x27 %llx\n"
            "x28 %llx\t" "fp %llx\n"
            "lr %llx\t" "sp %llx\n"
            "pc %llx\n", 
            mach_exc_string(exception),
            *(uint64_t*)code,
            *((uint64_t*)code + 1),
            state->__x[0], state->__x[1],
            state->__x[2], state->__x[3],
            state->__x[4], state->__x[5],
            state->__x[6], state->__x[7],
            state->__x[8], state->__x[9],
            state->__x[10], state->__x[11],
            state->__x[12], state->__x[13],
            state->__x[14], state->__x[15],
            state->__x[16], state->__x[17],
            state->__x[18], state->__x[19],
            state->__x[20], state->__x[21],
            state->__x[22], state->__x[23],
            state->__x[24], state->__x[25],
            state->__x[26], state->__x[27],
            state->__x[28], state->__fp,
            state->__lr, state->__sp, 
            state->__pc);
    return KERN_FAILURE;
}

static mach_port_t 
_translator_prepare_exc_port(void) {
    kern_return_t err;
    mach_port_t server_port;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &server_port);
    if (err != KERN_SUCCESS) {
        fprintf(stderr, "translator: mach_port_allocate: %s\n", mach_error_string(err));
        return MACH_PORT_NULL;
    }
    err = mach_port_insert_right(mach_task_self(), server_port, server_port, MACH_MSG_TYPE_MAKE_SEND);
    if (err != KERN_SUCCESS) {
        fprintf(stderr, "translator: mach_port_insert_right: %s\n", mach_error_string(err));
        mach_port_deallocate(mach_task_self(), server_port);
        return MACH_PORT_NULL;
    }
    return server_port;
}

mach_port_t translator(task_t t) {
    task_t child = t;
    kern_return_t err;
    //host_page_size(mach_host_self(), &_page_size);
    _page_size = vm_page_size;
    
    mach_port_t server_port = _translator_prepare_exc_port();
    if (server_port == MACH_PORT_NULL) {
        fprintf(stderr, "translator: failed to prepare mach_port\n");
        return MACH_PORT_NULL;
    }

    err = task_set_exception_ports(child, EXC_MASK_BAD_INSTRUCTION, server_port, EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64);
    if (err != MACH_PORT_NULL) {
        fprintf(stderr, "translator: task_set_exception_ports %s\n", mach_error_string(err));
    }

    return server_port;
}

#if ENABLE_DOBBY_HOOK

static void *
translator_thread_internal(void *ctx) {
    static const char thread_name[] = "com.sxx.reductant-translator0";
    //pthread_setname_np(thread_name);
    #define PROC_INFO_CALL_SETCONTROL        0x5
    #define PROC_SELFSET_THREADNAME		2
    int __proc_info(int callnum, int pid, int flavor, uint64_t arg, void * buffer, int buffersize) ;
    __proc_info(PROC_INFO_CALL_SETCONTROL, getpid(), PROC_SELFSET_THREADNAME, (uint64_t)0, (void*)thread_name, sizeof(thread_name));
    thread_t translator_thread = *(thread_t *)ctx;
    mach_port_t server_port = _translator_prepare_exc_port();
    if (server_port == MACH_PORT_NULL) {
        fprintf(stderr, "translator_thread_internal: failed to prepare mach_port\n");
        return NULL;
    }
    kern_return_t err;
    err = thread_set_exception_ports(translator_thread, EXC_MASK_BAD_INSTRUCTION, server_port, EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64);
    if (err != KERN_SUCCESS) {
        fprintf(stderr, "translator_thread_internal: thread_set_exception_ports %s\n", mach_error_string(err));
        return NULL;
    }
    if ((err = mach_msg_server(mach_exc_server, 4096, server_port, 0)) != KERN_SUCCESS) {
        fprintf(stderr, "translator_thread_internal: mach_msg_server %d\n", err);
    }
    return NULL;
}

#endif

void 
translator_loop(mach_port_t port) {
    kern_return_t err;
    
    if ((err = mach_msg_server(mach_exc_server, 4096, port, 0)) != KERN_SUCCESS) {
        fprintf(stderr, "translator_loop: mach_msg_server %d\n", err);
    }
}

void *
translator_subthread(void *arg) {
    pthread_setname_np("com.sxx.reductant-translator");
#if ENABLE_DOBBY_HOOK
    if (getenv("RT_DISABLE_DOBBY_HOOK")) {
        disable_dobby_hook = true;
    } else {
        //host_page_size(mach_host_self(), &_page_size);
        _page_size = vm_page_size;
        dobby_enable_near_branch_hook();
        pthread_t pth;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        thread_t current_thread = mach_thread_self();
        translator_thread = current_thread;
        pthread_attr_setdetachstate(&attr, 1);
        pthread_create(&pth, &attr, translator_thread_internal, &current_thread);
    }
#endif
    mach_port_t port = translator(mach_task_self());
    if (port != MACH_PORT_NULL) {
        translator_loop(port);
    }
    return NULL;
}