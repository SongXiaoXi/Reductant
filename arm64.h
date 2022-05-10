#ifndef __ARM64_h__
#define __ARM64_h__

#define BIT_MASK(bit_num) ((1 << ((bit_num))) - 1)

#define ARMv8_REG_MASK BIT_MASK(ARMv8_REG_BITS)
#define ARMv8_REG_BITS 5
#define ARMv8_REG_LR 30

#define ARMv8_RET_mask 0xfffffc1f
#define ARMv8_RET_base 0xd65f0000

#define ARMv8_RET(...) _ARMv8_RET_IMPL(0, ##__VA_ARGS__, ARMv8_REG_LR)
#define _ARMv8_RET_IMPL(ph, reg, ...) (0xd65f0000 | ((reg) << ARMv8_REG_BITS))
#define ARMv8_is_RET(instr) (((instr) & ARMv8_RET_mask) == ARMv8_RET_base)

#define ARMv8_NOP_mask 0xffffffff
#define ARMv8_NOP_base 0xd503201f
#define ARMv8_NOP() (ARMv8_NOP_base)
#define ARMv8_is_NOP(instr) ((instr) == ARMv8_NOP())

#define ARMv8_BLR_mask 0xfffffc1f
#define ARMv8_BLR_base 0xd63f0000
#define ARMv8_BLR(xs) (0xd63f0000 | ((xs) << ARMv8_REG_BITS)) 
#define ARMv8_is_BLR(instr) (((instr) & ARMv8_BLR_mask) == ARMv8_BLR_base)

#define ARMv8_BR_mask 0xfffffc1f
#define ARMv8_BR_base 0xd61f0000
#define ARMv8_BR(xs) (0xd61f0000 | ((xs) << ARMv8_REG_BITS))
#define ARMv8_is_BR(instr) (((instr) & ARMv8_BR_mask) == ARMv8_BR_base)

#define ARMv8_LDRi64_preindex_mask 0xffe00c00
#define ARMv8_LDRi64_preindex_base 0xf8400c00
#define ARMv8_LDRi64_preindex(xs, xd, imm12) (ARMv8_LDRi64_preindex_base | (imm12 << 12) | (xs << ARMv8_REG_BITS) | (xd))
#define ARMv8_is_LDRi64_preindex(instr) (((instr) & ARMv8_LDRi64_preindex_mask) == ARMv8_LDRi64_preindex_base)

#define ARMv8_LDRiu64_mask 0xffc00000
#define ARMv8_LDRiu64_base 0xf9400000
#define ARMv8_LDRiu64(Xt, Xn_SP, imm12) (ARMv8_LDRiu64_base | ((imm12) << 10) | ((Xn_SP) << 5) | (Xt))
#define ARMv8_is_LDRiu64(instr) (((instr) & ARMv8_LDRiu64_mask) == ARMv8_LDRiu64_base)

#define ARMv8_LDUR64_mask 0xffe00c00
#define ARMv8_LDUR64_base 0xf8400000
#define ARMv8_LDUR64(Xt, Xn_SP, imm9) (ARMv8_LDUR64_base | ((imm9) << 12) | ((Xn_SP) << 5) | (Xt))
#define ARMv8_is_LDUR64(instr) (((instr) & ARMv8_LDUR64_mask) == ARMv8_LDUR64_base)

#define ARMv8_LDAR_mask 0x3ffffc00
#define ARMv8_LDAR_base 0x8dffc00
#define ARMv8_LDAR(size, Rn_SP, Rt) (ARMv8_LDAR_base | ((size) << 30) | ((Rn_SP) << 5) | (Rt))
#define ARMv8_is_LDAR(instr) (((instr) & ARMv8_LDAR_mask) == ARMv8_LDAR_base)

#define ARMv8_CMP_er_mask 0x7fe0001f
#define ARMv8_CMP_er_base 0x6b20001f
#define ARMv8_is_CMP_er(instr) (((instr) & ARMv8_CMP_er_mask) == ARMv8_CMP_er_base)
#define ARMv8_CMP_i_mask 0x7f80001f
#define ARMv8_CMP_i_base 0x7100001f
#define ARMv8_is_CMP_i(instr) (((instr) & ARMv8_CMP_i_mask) == ARMv8_CMP_i_base)
#define ARMv8_CMP_sr_mask 0x7f20001f
#define ARMv8_CMP_sr_base 0x6b00001f
#define ARMv8_is_CMP_sr(instr) (((instr) & ARMv8_CMP_sr_mask) == ARMv8_CMP_sr_base)

#define ARMv8_is_CAS_family(instr) (((instr) & 0x3fa07c00) == 0x8a07c00)

#define ARMv8_is_CASP_family(instr) (((instr) & 0xbfa07c00) == 0x8207c00)

#define ARMv8_is_SWP_family(instr) (((instr) & 0x3f20fc00) == 0x38208000)

#define ARMv8_is_ldadd_family(instr) (((instr) & 0x3f20fc00) == 0x38200000)

#define ARMv8_is_LDSET_family(instr) (((instr) & 0x3f20fc00) == 0x38203000)

#define ARMv8_is_LDCLR_family(instr) (((instr) & 0x3f20fc00) == 0x38201000)

#define ARMv8_is_LDEOR_family(instr) (((instr) & 0x3f20fc00) == 0x38202000)

#define ARMv8_is_LDAPR_family(instr) (((instr) & 0x3ffffc00) == 0x38bfc000)

#endif //__ARM64_h__