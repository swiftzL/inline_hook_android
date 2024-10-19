//
// Created by zilongli on 2024/10/18.
//

#ifndef INLINEHOOK_FINAL_COMM_H
#define INLINEHOOK_FINAL_COMM_H
#include <android/log.h>

#define debug_log(fmt,...) __android_log_print(6, "hooks", fmt,__VA_ARGS__ )
#define LE(fmt, args...) __android_log_print(5, "hooks", fmt, ##args);
#define BYTE unsigned char

enum INSTRUCTION_TYPE {


    // BLX <label>
    BLX_ARM,
    // BL <label>
    BL_ARM,
    // B <label>
    B_ARM,

    // <Add by GToad>
    // B <label>
    BEQ_ARM,
    // B <label>
    BNE_ARM,
    // B <label>
    BCS_ARM,
    // B <label>
    BCC_ARM,
    // B <label>
    BMI_ARM,
    // B <label>
    BPL_ARM,
    // B <label>
    BVS_ARM,
    // B <label>
    BVC_ARM,
    // B <label>
    BHI_ARM,
    // B <label>
    BLS_ARM,
    // B <label>
    BGE_ARM,
    // B <label>
    BLT_ARM,
    // B <label>
    BGT_ARM,
    // B <label>
    BLE_ARM,
    // </Add by GToad>

    // BX PC
    BX_ARM,
    // ADD Rd, PC, Rm (Rd != PC, Rm != PC) 在对ADD进行修正时，采用了替换PC为Rr的方法，当Rd也为PC时，由于之前更改了Rr的值，可能会影响跳转后的正常功能;实际汇编中没有发现Rm也为PC的情况，故未做处理。
    ADD_ARM,
    // ADR Rd, <label>
    ADR1_ARM,
    // ADR Rd, <label>
    ADR2_ARM,
    // MOV Rd, PC
    MOV_ARM,
    // LDR Rt, <label>
    LDR_ARM,


    ADR_ARM64,

    ADRP_ARM64,

    LDR_ARM64,

    B_ARM64,

    B_COND_ARM64,

    BR_ARM64,

    BL_ARM64,

    BLR_ARM64,

    CBNZ_ARM64,

    CBZ_ARM64,

    TBNZ_ARM64,

    TBZ_ARM64,

    LDR_ARM64_32,

    UNDEFINE,

    BL_ARM64_b
};


#endif //INLINEHOOK_FINAL_COMM_H
