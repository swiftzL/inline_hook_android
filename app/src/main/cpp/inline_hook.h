//
// Created by zilongli on 2024/10/18.
//

#ifndef INLINEHOOK_FINAL_INLINE_HOOK_H
#define INLINEHOOK_FINAL_INLINE_HOOK_H


#include <asm-generic/types.h>
#include <iostream>
#include "comm.h"
union my_neon_regs {
    long double qregs[32];
    double dregs[32][2];
//    float fregs[64*2];
    float fregs[32][4];
};

struct my_pt_regs {
    union my_neon_regs neon;
    __u64 uregs[31];
    __u64 sp;
    __u64 pstate;       //有时间应该修复，pc在前，但是涉及到栈和生成shellcode都要改，先这么用吧，和系统结构体有这点不同
    __u64 pc;

};


class HkInfo {
public:
    void *bHookFuncAddr;
    void *hookFuncAddr;
    void (*onPreCallBack)(struct my_pt_regs *, HkInfo *pInfo);
    void (*onCallBack)(struct my_pt_regs *, HkInfo *pInfo);
    std::string methodName;
    int backupFixInstLength[6]; //备份6条指令
    BYTE szbyBackupOpcodes[24];
    long shellcodeLength;
    void** hkInfo;
    void* pStubShellCodeAddr;
    void *pNewEntryForOriFuncAddr;          //和pOriFuncAddr一致
} HkInfoAlias;

typedef void (*onPreCallBack)(struct my_pt_regs *, HkInfo *pInfo);

typedef void (*onCallBack)(struct my_pt_regs *, HkInfo *pInfo);

void hook(void *bHookFuncAddr, onPreCallBack onPreCallBackFunc, onCallBack onCallBackFunc,
          const char *methodName);


#endif //INLINEHOOK_FINAL_INLINE_HOOK_H
