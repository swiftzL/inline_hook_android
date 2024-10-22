//
// Created by zilongli on 2024/10/18.
//

#ifndef INLINEHOOK_FINAL_INLINE_HOOK_H
#define INLINEHOOK_FINAL_INLINE_HOOK_H


#include <asm-generic/types.h>
#include <iostream>
#include "comm.h"

class HkInfo {
public:
    void *bHookFuncAddr;
    void* oldFuncAddr;
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
};

typedef void (*onPreCallBack)(struct my_pt_regs *, HkInfo *pInfo);

typedef void (*onCallBack)(struct my_pt_regs *, HkInfo *pInfo);

void hook_func(void *bHookFuncAddr,void* hookFuncAddr,std::string methodName);
bool ChangePageProperty(void *pAddress, size_t size);

#ifdef __cplusplus
extern "C" {
#endif
void* getHookAddr();
#ifdef __cplusplus
}
#endif

#endif //INLINEHOOK_FINAL_INLINE_HOOK_H
