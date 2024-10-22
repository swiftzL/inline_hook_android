//
// Created by zilongli on 2024/10/18.
//

#include "inline_hook.h"
#include "comm.h"
#include <vector>
#include <mutex>
#include <unistd.h>
#include <android/log.h>
#include <asm-generic/mman-common.h>
#include <sys/mman.h>

#define SP(i) *((__u64*)regs->sp+i)
static std::vector<HkInfo *> infos;
static std::mutex info_mutex;

extern unsigned long replace_start;
extern unsigned long replace_end;
extern unsigned  long call_addr;


static void add(HkInfo *info) {
    std::lock_guard<std::mutex> _lock(info_mutex);
    for (auto it = infos.begin(); it < infos.end(); ++it) {
        HkInfo *pInfo = *it;
        if (pInfo->bHookFuncAddr == info->bHookFuncAddr) {
            return;
        }
    }
    infos.push_back(info);
}




static int getTypeInArm64(uint32_t instruction)
{
    if ((instruction & 0x9F000000) == 0x10000000) { //1001 1111 = 0001 0000
        LE("is ADR_ARM64");
        return ADR_ARM64;
    }
    if ((instruction & 0x9F000000) == 0x90000000) {
        LE("is ADRP_ARM64");
        return ADRP_ARM64;
    }
    if ((instruction & 0xFC000000) == 0x14000000) {
        LE("is B_ARM64");
        return B_ARM64;
    }
    if ((instruction & 0xFF000010) == 0x54000010) {
        LE("is B_COND_ARM64");
        return B_COND_ARM64;
    }
    if ((instruction & 0xFC000000) == 0x94000000) {//1111 1100 //覆盖最高的6位 0100
        if ((instruction & 0xFF000000) == 0x97000000) {
            LE("is BL_ARM64_b");
            return BL_ARM64_b;
        }
        LE("is BL_ARM64");
        return BL_ARM64;
    }
    if ((instruction & 0xFF000000) == 0x58000000) {//LDR Lliteral need to learn
        return LDR_ARM64;
    }
    if ((instruction & 0x7F000000) == 0x35000000) {
        return CBNZ_ARM64;
    }
    if ((instruction & 0x7F000000) == 0x34000000) {
        return CBZ_ARM64;
    }
    if ((instruction & 0x7F000000) == 0x37000000) {
        return TBNZ_ARM64;
    }
    if ((instruction & 0x7F000000) == 0x36000000) {
        return TBZ_ARM64;
    }
    if ((instruction & 0xFF000000) == 0x18000000) {//LDR Lliteral 32 need to learn
        return LDR_ARM64_32;
    }
    return UNDEFINE;
}

int lengthFixArm64(uint32_t opcode)
{
    int type;
    type = getTypeInArm64(opcode);
    switch(type)
    {
        case B_COND_ARM64:return 32;break;
        case BNE_ARM:
        case BCS_ARM:
        case BCC_ARM:
        case BMI_ARM:
        case BPL_ARM:
        case BVS_ARM:
        case BVC_ARM:
        case BHI_ARM:
        case BLS_ARM:
        case BGE_ARM:
        case BLT_ARM:
        case BGT_ARM:
        case BLE_ARM:return 12;break;
        case BLX_ARM:
        case BL_ARM:return 12;break;
        case B_ARM:
        case BX_ARM:return 8;break;
        case ADD_ARM:return 24;break;
        case ADR1_ARM:
        case ADR2_ARM:
        case LDR_ARM:
        case MOV_ARM:return 12;break;
        case UNDEFINE:return 4;
    }
    return 0;
}


bool InitArmHookInfo(HkInfo *pInfo) {
    bool bRet = false;
    uint32_t *currentOpcode = static_cast<uint32_t *>(pInfo->bHookFuncAddr);

    for (int i = 0; i < 6; i++) {
        pInfo->backupFixInstLength[i] = -1;
    }
    memcpy(pInfo->szbyBackupOpcodes, pInfo->bHookFuncAddr, 24);
    for (int i = 0; i < 6; i++) {
        LE("Arm64 Opcode to fix %d : %x", i, *currentOpcode);
        pInfo->backupFixInstLength[i] = lengthFixArm64(*currentOpcode);
        currentOpcode += 1;
    }

    return true;
}

void dump(void *addr) {
    __android_log_print(6, "r0ysue", "dump addr is %p", addr);
    for (int i = 0; i <= 24; i++) {
        __android_log_print(6, "r0ysue", "dump   %x", *((char*)addr + i));
    }
}

void build_replace(HkInfo* info){
    void *p_shellcode_start_s = &replace_start;
    void *p_shellcode_end_s = &replace_end;
    LE("shellcode _start %p",p_shellcode_start_s);
    LE("shellcode _end %p",p_shellcode_end_s);
    long shellCodeSize = reinterpret_cast<long>(p_shellcode_end_s) - reinterpret_cast<long>(p_shellcode_start_s);
    info->shellcodeLength = shellCodeSize;
    LE("shell code length is %ld",info->shellcodeLength);
    long pageSize = sysconf(_SC_PAGESIZE);
    void* newShellCode = nullptr;
    int code = posix_memalign(&newShellCode, pageSize, pageSize);
    if (code || newShellCode== nullptr) {
        LE("memalign is fail ");
        return;
    }
    memcpy(newShellCode,p_shellcode_start_s,info->shellcodeLength);
    memcpy((void*)((char*)newShellCode+info->shellcodeLength-8),&info->hookFuncAddr,8);
    ChangePageProperty(newShellCode,pageSize);
    info->pStubShellCodeAddr = newShellCode;
    LE("p stub shell coder addr is %p",info->pStubShellCodeAddr);
}

bool isTargetAddrInBackup(uint64_t target_addr, uint64_t hook_addr, int backup_length)
{
    if((target_addr<=hook_addr+backup_length)&&(target_addr>=hook_addr))
        return true;
    return false;
}
//pc 当前代码段地址
int fixPCOpcodeInstrucArm64(uint64_t pc, uint64_t lr, uint32_t instruction, uint32_t *trampoline_instructions, HkInfo* pstInlineHook)
{
    int type;
    int trampoline_pos;
    trampoline_pos = 0;
    LE("THE ARM64 OPCODE IS %x",instruction);
    type = getTypeInArm64(instruction);
    if (type == B_COND_ARM64) {
        //STP X_tmp1, X_tmp2, [SP, -0x10]
        //LDR X_tmp2, ?
        //[target instruction fix code] if you want
        //BR X_tmp2
        //B 8
        //PC+imm*4
        LE("B_COND_ARM64");
        uint32_t target_ins;
        uint32_t imm19;
        uint64_t value;

        imm19 = (instruction & 0xFFFFE0) >> 5; //8 19 1 4
        value = pc + imm19*4;//实际地址
        if((imm19>>18)==1){//负数说明跳转上面
            value = pc - 4*(0x7ffff-imm19+1);//0111 1111 24位
        }//-5 1
        if(isTargetAddrInBackup(value, (uint64_t)pstInlineHook->bHookFuncAddr, 24)){//目标地址在备份中
            int target_idx = (int)((value - (uint64_t)pstInlineHook->bHookFuncAddr)/4);
            int bc_ins_idx = (int)((pc - (uint64_t)pstInlineHook->bHookFuncAddr)/4);
            int idx = 0;
            int gap = 0;
            for(idx=bc_ins_idx+1;idx<target_idx;idx++){
                gap += pstInlineHook->backupFixInstLength[idx];
            }
            trampoline_instructions[trampoline_pos++] = (instruction & 0xff00000f) + ((gap+32)<<3); // B.XX 32+gap
            trampoline_instructions[trampoline_pos++] = 0x14000007; //B 28
        }
        else{
            //backup to outside
            target_ins = *((uint32_t *)value);
            trampoline_instructions[trampoline_pos++] = ((instruction & 0xff00000f) + (32<<3)) ^ 0x1; // B.anti_cond 32
            trampoline_instructions[trampoline_pos++] = target_ins; //target_ins (of cource the target ins maybe need to fix, do it by yourself if you need)
            trampoline_instructions[trampoline_pos++] = 0xa93f03e0; //STP X0, X0, [SP, -0x10] default
            trampoline_instructions[trampoline_pos++] = 0x58000080; //LDR X0, 12
            trampoline_instructions[trampoline_pos++] = 0xd61f0000; //BR X0
            trampoline_instructions[trampoline_pos++] = 0x14000002; //B 8
            trampoline_instructions[trampoline_pos++] = (uint32_t)(value >> 32);
            trampoline_instructions[trampoline_pos++] = (uint32_t)(value & 0xffffffff);
        }

        return 4*trampoline_pos;
    }
    if (type == ADR_ARM64) {//0x10
       //adr x1,4 //0001 0x10
        uint32_t imm21;
        uint64_t value;
        uint32_t rd;
        //               1110 0000                                       0110 0000
        imm21 = ((instruction & 0xFFFFE0)>>3) + ((instruction & 0x60000000)>>29);
        value = pc + 4*imm21;
        if((imm21 & 0x100000)==0x100000)
        {
            value = pc - 4 * (0x1fffff - imm21 + 1);
        }
        rd = instruction & 0x1f; //寄存器位置
        trampoline_instructions[trampoline_pos++] = 0x58000020+rd; // ldr rd, 4
        trampoline_instructions[trampoline_pos++] = (uint32_t)(value >> 32);
        trampoline_instructions[trampoline_pos++] = (uint32_t)(value & 0xffffffff);
        return 4*trampoline_pos;
    }
    if (type == ADRP_ARM64) {
        uint32_t imm21;
        uint64_t value;
        uint32_t rd;
        imm21 = ((instruction & 0xFFFFE0)>>3) + ((instruction & 0x60000000)>>29);
        value = (pc & 0xfffffffffffff000) + 4096*imm21;
        if((imm21 & 0x100000)==0x100000)
        {
            value = (pc & 0xfff) - 4096 * (0x1fffff - imm21 + 1);
        }
        rd = instruction & 0x1f;
        trampoline_instructions[trampoline_pos++] = 0x58000040+rd; // ldr rd, 8
        trampoline_instructions[trampoline_pos++] = 0x14000003; // b 12
        trampoline_instructions[trampoline_pos++] = (uint32_t)(value & 0xffffffff);
        trampoline_instructions[trampoline_pos++] = (uint32_t)(value >> 32);


        return 4*trampoline_pos;
    }
    if (type == LDR_ARM64) {
        //STP Xt, Xn, [SP, #-0x10]
        //LDR Xn, 16
        //LDR Xt, [Xn, 0]
        //LDR Xn, [sp, #-0x8]
        //B 8
        //PC+imm*4
        uint32_t imm19;
        uint64_t value;
        uint32_t rt;
        uint32_t rn;
        rt = instruction & 0x1f;
        int i;
        for(i=0;i<31;i++)
        {
            if(i!=rt){
                rn = i;
                break;
            }
        }

        imm19 = ((instruction & 0xFFFFE0)>>5);
        trampoline_instructions[trampoline_pos++] = 0xa93f03e0 + rt + (rn << 10); //STP Xt, Xn, [SP, #-0x10]
        trampoline_instructions[trampoline_pos++] = 0x58000080 + rn; //LDR Xn, 16
        trampoline_instructions[trampoline_pos++] = 0xf9400000 + (rn << 5); //LDR Xt, [Xn, 0]
        trampoline_instructions[trampoline_pos++] = 0xf85f83e0 + rn; //LDR Xn, [sp, #-0x8]
        trampoline_instructions[trampoline_pos++] = 0x14000002; //B 8

        value = pc + 4*imm19;
        if((imm19 & 0x40000)==0x40000){
            value = pc - 4*(0x7ffff-imm19+1);
        }
        trampoline_instructions[trampoline_pos++] = (uint32_t)(value >> 32);
        trampoline_instructions[trampoline_pos++] = (uint32_t)(value & 0xffffffff);

        return 4*trampoline_pos;
    }
    if (type == B_ARM64) {

        LE("BL_ARM64");
        uint32_t target_ins;
        uint32_t imm26;
        uint64_t value;

        imm26 = instruction & 0xFFFFFF;
        value = pc + imm26*4;
        target_ins = *((uint32_t *)value);


        trampoline_instructions[trampoline_pos++] = 0x5800007E; //LDR LR, 12
        trampoline_instructions[trampoline_pos++] = 0xD63F03C0; //BLR LR
        trampoline_instructions[trampoline_pos++] = 0x14000003; //B 12
        trampoline_instructions[trampoline_pos++] = (uint32_t)(value & 0xffffffff);
        trampoline_instructions[trampoline_pos++] = (uint32_t)(value >> 32);

        return 4*trampoline_pos;
    } else if (type == BL_ARM64_b) {
        LE("BL_ARM64_b");
        uint32_t target_ins;
        uint32_t imm26;
        uint64_t value;

        imm26 = instruction & 0xFFFFFF;
        value = pc - 4*(0xffffff-imm26+1);
        target_ins = *((uint32_t *)value);
        trampoline_instructions[trampoline_pos++] = 0x5800007E; //LDR LR, 12
        trampoline_instructions[trampoline_pos++] = 0xD63F03C0; //BLR LR
        trampoline_instructions[trampoline_pos++] = 0x14000003; //B 12
        trampoline_instructions[trampoline_pos++] = (uint32_t)(value & 0xffffffff);
        trampoline_instructions[trampoline_pos++] = (uint32_t)(value >> 32);

        return 4*trampoline_pos;
    }
    else {
        trampoline_instructions[trampoline_pos++] = instruction;
        return 4*trampoline_pos;
    }
}

int fixPcOpcodeArm64(void* fixOpcodes,HkInfo* info){
    uint64_t pc;
    uint64_t lr;
    int backUpPos = 0;
    int fixPos = 0;
    int offset = 0;

    uint32_t *currentOpcode;
    uint32_t tmpFixOpcodes[40]; //对于每条PC命令的修复指令都将暂时保存在这里。
    currentOpcode = reinterpret_cast<uint32_t *>(info->szbyBackupOpcodes +
                                                 sizeof(uint8_t) * backUpPos);

    pc = reinterpret_cast<uint64_t>(info->bHookFuncAddr);
    lr = reinterpret_cast<uint64_t>((char *) (info->bHookFuncAddr) + 24);


    while(1) {
        offset = fixPCOpcodeInstrucArm64(pc, lr, *currentOpcode, tmpFixOpcodes, info);
        memcpy((void *)((long)fixOpcodes+fixPos), tmpFixOpcodes, offset);
        backUpPos += 4; //arm32的话下一次取后面4 byte偏移的指令
        pc += 4;
        fixPos += offset;
        if (backUpPos < 24)
        {
            currentOpcode = (uint32_t*)((char*)info->szbyBackupOpcodes + backUpPos);
        }
        else{
            return fixPos;
        }
    }
}
bool ChangePageProperty(void *pAddress, size_t size)
{
    bool bRet = false;
    //计算包含的页数、对齐起始地址
    unsigned long ulPageSize = sysconf(_SC_PAGESIZE); //得到页的大小
    int iProtect = PROT_READ | PROT_WRITE | PROT_EXEC; //读写执行

    if (true) {
        uintptr_t start = MY_PAGE_START((uintptr_t)pAddress, ulPageSize);//(~(page_size - 1) & (addr))
        uintptr_t end = MY_PAGE_END((uintptr_t) pAddress + size, ulPageSize);
        LE("start=%p, end=%p, size=%p", start, end, end-start);
        //高版本mprotect即使第二个参数size为0，也是改变一页的内存
        int code = mprotect((void *) (start), end - start, iProtect);
        if(code)
        {
            LE("mprotect error:%s", strerror(errno));
            return bRet;
        }
        return true;
    }
}

HkInfo* currentInfo;

void* getHookAddr(){
    return currentInfo->hookFuncAddr;
}


void BuildArmJumpCode(void *pCurAddress , void *pJumpAddress, HkInfo* info){//--------------
    LE("build arm jump code %p %p", pCurAddress,pJumpAddress)
    //stp x1, x0, [sp, #-0x10]
    //ldr x0, #8
    //br x0
    //xxxx 地址
    //xxxxx
    //ldur x0, [sp, #-8]
    BYTE szLdrPCOpcodes[24] = {0xe1, 0x03, 0x3f, 0xa9, 0x40, 0x00, 0x00, 0x58, 0x00, 0x00, 0x1f, 0xd6};
    //将目的地址拷贝到跳转指令缓存位置
    memcpy(szLdrPCOpcodes + 12, &pJumpAddress, 8);
    LE("build arm jump code1 %p %p %x,", pCurAddress,pJumpAddress,*(uint32_t *)pCurAddress)
    szLdrPCOpcodes[20] = 0xE0;
    szLdrPCOpcodes[21] = 0x83;
    szLdrPCOpcodes[22] = 0x5F;
    szLdrPCOpcodes[23] = 0xF8;
    ChangePageProperty(pCurAddress,24);

    /**
     * ump   0
2024-10-21 20:58:01.694 23895-23895 r0ysue                  com.r0ysue.inlinehook_final          E  dump   60
2024-10-21 20:58:01.694 23895-23895 r0ysue                  com.r0ysue.inlinehook_final          E  dump   3e
2024-10-21 20:58:01.694 23895-23895 r0ysue                  com.r0ysue.inlinehook_final          E  dump   48
2024-10-21 20:58:01.694 23895-23895 r0ysue                  com.r0ysue.inlinehook_final          E  dump   75
2024-10-21 20:58:01.694 23895-23895 r0ysue                  com.r0ysue.inlinehook_final          E  dump   0
2024-10-21 20:58:01.694 23895-23895 r0ysue                  com.r0ysue.inlinehook_final          E  dump   0
2024-10-21 20:58:01.694 23895-23895 r0ysue                  com.r0ysue.inlinehook_final          E  dump   b4
     */

    memcpy(pCurAddress, szLdrPCOpcodes, 24);
    LE("build arm jump code2 %p %p,", pCurAddress,pJumpAddress)
    __builtin___clear_cache((char *) pCurAddress,
                            (char *) pCurAddress + 24);
}
void build_old_func(HkInfo* info) {
    LE("build_old_func %p", info)
    void* fixOpCode = mmap(NULL,PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    void *pNewEntryForOldFunction = NULL;
    pNewEntryForOldFunction = (char*)(info->pStubShellCodeAddr) + info->shellcodeLength;
    info->pNewEntryForOriFuncAddr = pNewEntryForOldFunction;
    int fixLength = fixPcOpcodeArm64(fixOpCode, info);
    mprotect((void *) (info->pNewEntryForOriFuncAddr), fixLength, PROT_READ | PROT_WRITE | PROT_EXEC);
    memcpy(pNewEntryForOldFunction, fixOpCode, fixLength);
    BuildArmJumpCode((void*)((char*)pNewEntryForOldFunction+fixLength),(void*)((char*)info->bHookFuncAddr+24),info);
    info->oldFuncAddr = pNewEntryForOldFunction;
    munmap(fixOpCode,PAGE_SIZE);
}

void rebuild_hook_target(HkInfo* info){
    LE("re build hook %p", info)

    BuildArmJumpCode(info->bHookFuncAddr, info->pStubShellCodeAddr, info);
}

void hook_arm64(HkInfo *info) {
    LE("start hook arm64 %p", info)
    InitArmHookInfo(info);
    if(info->hookFuncAddr){
        build_replace(info);
    }
    build_old_func(info);
    rebuild_hook_target(info);
    LE("start hook arm64 end %p", info)
}

void hook_func(void *bHookFuncAddr,void* hookFuncAddr,std::string methodName) {
    auto *h_info = new HkInfo();
    currentInfo = h_info;
    h_info->bHookFuncAddr = bHookFuncAddr;
    add(h_info);
    h_info->methodName = methodName;
    h_info->hookFuncAddr = hookFuncAddr;
    hook_arm64(h_info);
}

