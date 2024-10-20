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
extern unsigned long p_hk_info;
extern unsigned long replace_end;


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

/*static*/ void
default_onPreCallBack(my_pt_regs *regs, HkInfo *pInfo) //参数regs就是指向栈上的一个数据结构，由第二部分的mov r0, sp所传递。
{
    const char *name = "null";
    if (pInfo) {
        name = pInfo->methodName.c_str();
    }
    LE("tid=%d, onPreCallBack:%s, "
       "x0=0x%llx, x1=0x%llx, x2=0x%llx, x3=0x%llx, x4=0x%llx, x5=0x%llx, x6=0x%llx, x7=0x%llx, x8=0x%llx, x9=0x%llx, x10=0x%llx,"
       " x11=0x%llx, x12=0x%llx, x13=0x%llx, x14=0x%llx, x15=0x%llx, x16=0x%llx, x17=0x%llx, x18=0x%llx, x19=0x%llx, x20=0x%llx, "
       "x21=0x%llx, x22=0x%llx, x23=0x%llx, x24=0x%llx, x25=0x%llx, x26=0x%llx, x27=0x%llx, x28=0x%llx, x29/FP=0x%llx, x30/LR=0x%llx, "
       "cur_sp=%p, ori_sp=%p, ori_sp/31=0x%llx, NZCV/32=0x%llx, x0/pc/33=0x%llx, cur_pc=%llx, arg8=%x, arg9=%x, arg10=%x, arg11=%x, "
       "arg12=%x, arg13=%x;", gettid(), name,
       regs->uregs[0], regs->uregs[1], regs->uregs[2], regs->uregs[3], regs->uregs[4],
       regs->uregs[5],
       regs->uregs[6], regs->uregs[7], regs->uregs[8], regs->uregs[9], regs->uregs[10],
       regs->uregs[11],
       regs->uregs[12], regs->uregs[13], regs->uregs[14], regs->uregs[15], regs->uregs[16],
       regs->uregs[17],
       regs->uregs[18], regs->uregs[19], regs->uregs[20], regs->uregs[21], regs->uregs[22],
       regs->uregs[23],
       regs->uregs[24], regs->uregs[25], regs->uregs[26], regs->uregs[27], regs->uregs[28],
       regs->uregs[29], regs->uregs[30],
       regs, /*((char*)regs + 0x110)*/((char *) regs + 0x310), regs->uregs[31], regs->uregs[32],
       regs->uregs[33], regs->pc,
       SP(0), SP(1), SP(2), SP(3), SP(4), SP(5)
    );
}



static int getTypeInArm64(uint32_t instruction)
{
    if ((instruction & 0x9F000000) == 0x10000000) { //1001 1111
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

void build_replace(HkInfo* info){
    void *p_shellcode_start_s = &replace_start;
    void *p_shellcode_end_s = &replace_end;
    void *t_hk_info = &p_hk_info;
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
    mprotect((void *) (newShellCode), pageSize, PROT_READ | PROT_WRITE | PROT_EXEC);
    info->hkInfo = reinterpret_cast<void **>(reinterpret_cast<long>(newShellCode) +
                                             (reinterpret_cast<long>(t_hk_info) -
                                              reinterpret_cast<long >(p_shellcode_start_s)));
    *(info->hkInfo) = info;
    info->pStubShellCodeAddr = newShellCode;
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
    uint32_t new_entry_addr = (uint32_t)pstInlineHook->pNewEntryForOriFuncAddr;
    LE("new_entry_addr : %x",new_entry_addr);
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
    if (type == ADR_ARM64) {
        //LDR Rn, 4
        //PC+imm*4
        LOGI("ADR_ARM64");
        uint32_t imm21;
        uint64_t value;
        uint32_t rd;
        imm21 = ((instruction & 0xFFFFE0)>>3) + ((instruction & 0x60000000)>>29);
        value = pc + 4*imm21;
        if((imm21 & 0x100000)==0x100000)
        {
            LOGI("NEG");
            value = pc - 4 * (0x1fffff - imm21 + 1);
        }
        LOGI("value : %x",value);

        rd = instruction & 0x1f;
        trampoline_instructions[trampoline_pos++] = 0x58000020+rd; // ldr rd, 4
        trampoline_instructions[trampoline_pos++] = (uint32_t)(value >> 32);
        trampoline_instructions[trampoline_pos++] = (uint32_t)(value & 0xffffffff);

        return 4*trampoline_pos;
    }
    if (type == ADRP_ARM64) {
        //LDR Rn, 8
        //B 12
        //PC+imm*4096
        LOGI("ADRP_ARM64");
        uint32_t imm21;
        uint64_t value;
        uint32_t rd;
        imm21 = ((instruction & 0xFFFFE0)>>3) + ((instruction & 0x60000000)>>29);
        value = (pc & 0xfffffffffffff000) + 4096*imm21;
        if((imm21 & 0x100000)==0x100000)
        {
            LOGI("NEG");
            value = (pc & 0xfff) - 4096 * (0x1fffff - imm21 + 1);
        }
        LOGI("pc    : %lx",pc);
        LOGI("imm21 : %x",imm21);
        LOGI("value : %lx",value);
        LOGI("valueh : %x",(uint32_t)(value >> 32));
        LOGI("valuel : %x",(uint32_t)(value & 0xffffffff));

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
        LOGI("LDR_ARM64");
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
        LOGI("Rn : %d",rn);
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
        LOGI("%p, target_ins : %x",value, target_ins);

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
        LOGI("%p, target_ins : %x",value, target_ins);

        trampoline_instructions[trampoline_pos++] = 0x5800007E; //LDR LR, 12
        trampoline_instructions[trampoline_pos++] = 0xD63F03C0; //BLR LR
        trampoline_instructions[trampoline_pos++] = 0x14000003; //B 12
        trampoline_instructions[trampoline_pos++] = (uint32_t)(value & 0xffffffff);
        trampoline_instructions[trampoline_pos++] = (uint32_t)(value >> 32);

        return 4*trampoline_pos;
    }
    else {
        LOGI("OTHER_ARM");
        trampoline_instructions[trampoline_pos++] = instruction;
        return 4*trampoline_pos;
    }
    //pc += sizeof(uint32_t);

    //trampoline_instructions[trampoline_pos++] = 0xe51ff004;	// LDR PC, [PC, #-4]
    //trampoline_instructions[trampoline_pos++] = lr;
    return 4*trampoline_pos;
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

void build_olf_func(HkInfo* info) {
    void* fixOpCode = mmap(NULL,PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    void *pNewEntryForOldFunction = NULL;
    pNewEntryForOldFunction = (char*)(info->pStubShellCodeAddr) + info->shellcodeLength;
    info->pNewEntryForOriFuncAddr = pNewEntryForOldFunction;
    int fixLength = fixPcOpcodeArm64(fixOpCode, info);

}

void hook_arm64(HkInfo *info) {
    LE("start hook arm64 %p", info)
    InitArmHookInfo(info);
    if(info->hookFuncAddr){
        build_replace(info);
    }

}

void hook(void *bHookFuncAddr, void (*onPreCallBack)(struct my_pt_regs *, HkInfo *pInfo),
          void (*onCallBack)(struct my_pt_regs *, HkInfo *pInfo),
          std::string methodName) {
    auto *h_info = new HkInfo();
    h_info->bHookFuncAddr = bHookFuncAddr;
    add(h_info);
    h_info->onPreCallBack = onPreCallBack == nullptr ? nullptr : default_onPreCallBack;
    h_info->methodName = methodName;
    h_info->onCallBack = onCallBack;
    hook_arm64(h_info);
}

