//
// Created by root on 11/20/21.
//

#include "findsobase.h"
#include <jni.h>
#include <string>
#include "findsym.h"
#include "ida.h"
#include "dlfcn.h"
#include "android/log.h"
#include "errno.h"
#include "elf.h"

long soheader;//这个变量本身就是一个地址 寄存器中一般都是存地址而不是值

typedef void *(*to_handle)(void *);

long get_solist_func;
long start;
long get_name_ptr;
__attribute__((noinline)) int add5(int a,int b,int c,int d,int e,int f,int g,int h ,int i,int j,int k,int x,int y,int z,int a1,int a2,int a3,int a4,int a5,int a6,int a7,int a8
,int a9,int a10,int a11,int a12,int a13,int a14,int a15,int a16,int a17,int a18,int a19,int a20){
    return a+c;
}
typedef char *(*get_so_name)(void *);

__attribute__((noinline)) int add4(int a,int b){
    int c = a+b;
    return add5(c,1,2,3,4,5,6,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32);
}

__attribute__((noinline)) int add3(int a,int b){
    int c = a+b;
    return add4(c,b);
}

__attribute__((noinline)) int add2(int a,int b){
    int c= a+b;
    return add3(c,2);
}

__attribute__((noinline)) int add1(int a,int b) {
    int c= a+b;
    return add2(c,2);
}


// solist_get_head = (soinfo_t(*)())resolve_elf_internal_symbol(LINKER_PATH, "__dl__Z15solist_get_headv");
void initlinker() {
    int c= add1(1,3);
    __android_log_print(6, "init-base", "res is %d ",c);
    __android_log_print(6, "init-base", "init linker ");
    long soheaderoff = findsym_file("/apex/com.android.runtime/bin/linker64",
                                    "__dl__ZL6solist");//solist指针
    long get_solist_ptr = findsym_file("/apex/com.android.runtime/bin/linker64",
                                       "__dl__Z15solist_get_headv");//0xb7b54
    long get_name_offset = findsym_file(
            "/apex/com.android.runtime/bin/linker64", "__dl__ZNK6soinfo10get_sonameEv");

    __android_log_print(6, "init-base-get_solit_ptr", "%p", get_solist_ptr);
    char line[1024];

    int *end;
    long *base;
    int n = 1;
    FILE *fp = fopen("/proc/self/maps", "r");
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "linker64")) {
            __android_log_print(6, "r0ysue", "%s", line);
            if (n == 1) {
                start = strtoul(strtok(line, "-"), NULL, 16);
                end = reinterpret_cast<int *>(strtoul(strtok(NULL, " "), NULL, 16));

            } else {
                strtok(line, "-");
                end = reinterpret_cast<int *>(strtoul(strtok(NULL, " "), NULL, 16));
            }
            n++;
        }

    }
    __android_log_print(6, "init-base-start", "%p", start);
    __android_log_print(6, "init-base-start", "0x%lx", start);


    __android_log_print(6, "init-solist-offset", "%p", soheaderoff);
    __android_log_print(6, "init-solist-offset", "0x%x", soheaderoff);
    soheader = (long) start + (soheaderoff);
    get_solist_func = start + get_solist_ptr;
    __android_log_print(6, "init-base", "%p", soheader);
    static long *(*solist_get_head)() = NULL;
    solist_get_head = reinterpret_cast<long *(*)(void)>(get_solist_func);
    __android_log_print(6, "init-base-get_solit_func_address", "%p", solist_get_head);
    long *solist_ptr = solist_get_head();
    __android_log_print(6, "init-base-get_solit_func", "solist func address %p name_func %p",
                        solist_ptr, get_name_offset);
    get_name_ptr = start + get_name_offset;
 long* char_ptr = reinterpret_cast<long*(*)(long*)>(get_name_ptr)(solist_ptr);//0x767cbe3008
    __android_log_print(6, "init-base-so_name is", "%s %p",(char*)char_ptr,char_ptr);  //0x767cbe31a1 =
                                                                                                    //0x767cbe3008
                                                                                                    // 1a1-8=193 = 403

    //0x718e897000
    //0x    12c0b0
    //          0b0
    //71 8E9C 30B0
    //0x718f1f7580

}


//dump


void *soinfo_findsym(void *soinfo) {
//    long* strtab_= reinterpret_cast<long *>(*(long*)((char *) soinfo + 56));
//    long* symtab_= reinterpret_cast<long *>(*(long*)((char *) soinfo + 64));
//    long strsz= reinterpret_cast<long>(*(long*)((char *) soinfo + 336));
//    int result;
//    __android_log_print(6,"r0ysue","%p %p %p",strtab_,symtab_,strsz);
//    char strtab[strsz];
//    memcpy(&strtab, strtab_, strsz);
//    Elf64_Sym mytmpsym;
//    for (int n = 0; n < (long) strtab_ - (long) symtab_; n = n + sizeof(Elf64_Sym)) {
//        memcpy(&mytmpsym,(char*)symtab_+n,sizeof(Elf64_Sym));
////        __android_log_print(6,"r0ysue","%p %s",mytmpsym.st_name,strtab+mytmpsym.st_name);
//        if(strstr(reinterpret_cast<const char *>(strtab + mytmpsym.st_name), "artFindNativeMethod"))
//            result=mytmpsym.st_value;
//
//
//    }


//return reinterpret_cast<void *>(result);
}


void *getmyhandle(void *soinfo) {
    int handleoff = findsym("/system/bin/linker64", "__dl__ZN6soinfo9to_handleEv");

    to_handle func = reinterpret_cast<to_handle>((char *) start + handleoff);
    void *myhandle = func(soinfo);


    return myhandle;

}


void *read_pointer(long pointer) {
    __android_log_print(6, "r0ysue", "old pinter %p", pointer);
    long ptr = *reinterpret_cast<long *>(pointer);
    __android_log_print(6, "r0ysue", "new pinter %ld", ptr);
    return reinterpret_cast<void *>(ptr);
}

void *findsobase(const char *soname) {

    long *base;
    long *soinfo;
    int n = 0;
    long *load_bias;
    __android_log_print(6, "r0ysue", " start find base %s", soname);
    __android_log_print(6, "r0ysue", " start find base so header %p", soheader);//x9
    __android_log_print(6, "r0ysue", " soinfo ptr is %p", read_pointer(soheader));//x9 0x767cbe3008

    for (
            _QWORD *result = (uint64 *) read_pointer(soheader);
            result;
            result = (_QWORD *) result[5]
            ) {
        char* soNamePtr = reinterpret_cast<char*(*)(char*)>(get_name_ptr)(
                reinterpret_cast<char *>(result));
//        char *soNamePtr = reinterpret_cast<char *>((char*)result + 409);//*result->solist->+409->soname
        if (soNamePtr == nullptr || *soNamePtr == 0) {
            __android_log_print(6, "r0ysue", "找不到 %s",soname);
            continue;
        } else {
            __android_log_print(6, "r0ysue", "找到 %s  %s", soNamePtr,soname);
        }
        if (strstr(soname,soNamePtr)) {
            __android_log_print(6, "r0ysue", "找到so了 %s", soNamePtr);
            base = reinterpret_cast<long *>(*(_QWORD *) ((char *) result + 16));
            __android_log_print(6, "r0ysue", " base:%p ", *base);
            long *size = reinterpret_cast<long *>(*(_QWORD *) ((char *) result + 24));
            __android_log_print(6, "r0ysue", " size:%x ", size);
            const char *name = reinterpret_cast<const char *>(((char*) result + 409));
            __android_log_print(6, "r0ysue", " soname:%s ", name);

            load_bias = reinterpret_cast<long *>(*(_QWORD *) ((char *) result + 256));
            __android_log_print(6, "r0ysue", " loadbias:%p ", load_bias);

            break;
        }

    }

    return load_bias;
}