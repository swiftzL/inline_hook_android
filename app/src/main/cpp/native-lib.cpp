#include <jni.h>
#include <string>
#include <android/log.h>
#include <unistd.h>
#include "myinlinehook.h"
#include "findsobase.h"
#include "findsym.h"
#include "inline_hook.h"

void func(void *a, void *b) {
    int aa = 1;
    int bb = 2;
    int cc = aa + bb * 3;

    __android_log_print(6, "r0ysue", "%p %d", b, cc);

}

void func1(void *a, void *b) {
    __android_log_print(6, "r0ysue", "i am from header%p", b);

}

extern "C" JNIEXPORT jstring JNICALL
        Java_com_r0ysue_inlinehook_1final_MainActivity_stringFromJNI1(JNIEnv *env,jobject /*this*/){
    hook_func((void *) func, (void *) func1, "func1");
    dump((void*)func);
    return env->NewStringUTF("");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_r0ysue_inlinehook_1final_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    initlinker();
    __android_log_print(6, "r0ysue-linker", "linker");
//    long* base= static_cast<long *>(findsobase("libart.so"));
    __android_log_print(6, "r0ysue-linker", "linker-2");

//    int off=findsym("/system/lib64/libart.so","_ZN3art11ClassLinker10LoadMethodE6RKNS_7DexFileERKNS_21ClassDataItemIteratorENS_6HandleINS_6mirror5ClassEEEPNS_9ArtMethodE");
//    long* addr= reinterpret_cast<long *>((char *) base + off );
//    __android_log_print(6,"r0ysue-libart","%p",addr);

//    long* st= reinterpret_cast<long *>((char *) base + 0x10D760 + 0x25000);
//    __android_log_print(6,"r0ysue-base","%p",st);

//    register_hook((void*) func, (void*)(func1));
//    register_hook(addr,(void*)func1);

    LE("start call hook func");
    func(0, 0);

    return env->NewStringUTF(hello.c_str());
}