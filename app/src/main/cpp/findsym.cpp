//
// Created by root on 10/14/21.
//

#include <jni.h>
#include <string>
#include <dlfcn.h>
#include "android/log.h"
#include "elf.h"
#include "ida.h"
#include "link.h"
#include "sys/mman.h"
#include "errno.h"
#include "findsym.h"
#include "sys/stat.h"
#include "fcntl.h"


#define debug_log(fmt,...) __android_log_print(6, "r0ysue", fmt,__VA_ARGS__ )
int* enumsym(const char* lib,int size){


    int fd;
    void *start;
    struct stat sb;
    fd = open(lib, O_RDONLY); /*打开/etc/passwd */
    fstat(fd, &sb); /* 取得文件大小 */
    start = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

    Elf64_Ehdr header;
    memcpy(&header, start, sizeof(Elf64_Ehdr));
    int secoff = header.e_shoff;
    int secsize = header.e_shentsize;
    int secnum = header.e_shnum;
    int secstr = header.e_shstrndx;
    Elf64_Shdr strtab;
    memcpy(&strtab, (char *) start + secoff + secstr * secsize, sizeof(Elf64_Shdr));
    int strtaboff = strtab.sh_offset;
    char strtabchar[strtab.sh_size];

    memcpy(&strtabchar, (char *) start + strtaboff, strtab.sh_size);
    Elf64_Shdr enumsec;
    int gotoff = 0;
    int gotsize = 0;
    int strtabsize = 0;
    int stroff = 0;
    for (int n = 0; n < secnum; n++) {

        memcpy(&enumsec, (char *) start + secoff + n * secsize, sizeof(Elf64_Shdr));


        if (strcmp(&strtabchar[enumsec.sh_name], ".symtab") == 0) {
            gotoff = enumsec.sh_offset;
            gotsize = enumsec.sh_size;

        }
        if (strcmp(&strtabchar[enumsec.sh_name], ".strtab") == 0) {
            stroff = enumsec.sh_offset;
            strtabsize = enumsec.sh_size;

        }


    }
    int realoff=0;
    char relstr[strtabsize];
    Elf64_Sym tmp;
    memcpy(&relstr, (char *) start + stroff, strtabsize);
int* sdc= static_cast<int *>(malloc(gotsize / sizeof(Elf64_Sym)));
    for (int n = 0; n < gotsize; n = n + sizeof(Elf64_Sym)) {
        memcpy(&tmp, (char *)start + gotoff+n, sizeof(Elf64_Sym));
//        __android_log_print(6, "r0ysue", "%x",gotoff+n);

            sdc[n/sizeof(Elf64_Sym)]=tmp.st_value;
            if(tmp.st_value>size)
                sdc[n/sizeof(Elf64_Sym)]=0;

    }
    return sdc;


}



int getsymsize(const char* lib){

    int fd;
    void *start;
    struct stat sb;
    fd = open(lib, O_RDONLY); /*打开/etc/passwd */
    fstat(fd, &sb); /* 取得文件大小 */
    start = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

    Elf64_Ehdr header;
    memcpy(&header, start, sizeof(Elf64_Ehdr));
    int secoff = header.e_shoff;
    int secsize = header.e_shentsize;
    int secnum = header.e_shnum;
    int secstr = header.e_shstrndx;
    Elf64_Shdr strtab;
    memcpy(&strtab, (char *) start + secoff + secstr * secsize, sizeof(Elf64_Shdr));
    int strtaboff = strtab.sh_offset;
    char strtabchar[strtab.sh_size];

    memcpy(&strtabchar, (char *) start + strtaboff, strtab.sh_size);
    Elf64_Shdr enumsec;
    int gotoff = 0;
    int gotsize = 0;
    int strtabsize = 0;
    int stroff = 0;
    for (int n = 0; n < secnum; n++) {

        memcpy(&enumsec, (char *) start + secoff + n * secsize, sizeof(Elf64_Shdr));


        if (strcmp(&strtabchar[enumsec.sh_name], ".symtab") == 0) {
            gotoff = enumsec.sh_offset;
            gotsize = enumsec.sh_size;

        }
        if (strcmp(&strtabchar[enumsec.sh_name], ".strtab") == 0) {
            stroff = enumsec.sh_offset;
            strtabsize = enumsec.sh_size;

        }


    }

    return gotsize/sizeof(Elf64_Sym);


}


int findsym_file(const char* lib,const char* sym){
    FILE* fd = fopen(lib,"r");
    if (fd == NULL) {
        debug_log("fd is null %d",1);
        return 0;
    }
    fseek(fd, 0, SEEK_END);

    // 获取当前文件指针的位置，即文件大小
    int size = ftell(fd);
    fseek(fd,0,SEEK_SET);
    void* start = malloc(size*8);
    size_t read_size = fread(start,8,size,fd);
    debug_log("read size_t %ld, %ld",read_size,size);
    Elf64_Ehdr elf_header;
    memcpy(&elf_header,start,sizeof(Elf64_Ehdr));
    int secoff = elf_header.e_shoff;
    int secsize = elf_header.e_shentsize;
    int secnum = elf_header.e_shnum;
    int secstr = elf_header.e_shstrndx;
    Elf64_Shdr  strtab;
    memcpy(&strtab,(char*)start+secoff+secstr*secsize,sizeof (Elf64_Shdr));
    int strtaboff = strtab.sh_offset;
    char strtabchar[strtab.sh_size];
    memcpy(&strtabchar,(char*)start+strtaboff,strtab.sh_size);
    Elf64_Shdr enumse;
    int gotoff = 0;
    int gotsize = 0;
    int strtabsize = 0;
    int stroff = 0;
    for (int n =0;n<secnum;n++) { //for all section header
        memcpy(&enumse, (char *) start + secoff + n * secsize, sizeof(Elf64_Shdr));
        debug_log("find section name %s",&strtabchar[enumse.sh_name]);
        if(strcmp(&strtabchar[enumse.sh_name],".symtab")==0) {
            gotoff = enumse.sh_offset;
            gotsize = enumse.sh_size;
        }
        if(strcmp(&strtabchar[enumse.sh_name],".strtab")==0){
            stroff = enumse.sh_offset;
            strtabsize = enumse.sh_size;
        }
    }
    int realoff = 0;
    char relstr[strtabsize];
    Elf64_Sym tmp;
    memcpy(&relstr,(char*)start+stroff,strtabsize);//sym符号
    for(int n=0;n<gotsize;n=n+sizeof(Elf64_Sym)){
        memcpy(&tmp,(char*)start+gotoff+n,sizeof(Elf64_Sym));
        if(tmp.st_name!=0&&strstr(relstr+tmp.st_name,sym)){
            realoff = tmp.st_value;
        }
    }
    free(start);
    fclose(fd);
    return realoff;

}

int findsym(const char* lib,const char* sym){
    int fd;
    void *start;
    struct stat sb;
    fd = open(lib, O_RDONLY); /*打开/etc/passwd */
    fstat(fd, &sb); /* 取得文件大小 */
    start = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    Elf64_Ehdr header;
    memcpy(&header, start, sizeof(Elf64_Ehdr));
    int secoff = header.e_shoff;
    int secsize = header.e_shentsize;
    int secnum = header.e_shnum;
    int secstr = header.e_shstrndx;
    Elf64_Shdr strtab;
    memcpy(&strtab, (char *) start + secoff + secstr * secsize, sizeof(Elf64_Shdr));
    int strtaboff = strtab.sh_offset;
    char strtabchar[strtab.sh_size];
    memcpy(&strtabchar, (char *) start + strtaboff, strtab.sh_size);
    Elf64_Shdr enumsec;
    int gotoff = 0;
    int gotsize = 0;
    int strtabsize = 0;
    int stroff = 0;
    for (int n = 0; n < secnum; n++) {
        memcpy(&enumsec, (char *) start + secoff + n * secsize, sizeof(Elf64_Shdr));
        if (strcmp(&strtabchar[enumsec.sh_name], ".symtab") == 0) {
            gotoff = enumsec.sh_offset;
            gotsize = enumsec.sh_size;
        }
        if (strcmp(&strtabchar[enumsec.sh_name], ".strtab") == 0) {
            stroff = enumsec.sh_offset;
            strtabsize = enumsec.sh_size;
        }
    }
    int realoff=0;
    char relstr[strtabsize];
    Elf64_Sym tmp;
    memcpy(&relstr, (char *) start + stroff, strtabsize);

    for (int n = 0; n < gotsize; n = n + sizeof(Elf64_Sym)) {
        memcpy(&tmp, (char *)start + gotoff+n, sizeof(Elf64_Sym));
//        __android_log_print(6, "r0ysue", "%x",gotoff+n);
        if(tmp.st_name!=0&&strstr(relstr+tmp.st_name,sym))
            realoff=tmp.st_value;


    }

    return realoff;


}