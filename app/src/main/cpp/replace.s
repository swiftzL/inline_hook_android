.global replace_start
.global replace_end
.global call_addr


.data

replace_start:
    LDP     x1,x0, [SP,#-0x10];
    sub     sp, sp, #0x20;
    STP     X29, X30, [SP,#0];
    STP     x1, x0, [SP,#0x10];
    ldr      lr,call_addr;
    blr      lr;
    LDP     X29, X30, [SP,#0];
    add     sp, sp ,#0x20;
    ret;
call_addr:
.double 0xffffffffffffffff
replace_end:
.end