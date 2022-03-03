#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096

uint8_t sig_stack_array[SIGSTKSZ];
stack_t sig_stack = {
    .ss_size = SIGSTKSZ,
    .ss_sp = sig_stack_array,
};

void configure_sig_handler(void (*handler)(int, siginfo_t *, void *), int signum)
{
    struct sigaction s;
    s.sa_sigaction = handler;
    s.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigfillset(&s.sa_mask);
    sigaction(signum, &s, NULL);

    sigaction(SIGILL, &s, NULL);
    sigaction(SIGSEGV, &s, NULL);
    sigaction(SIGFPE, &s, NULL);
    sigaction(SIGBUS, &s, NULL);
    sigaction(SIGTRAP, &s, NULL);
}

void sig_handler(int signum, siginfo_t *si, void *p)
{
    mcontext_t mc = ((ucontext_t *)p)->uc_mcontext;
    printf("%d@", signum);
#ifdef __aarch64__
    for (int i = 0; i <= 30; i++)
    {
        printf("%x ", mc.regs[i]);
    }
    printf("%x ", mc.sp);
    printf("%x ", mc.pc);
    printf("%x$", mc.pstate);
#else
    printf("%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x$",
           mc.arm_r0, mc.arm_r1, mc.arm_r2, mc.arm_r3, mc.arm_r4, mc.arm_r5, mc.arm_r6, mc.arm_r7, mc.arm_r8,
           mc.arm_r9, mc.arm_r10, mc.arm_fp, mc.arm_ip, mc.arm_sp, mc.arm_lr, mc.arm_pc, mc.arm_cpsr);
#endif
    exit(signum);
}

void init_sig_handlers(void)
{
    sigaltstack(&sig_stack, NULL);
    configure_sig_handler(sig_handler, SIGILL);
    configure_sig_handler(sig_handler, SIGSEGV);
    configure_sig_handler(sig_handler, SIGFPE);
    configure_sig_handler(sig_handler, SIGBUS);
    configure_sig_handler(sig_handler, SIGTRAP);
}

int main()
{
    // void *null_p = mmap(0, PAGE_SIZE*2, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    // if (null_p == MAP_FAILED) {
    //     fprintf(stderr, "null access requires running as root\n");
    //     exit(-1);
    // }

    init_sig_handlers();
#ifdef __aarch64__
    __asm__ __volatile__(
        "mov x0, %[reg_init]        \n"
        "mov x1, %[reg_init]        \n"
        "mov x2, %[reg_init]        \n"
        "mov x3, %[reg_init]        \n"
        "mov x4, %[reg_init]        \n"
        "mov x5, %[reg_init]        \n"
        "mov x6, %[reg_init]        \n"
        "mov x7, %[reg_init]        \n"
        "mov x8, %[reg_init]        \n"
        "mov x9, %[reg_init]        \n"
        "mov x10, %[reg_init]       \n"
        "mov x11, %[reg_init]       \n"
        "mov x12, %[reg_init]       \n"
        "mov x13, %[reg_init]       \n"
        "mov x14, %[reg_init]       \n"
        "mov x15, %[reg_init]       \n"
        "mov x16, %[reg_init]       \n"
        "mov x17, %[reg_init]       \n"
        "mov x18, %[reg_init]       \n"
        "mov x19, %[reg_init]       \n"
        "mov x20, %[reg_init]       \n"
        "mov x21, %[reg_init]       \n"
        "mov x22, %[reg_init]       \n"
        "mov x23, %[reg_init]       \n"
        "mov x24, %[reg_init]       \n"
        "mov x25, %[reg_init]       \n"
        "mov x26, %[reg_init]       \n"
        "mov x27, %[reg_init]       \n"
        "mov x28, %[reg_init]       \n"
        "mov x29, %[reg_init]       \n"
        "mov x30, %[reg_init]       \n"
        "mov sp, x0                 \n"
        :
        : [reg_init] "n"(0));
#else
    __asm__ __volatile__(
        "mov r0, %[reg_init]        \n"
        "mov r1, %[reg_init]        \n"
        "mov r2, %[reg_init]        \n"
        "mov r3, %[reg_init]        \n"
        "mov r4, %[reg_init]        \n"
        "mov r5, %[reg_init]        \n"
        "mov r6, %[reg_init]        \n"
        "mov r7, %[reg_init]        \n"
        "mov r8, %[reg_init]        \n"
        "mov r9, %[reg_init]        \n"
        "mov r10, %[reg_init]       \n"
        "mov r11, %[reg_init]       \n"
        "mov r12, %[reg_init]       \n"
        "mov r14, %[reg_init]       \n"
        "mov r13, r0                \n"
        :
        : [reg_init] "n"(0));
#endif

    __asm__ __volatile__(
        ".global inst_location\n"
        "inst_location:\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        ".global bkpt_location\n"
        "bkpt_location:\n"
#ifdef __aarch64__
        "brk #0\n"
#else
        "bkpt #0\n"
#endif
    );

    // 正常情况下, 不会到达这里
    exit(0);
}
