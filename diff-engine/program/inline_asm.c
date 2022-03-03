#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <malloc.h>
#include <math.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

#define PAGE_SIZE 4096

extern char resume;

void configure_sig_handler(void (*handler)(int, siginfo_t *, void *))
{
    struct sigaction s;
    s.sa_sigaction = handler;
    s.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigfillset(&s.sa_mask);

    // sigaction(SIGILL, &s, NULL);
    // sigaction(SIGSEGV, &s, NULL);
    // sigaction(SIGFPE, &s, NULL);
    // sigaction(SIGBUS, &s, NULL);
    sigaction(SIGTRAP, &s, NULL);
}

void *inst_buffer;
struct
{
    uint64_t dummy_stack_hi[256];
    uint64_t dummy_stack_lo[256];
} dummy_stack __attribute__((aligned(PAGE_SIZE)));

void run(void)
{
    __asm__ __volatile__(
        "ldr r13, %[rsp]\n\t"
        "mov r0, #0\n\t"
        "mov r1, #0\n\t"
        "mov r2, #0\n\t"
        "mov r3, #0\n\t"
        "mov r4, #0\n\t"
        "mov r5, #0\n\t"
        "mov r6, #0\n\t"
        "mov r7, #0\n\t"
        "mov r8, #0\n\t"
        "mov r9, #0\n\t"
        "mov r10, #0\n\t"
        "mov r11, #0\n\t"
        "mov r12, #0\n\t"
        : /* no output */
        : [rsp]"m"(dummy_stack.dummy_stack_lo)
    );
    // goto *inst_buffer;
	__asm__ __volatile__ (
        ".global resume\n\t"
        "resume:\n\t"
	);
    printf("yes!\n");
}

void sig_handler(int signum, siginfo_t *si, void *p)
{
    uint32_t r0 = ((ucontext_t *)p)->uc_mcontext.arm_r0;
    uint32_t r1 = ((ucontext_t *)p)->uc_mcontext.arm_r1;
    uint32_t r2 = ((ucontext_t *)p)->uc_mcontext.arm_r2;
    uint32_t r3 = ((ucontext_t *)p)->uc_mcontext.arm_r3;
    uint32_t r4 = ((ucontext_t *)p)->uc_mcontext.arm_r4;
    uint32_t r5 = ((ucontext_t *)p)->uc_mcontext.arm_r5;
    uint32_t r6 = ((ucontext_t *)p)->uc_mcontext.arm_r6;
    uint32_t r7 = ((ucontext_t *)p)->uc_mcontext.arm_r7;
    uint32_t r8 = ((ucontext_t *)p)->uc_mcontext.arm_r8;
    uint32_t r9 = ((ucontext_t *)p)->uc_mcontext.arm_r9;
    uint32_t r10 = ((ucontext_t *)p)->uc_mcontext.arm_r10;
    uint32_t r11 = ((ucontext_t *)p)->uc_mcontext.arm_fp;
    uint32_t r12 = ((ucontext_t *)p)->uc_mcontext.arm_ip;
    uint32_t r13 = ((ucontext_t *)p)->uc_mcontext.arm_sp;
    uint32_t r14 = ((ucontext_t *)p)->uc_mcontext.arm_lr;
    uint32_t r15 = ((ucontext_t *)p)->uc_mcontext.arm_pc;
    uint32_t error_code = ((ucontext_t *)p)->uc_mcontext.error_code;
    uint32_t fault_address = ((ucontext_t *)p)->uc_mcontext.fault_address;
    uint32_t trap_no = ((ucontext_t *)p)->uc_mcontext.trap_no;
    uint32_t oldmask = ((ucontext_t *)p)->uc_mcontext.oldmask;
    printf("%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n", r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, error_code, fault_address, trap_no, oldmask);
    ((ucontext_t *)p)->uc_mcontext.arm_pc = (uintptr_t)&resume;
}

int main()
{
    inst_buffer = memalign(PAGE_SIZE, PAGE_SIZE);
    errno = 0;
    if (mprotect(inst_buffer, 4, PROT_WRITE | PROT_EXEC) == -1)
    {
        perror("mprotect error");
        exit(0);
    }
    char bkpt[4] = "\x70\x00\x20\xe1"; // bkpt #0
    memcpy(inst_buffer, bkpt, 4);

    printf("%p\n", &dummy_stack.dummy_stack_lo);

    configure_sig_handler(sig_handler);
    run();
    printf("end\n");
    return 0;
}
