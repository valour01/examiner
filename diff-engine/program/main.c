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
#include <sys/types.h>

#include "utils.h"

#define N 100
#define PAGE_SIZE 4096

/* configuration */
struct
{
    char *path;
} config;

void help(void)
{
    printf("help:\n");
    printf("examiner FILE_PATH\n");
}

void init_config(int argc, char **argv)
{
    if (argc < 2)
    {
        help();
        exit(0);
    }
    config.path = argv[1];
}

/* signal handle */
mcontext_t mc;
uint8_t sig_stack_array[SIGSTKSZ];
stack_t sig_stack = {
    .ss_size = SIGSTKSZ,
    .ss_sp = sig_stack_array,
};

void sig_handler(int signum, siginfo_t *si, void *p)
{
    mc = ((ucontext_t *)p)->uc_mcontext;
    ((ucontext_t *)p)->uc_mcontext.arm_pc -= 4;
}

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

void init_sig_handler(void) {
    sigaltstack(&sig_stack, NULL);
    configure_sig_handler(sig_handler, SIGILL);
    configure_sig_handler(sig_handler, SIGSEGV);
    configure_sig_handler(sig_handler, SIGFPE);
    configure_sig_handler(sig_handler, SIGBUS);
    configure_sig_handler(sig_handler, SIGTRAP);
}

// instruction
extern char boilerplate_start, boilerplate_end, insn_location;
uint32_t insn_offset = 0;
void *insn_page;

/*
 * State management when testing instructions.
 *
 * Used to prevent instructions with side-effects to corrupt the program
 * state, in addition to saving register values for analysis.
 */
void execution_boilerplate(void)
{
    asm volatile(
        ".global boilerplate_start  \n"
        "boilerplate_start:         \n"

        // Store all gregs
        "push {r0-r12, lr}          \n"

        /*
             * It's better to use ptrace in cases where the sp might
             * be corrupted, but storing the sp in a vector reg
             * mitigates the issue somewhat.
             */
        "vmov s0, sp                \n"

        // Reset the regs to make insn execution deterministic
        // and avoid program corruption
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
        "mov lr, %[reg_init]        \n"
        "mov sp, %[reg_init]        \n"

        // Note: this msr insn must be directly above the nop
        // because of the -c option (excluding the label ofc)
        "msr cpsr_f, #0             \n"

        ".global insn_location      \n"
        "insn_location:             \n"

        // This instruction will be replaced with the one to be tested
        "nop                        \n"

        "vmov sp, s0                \n"

        // Restore all gregs
        "pop {r0-r12, lr}           \n"

        "bx lr                      \n"
        ".global boilerplate_end    \n"
        "boilerplate_end:           \n"
        :
        : [reg_init] "n"(0));
}

int init_insn_page(void)
{
    // Allocate an executable page / memory region
    insn_page = mmap(NULL,
                     PAGE_SIZE,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1,
                     0);

    if (insn_page == MAP_FAILED) {
        return 1;
    }

    uint32_t boilerplate_length = (&boilerplate_end - &boilerplate_start) / 4;

    // Load the boilerplate assembly
    for (uint32_t i = 0; i < boilerplate_length; ++i)
        ((uint32_t *)insn_page)[i] = ((uint32_t *)&boilerplate_start)[i];

    insn_offset = (&insn_location - &boilerplate_start) / 4;

    return 0;
}

void execute_insn_page(uint8_t *insn_bytes)
{
    // Jumps to the instruction buffer
    void (*exec_page)() = (void (*)())insn_page;

    memcpy(insn_page + insn_offset * 4, insn_bytes, 4);

    /*
     * Clear insn_page (at the insn to be tested + the msr insn before)
     * in the d- and icache
     * (some instructions might be skipped otherwise.)
     */
    __clear_cache(insn_page + (insn_offset - 1) * 4,
                  insn_page + insn_offset * 4 + 4);

    exec_page();
}

int main(int argc, char **argv)
{
    FILE *f;
    char content[N + 1];

    init_config(argc, argv);

    if ((f = fopen(config.path, "r")) == NULL)
    {
        printf("Failed to open file %s\n", config.path);
        exit(0);
    }

    mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE,
         MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    init_sig_handler();
    if (init_insn_page() != 0)
    {
        perror("insn_page mmap failed");
        return 1;
    }

    while (fgets(content, N, f) != NULL)
    {
        char *name = content;
        char *code = content;
        while (*code != ' ')
        {
            code++;
        }
        *code = 0;
        code++;
        uint8_t inst[4];
        bin2bytes(inst, code, 32);
        execute_insn_page(inst);
    }


    munmap(insn_page, PAGE_SIZE);
    fclose(f);
    return 0;
}
