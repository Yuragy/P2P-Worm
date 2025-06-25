#include "vm.h"
#include <stdio.h>
#include <stdlib.h>

#define VM_STACK_MAX 1024

void run_vm(const unsigned char *code, size_t len) {
    int stack[VM_STACK_MAX];
    size_t sp = 0;    // stack pointer
    size_t ip = 0;    // instruction pointer

    #define STACK_PUSH(v) do {                                            \
        if (sp >= VM_STACK_MAX) {                                         \
            fprintf(stderr, "VM error: stack overflow (max %d)\n", VM_STACK_MAX); \
            exit(1);                                                      \
        }                                                                  \
        stack[sp++] = (int)(v);                                           \
    } while (0)

    #define STACK_POP() ({                                                \
        if (sp == 0) {                                                    \
            fprintf(stderr, "VM error: stack underflow\n");              \
            exit(1);                                                      \
        }                                                                  \
        stack[--sp];                                                      \
    })

    while (ip < len) {
        unsigned char op = code[ip++];
        switch (op) {
            case VM_OP_PUSH: {
                if (ip >= len) {
                    fprintf(stderr, "VM error: unexpected EOF during PUSH\n");
                    exit(1);
                }
                unsigned char imm = code[ip++];
                STACK_PUSH((int)imm);
                break;
            }
            case VM_OP_ADD: {
                int b = STACK_POP();
                int a = STACK_POP();
                STACK_PUSH(a + b);
                break;
            }
            case VM_OP_SUB: {
                int b = STACK_POP();
                int a = STACK_POP();
                STACK_PUSH(a - b);
                break;
            }
            case VM_OP_MUL: {
                int b = STACK_POP();
                int a = STACK_POP();
                STACK_PUSH(a * b);
                break;
            }
            case VM_OP_DIV: {
                int b = STACK_POP();
                int a = STACK_POP();
                if (b == 0) {
                    fprintf(stderr, "VM error: division by zero\n");
                    exit(1);
                }
                STACK_PUSH(a / b);
                break;
            }
            case VM_OP_PRINT: {
                int v = STACK_POP();
                printf("%d\n", v);
                break;
            }
            case VM_OP_HALT: {
                return;
            }
            default: {
                fprintf(stderr, "VM error: unknown opcode 0x%02X at byte %zu\n", op, ip-1);
                exit(1);
            }
        }
    }

    #undef STACK_PUSH
    #undef STACK_POP
}
