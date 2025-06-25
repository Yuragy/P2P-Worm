#ifndef VM_H
#define VM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    VM_OP_PUSH  = 0x01,  ///< PUSH <imm8>: push immediate byte onto stack
    VM_OP_ADD   = 0x02,  ///< ADD: pop a, pop b, push (a + b)
    VM_OP_SUB   = 0x03,  ///< SUB: pop a, pop b, push (a - b)
    VM_OP_MUL   = 0x04,  ///< MUL: pop a, pop b, push (a * b)
    VM_OP_DIV   = 0x05,  ///< DIV: pop a, pop b, push (a / b) integer; b != 0
    VM_OP_PRINT = 0x06,  ///< PRINT: pop a, print as signed int with newline
    VM_OP_HALT  = 0xFF   ///< HALT: stop execution
};

void run_vm(const unsigned char *code, size_t len);

#ifdef __cplusplus
}
#endif

#endif // VM_H
