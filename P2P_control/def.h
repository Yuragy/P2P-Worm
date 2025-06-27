#ifndef DEF_H
#define DEF_H

#include <stdbool.h>


bool is_debugger_present(void);
bool is_running_in_vm(void);
bool is_sandbox_environment(void);
bool is_compromised(void);

#endif // DEF_H
