#include <sys/syscall.h>

set<ADDRINT> sensitive_syscall_set;

void init_sensitive_syscall_set() {
  sensitive_syscall_set.insert(SYS_read);
}