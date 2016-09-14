#include <sys/syscall.h>

set<ADDRINT> ignore_syscall_set;

void init_ignore_syscall_set() {
  ignore_syscall_set.insert(SYS_brk);
  ignore_syscall_set.insert(SYS_mmap);
}