#include "pin.H"
#include <iostream>
#include <bitset>
#include <set>
#include <vector>
#include <memory>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

using namespace std;

int taint_mem_fd;

vector<bool> taint_reg_set(REG_LAST, false);

KNOB<uint64_t> StartAddr(KNOB_MODE_WRITEONCE, "pintool", "s", "0", "start address");
KNOB<uint64_t> EndAddr(KNOB_MODE_WRITEONCE, "pintool", "e", "0", "end address");

INT32 Usage() {
    cerr << "This tool analysis indirect branch with taint propagate" << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

// #include "syscall_num.inc"
#include "syscall_num_sensitive.inc"

void syscall_entry(THREADID tid, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* v) {
  ADDRINT syscall_num = PIN_GetSyscallNumber(ctxt, std);
  cout << "===syscall entry===" << endl << "syscall num: " << syscall_num << endl;
  // if(ignore_syscall_set.find(syscall_num) != ignore_syscall_set.end())
  if(sensitive_syscall_set.find(syscall_num) == sensitive_syscall_set.end())
    return;
  if(PIN_GetSyscallArgument(ctxt, std, 0) == 0) {
    ADDRINT mem_addr = PIN_GetSyscallArgument(ctxt, std, 1);
    ADDRINT mem_size = PIN_GetSyscallArgument(ctxt, std, 2);
    
    lseek(taint_mem_fd, mem_addr, SEEK_SET);
    char flag = 1;    
    for(ADDRINT i = 0; i < mem_size; ++i) {
      write(taint_mem_fd, &flag, 1);
    }
  }
}

VOID before_inst_with_read_reg(REG reg, ADDRINT reg_val) {
  cout << "\tread reg: " << REG_StringShort(reg) << " - 0x" << hex << reg_val << endl;
}

VOID inst_instrument(INS inst, VOID *v) {
  cout << "0x" << hex << INS_Address(inst) << ": " << INS_Disassemble(inst) << endl;
    
  uint32_t regR_num = INS_MaxNumRRegs(inst);
  for(uint32_t i = 0; i < regR_num ; ++i) {
    // cout << "\tread reg: " << REG_StringShort(INS_OperandReg(inst, i)) << endl;
    // if(REG_valid(INS_OperandReg(inst, i))) {
      // INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst_with_read_reg, IARG_REG_REFERENCE, IARG_REG_VALUE, INS_OperandReg(inst, i), IARG_END);
    // }
  }

  uint32_t regW_num = INS_MaxNumWRegs(inst);
  for(uint32_t i = 0; i < regW_num ; ++i) {
    // insertCall(inst, IPOINT_BEFORE, before_inst_with_written_reg, IARG_PTR, IARG_REG_REFERENCE);
  }
  
  uint32_t opr_count = INS_OperandCount(inst);
  for(uint32_t i = 0; i < opr_count; ++i) {
    if(INS_OperandIsMemory(inst, i)) {
      if(INS_OperandRead(inst, i)) {
        // insertCall(inst, IPOINT_BEFORE, before_inst_with_read_mem, IARG_PTR, IARG_MEMORYREAD_EA);
      }
      if(INS_OperandWritten(inst, i)) {
        // insertCall(inst, IPOINT_BEFORE, before_inst_with_written_mem, IARG_PTR, IARG_MEMORYREAD_EA);
      }
    }
  }
}

int main(int argc, char *argv[]) {
  // init_ignore_syscall_set();
  init_sensitive_syscall_set();

  system("fallocate -n -l 8G taint_mem_file");

  PIN_InitSymbols();
  if( PIN_Init(argc,argv) )
  {
    return Usage();
  }

  INS_AddInstrumentFunction(inst_instrument, 0);
  PIN_AddSyscallEntryFunction(syscall_entry, NULL);

  PIN_StartProgram();
  return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
