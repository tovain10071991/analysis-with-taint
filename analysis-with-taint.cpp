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

VOID before_inst_with_read_reg(ADDRINT reg_id, CONTEXT* ctxt) {
  REG reg = (REG)reg_id;
  cout << "\tread reg: " << REG_StringShort(reg) << endl;
  cout << "\t\t";
  UINT8 val_buf[512];
  UINT32 reg_size = REG_Size(reg);
  PIN_GetContextRegval(ctxt, reg, val_buf);
  cout << hex;
  for(UINT32 i = 0; i < reg_size; ++i) {
    cout << " " << int(val_buf[i]);
  }
  cout << endl;
}

VOID before_inst_with_written_reg(ADDRINT reg_id, CONTEXT* ctxt) {
  REG reg = (REG)reg_id;
  cout << "\twritten reg: " << REG_StringShort(reg) << endl;
  cout << "\t\t";
  UINT8 val_buf[512];
  UINT32 reg_size = REG_Size(reg);
  PIN_GetContextRegval(ctxt, reg, val_buf);
  cout << hex;
  for(UINT32 i = 0; i < reg_size; ++i) {
    cout << " " << int(val_buf[i]);
  }
  cout << endl;
}

VOID before_inst_with_read_mem(ADDRINT mem_addr) {
  cout << "\tread mem: " << hex << mem_addr << endl;
}

VOID before_inst_with_written_mem(ADDRINT mem_addr) {
  cout << "\twritten mem: " << hex << mem_addr << endl;
}

VOID inst_instrument(INS inst, VOID *v) {
  cout << "0x" << hex << INS_Address(inst) << ": " << INS_Disassemble(inst) << endl;
    
  uint32_t regR_num = INS_MaxNumRRegs(inst);
  for(uint32_t i = 0; i < regR_num ; ++i) {
    // cout << "\tread reg: " << REG_StringShort(INS_RegR(inst, i)) << endl;
    if(REG_valid(INS_RegR(inst, i))) {
      INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst_with_read_reg, IARG_ADDRINT, INS_RegR(inst, i), IARG_CONTEXT, IARG_END);
    }
  }

  uint32_t regW_num = INS_MaxNumWRegs(inst);
  for(uint32_t i = 0; i < regW_num ; ++i) {
    INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst_with_written_reg, IARG_ADDRINT, INS_RegW(inst, i), IARG_CONTEXT, IARG_END);
  }
  
  if(INS_IsMemoryRead(inst)) {
    INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst_with_read_mem, IARG_MEMORYREAD_EA, IARG_END);
  }
  if(INS_HasMemoryRead2(inst)) {
    INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst_with_read_mem, IARG_MEMORYREAD2_EA, IARG_END);
  }
  if(INS_IsMemoryWrite(inst)) {
    INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst_with_written_mem, IARG_MEMORYWRITE_EA, IARG_END);
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
