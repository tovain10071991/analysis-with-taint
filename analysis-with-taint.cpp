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

inline void init_taint_mem() {
  system("fallocate -n -l 8G taint_mem_file");  
}

inline void set_taint_mem(ADDRINT mem_addr, ADDRINT mem_size) {
  lseek(taint_mem_fd, mem_addr, SEEK_SET);
  char flag = 1;
  for(ADDRINT i = 0; i < mem_size; ++i) {
    write(taint_mem_fd, &flag, 1);
  }
}

inline void reset_taint_mem(ADDRINT mem_addr, ADDRINT mem_size) {
  lseek(taint_mem_fd, mem_addr, SEEK_SET);
  char flag = 0;
  for(ADDRINT i = 0; i < mem_size; ++i) {
    write(taint_mem_fd, &flag, 1);
  }
}

inline void set_taint_reg(REG reg) {
  taint_reg_set[reg] = true;
}

inline void reset_taint_reg(REG reg) {
  taint_reg_set[reg] = false;
}

inline void propagate_taint(REG src_reg, REG des_reg) {
  assert(REG_Size(src_reg) == REG_Size(des_reg));
}

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
    
    set_taint_mem(mem_addr, mem_size);
  }
}

VOID before_inst(ADDRINT inst_addr, ADDRINT read_reg_id_1, ADDRINT read_reg_id_2, ADDRINT read_reg_id_3, ADDRINT read_reg_id_4, ADDRINT read_reg_id_5, ADDRINT read_reg_id_6, ADDRINT written_reg_id_1, ADDRINT written_reg_id_2, ADDRINT written_reg_id_3, ADDRINT written_reg_id_4, ADDRINT written_reg_id_5, ADDRINT written_reg_id_6, BOOL have_read_mem_1, ADDRINT read_mem_addr_1, BOOL have_read_mem_2, ADDRINT read_mem_addr_2, BOOL have_written_mem, ADDRINT written_mem_addr, CONTEXT* ctxt) {
  REG read_reg[6] = {(REG)read_reg_id_1, (REG)read_reg_id_2, (REG)read_reg_id_3, (REG)read_reg_id_4, (REG)read_reg_id_5, (REG)read_reg_id_6};
  REG written_reg[6] = {(REG)written_reg_id_1, (REG)written_reg_id_2, (REG)written_reg_id_3, (REG)written_reg_id_4, (REG)written_reg_id_5, (REG)written_reg_id_6};
  
  cout << "0x" << hex << inst_addr << endl;
  
  for(int i = 0; i < 6; ++i) {
    if(!REG_valid(read_reg[i])) {
      continue;
    }
    cout << "\tread reg: " << REG_StringShort(read_reg[i]) << endl;
    cout << "\t\t";
    UINT8 val_buf[512];
    UINT32 reg_size = REG_Size(read_reg[i]);
    PIN_GetContextRegval(ctxt, read_reg[i], val_buf);
    cout << hex;
    for(UINT32 i = 0; i < reg_size; ++i) {
      cout << " " << int(val_buf[i]);
    }
    cout << endl;
  }
  
  for(int i = 0; i < 6; ++i) {
    if(!REG_valid(written_reg[i])) {
      continue;
    }
    cout << "\twritten reg: " << REG_StringShort(written_reg[i]) << endl;
    cout << "\t\t";
    UINT8 val_buf[512];
    UINT32 reg_size = REG_Size(written_reg[i]);
    PIN_GetContextRegval(ctxt, written_reg[i], val_buf);
    cout << hex;
    for(UINT32 i = 0; i < reg_size; ++i) {
      cout << " " << int(val_buf[i]);
    }
    cout << endl;
  }
  
  if(have_read_mem_1) {
    cout << "\tread mem: " << hex << read_mem_addr_1 << endl;
  }
  if(have_read_mem_2) {
    cout << "\tread mem: " << hex << read_mem_addr_2 << endl;
  }
  if(have_written_mem) {
    cout << "\twritten mem: " << hex << written_mem_addr << endl;
  }
}

VOID before_inst_with_read_reg(ADDRINT inst_addr, ADDRINT reg_id, CONTEXT* ctxt) {
  REG reg = (REG)reg_id;
  cout << "0x" << hex << inst_addr << endl << "\tread reg: " << REG_StringShort(reg) << endl;
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

VOID before_inst_with_written_reg(ADDRINT inst_addr, ADDRINT reg_id, CONTEXT* ctxt) {
  REG reg = (REG)reg_id;
  cout << "0x" << hex << inst_addr << endl << "\twritten reg: " << REG_StringShort(reg) << endl;
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

VOID before_inst_with_read_mem(ADDRINT inst_addr, ADDRINT mem_addr) {
  cout << "0x" << hex << inst_addr << endl << "\tread mem: " << hex << mem_addr << endl;
}

VOID before_inst_with_written_mem(ADDRINT inst_addr, ADDRINT mem_addr) {
  cout << "0x" << hex << inst_addr << endl << "\twritten mem: " << hex << mem_addr << endl;
}

VOID inst_instrument(INS inst, VOID *v) {
  cout << "0x" << hex << INS_Address(inst) << ": " << INS_Disassemble(inst) << endl;
  
  ADDRINT read_reg_id[6] = {0};
  ADDRINT written_reg_id[6] = {0};

  bool have_read_mem_1 = false, have_read_mem_2 = false, have_written_mem = false;
    
  uint32_t regR_num = INS_MaxNumRRegs(inst);
  assert(regR_num <= 6);
  for(uint32_t i = 0; i < regR_num ; ++i) {
    // cout << "\tread reg: " << REG_StringShort(INS_RegR(inst, i)) << endl;
    // if(REG_valid(INS_RegR(inst, i))) {
    read_reg_id[i] = INS_RegR(inst, i);
      // INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst_with_read_reg, IARG_INST_PTR, IARG_ADDRINT, INS_RegR(inst, i), IARG_CONTEXT, IARG_END);
    // }
  }

  if(INS_IsMemoryRead(inst)) {
    cout << "have read mem 1" << endl;
    have_read_mem_1 = true;
    // INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst_with_read_mem, IARG_INST_PTR, IARG_MEMORYREAD_EA, IARG_END);
  }
  if(INS_HasMemoryRead2(inst)) {
    cout << "have read mem 2" << endl;
    have_read_mem_2 = true;
    // INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst_with_read_mem, IARG_INST_PTR, IARG_MEMORYREAD2_EA, IARG_END);
  }

  uint32_t regW_num = INS_MaxNumWRegs(inst);
  assert(regW_num <= 6);
  for(uint32_t i = 0; i < regW_num ; ++i) {
    written_reg_id[i] = INS_RegW(inst, i);
    // INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst_with_written_reg, IARG_INST_PTR, IARG_ADDRINT, INS_RegW(inst, i), IARG_CONTEXT, IARG_END);
  }
  
  if(INS_IsMemoryWrite(inst)) {
    cout << "have written mem" << endl;
    have_written_mem = true;
    // INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst_with_written_mem, IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_END);
  }
  
  if(have_read_mem_1 == true) {
    if(have_read_mem_2 == true) {
      if(have_written_mem == true) {
        INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst, IARG_INST_PTR, IARG_ADDRINT, read_reg_id[0], IARG_ADDRINT, read_reg_id[1], IARG_ADDRINT, read_reg_id[2], IARG_ADDRINT, read_reg_id[3], IARG_ADDRINT, read_reg_id[4], IARG_ADDRINT, read_reg_id[5], IARG_ADDRINT, written_reg_id[0], IARG_ADDRINT, written_reg_id[1], IARG_ADDRINT, written_reg_id[2], IARG_ADDRINT, written_reg_id[3], IARG_ADDRINT, written_reg_id[4], IARG_ADDRINT, written_reg_id[5], IARG_BOOL, have_read_mem_1, IARG_MEMORYREAD_EA, IARG_BOOL, have_read_mem_2, IARG_MEMORYREAD2_EA, IARG_BOOL, have_written_mem, IARG_MEMORYWRITE_EA, IARG_CONTEXT, IARG_END);
      }
      else {
        INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst, IARG_INST_PTR, IARG_ADDRINT, read_reg_id[0], IARG_ADDRINT, read_reg_id[1], IARG_ADDRINT, read_reg_id[2], IARG_ADDRINT, read_reg_id[3], IARG_ADDRINT, read_reg_id[4], IARG_ADDRINT, read_reg_id[5], IARG_ADDRINT, written_reg_id[0], IARG_ADDRINT, written_reg_id[1], IARG_ADDRINT, written_reg_id[2], IARG_ADDRINT, written_reg_id[3], IARG_ADDRINT, written_reg_id[4], IARG_ADDRINT, written_reg_id[5], IARG_BOOL, have_read_mem_1, IARG_MEMORYREAD_EA, IARG_BOOL, have_read_mem_2, IARG_MEMORYREAD2_EA, IARG_BOOL, have_written_mem, IARG_ADDRINT, 0, IARG_CONTEXT, IARG_END);
      }
    }
    else {
      if(have_written_mem == true) {
        INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst, IARG_INST_PTR, IARG_ADDRINT, read_reg_id[0], IARG_ADDRINT, read_reg_id[1], IARG_ADDRINT, read_reg_id[2], IARG_ADDRINT, read_reg_id[3], IARG_ADDRINT, read_reg_id[4], IARG_ADDRINT, read_reg_id[5], IARG_ADDRINT, written_reg_id[0], IARG_ADDRINT, written_reg_id[1], IARG_ADDRINT, written_reg_id[2], IARG_ADDRINT, written_reg_id[3], IARG_ADDRINT, written_reg_id[4], IARG_ADDRINT, written_reg_id[5], IARG_BOOL, have_read_mem_1, IARG_MEMORYREAD_EA, IARG_BOOL, have_read_mem_2, IARG_ADDRINT, 0, IARG_BOOL, have_written_mem, IARG_MEMORYWRITE_EA, IARG_CONTEXT, IARG_END);
      }
      else {
        INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst, IARG_INST_PTR, IARG_ADDRINT, read_reg_id[0], IARG_ADDRINT, read_reg_id[1], IARG_ADDRINT, read_reg_id[2], IARG_ADDRINT, read_reg_id[3], IARG_ADDRINT, read_reg_id[4], IARG_ADDRINT, read_reg_id[5], IARG_ADDRINT, written_reg_id[0], IARG_ADDRINT, written_reg_id[1], IARG_ADDRINT, written_reg_id[2], IARG_ADDRINT, written_reg_id[3], IARG_ADDRINT, written_reg_id[4], IARG_ADDRINT, written_reg_id[5], IARG_BOOL, have_read_mem_1, IARG_MEMORYREAD_EA, IARG_BOOL, have_read_mem_2, IARG_ADDRINT, 0, IARG_BOOL, have_written_mem, IARG_ADDRINT, 0, IARG_CONTEXT, IARG_END);
      }
    }
  }
  else {
    if(have_written_mem == true) {
      INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst, IARG_INST_PTR, IARG_ADDRINT, read_reg_id[0], IARG_ADDRINT, read_reg_id[1], IARG_ADDRINT, read_reg_id[2], IARG_ADDRINT, read_reg_id[3], IARG_ADDRINT, read_reg_id[4], IARG_ADDRINT, read_reg_id[5], IARG_ADDRINT, written_reg_id[0], IARG_ADDRINT, written_reg_id[1], IARG_ADDRINT, written_reg_id[2], IARG_ADDRINT, written_reg_id[3], IARG_ADDRINT, written_reg_id[4], IARG_ADDRINT, written_reg_id[5], IARG_BOOL, have_read_mem_1, IARG_ADDRINT, 0, IARG_BOOL, have_read_mem_2, IARG_ADDRINT, 0, IARG_BOOL, have_written_mem, IARG_MEMORYWRITE_EA, IARG_CONTEXT, IARG_END);
    }
    else {
      INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst, IARG_INST_PTR, IARG_ADDRINT, read_reg_id[0], IARG_ADDRINT, read_reg_id[1], IARG_ADDRINT, read_reg_id[2], IARG_ADDRINT, read_reg_id[3], IARG_ADDRINT, read_reg_id[4], IARG_ADDRINT, read_reg_id[5], IARG_ADDRINT, written_reg_id[0], IARG_ADDRINT, written_reg_id[1], IARG_ADDRINT, written_reg_id[2], IARG_ADDRINT, written_reg_id[3], IARG_ADDRINT, written_reg_id[4], IARG_ADDRINT, written_reg_id[5], IARG_BOOL, have_read_mem_1, IARG_ADDRINT, 0, IARG_BOOL, have_read_mem_2, IARG_ADDRINT, 0, IARG_BOOL, have_written_mem, IARG_ADDRINT, 0, IARG_CONTEXT, IARG_END);
    }
  }
}

int main(int argc, char *argv[]) {
  // init_ignore_syscall_set();
  init_sensitive_syscall_set();

  init_taint_mem();

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
