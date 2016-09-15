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

typedef struct mem_info_t {
  REG segmentReg;
  REG baseReg;
  REG indexReg;
  uint32_t scale;
  uint32_t disp;
} mem_info_t;

typedef struct access_info_t {
  vector<mem_info_t> read_mem_set;
  vector<mem_info_t> written_mem_set;
  vector<REG> read_reg_set;
  vector<REG> written_reg_set;
} access_info_t;

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


VOID inst_instrument(INS inst, VOID *v) {
  cout << "0x" << hex << INS_Address(inst) << ": " << INS_Disassemble(inst) << endl;
  
  auto_ptr<access_info_t> access_info(new access_info_t);
  
  uint32_t regR_num = INS_MaxNumRRegs(inst);
  for(uint32_t i = 0; i < regR_num ; ++i) {
    access_info->read_reg_set.push_back(INS_RegR(inst, i));
  }

  uint32_t regW_num = INS_MaxNumWRegs(inst);
  for(uint32_t i = 0; i < regW_num ; ++i) {
    access_info->written_reg_set.push_back(INS_RegW(inst, i));
  }
  
  uint32_t opr_count = INS_OperandCount(inst);
  for(uint32_t i = 0; i < opr_count; ++i) {
    if(INS_OperandIsMemory(inst, i)) {
      REG segmentReg = INS_OperandMemorySegmentReg(inst, i);
      REG baseReg = INS_OperandMemoryBaseReg(inst, i);
      REG indexReg = INS_OperandMemoryIndexReg(inst, i);
      uint32_t scale = INS_OperandMemoryScale(inst, i);
      uint32_t disp = INS_OperandMemoryDisplacement(inst, i);
      if(INS_OperandRead(i)) {
        access_info->read_mem_set.push_back({segmentReg, baseReg, indexReg, scale, disp});
      }
      if(INS_OperandWritten(i)) {
        access_info->written_mem_set.push_back({segmentReg, baseReg, indexReg, scale, disp});
      }
    }
  }
  
//  insertCall(inst, IPOINT_BEFORE, before_inst, IARG_PTR, access_info);
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
