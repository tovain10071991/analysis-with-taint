#include "pin.H"
#include <iostream>
#include <bitset>
#include <set>
#include <vector>
#include <map>
#include <memory>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

using namespace std;

// #include "syscall_num.inc"
#include "syscall_num_sensitive.inc"
#include "reg_to_full.inc"

map<ADDRINT, ADDRINT> taint_mem_set;
map<REG, vector<bool> > taint_reg_set;

void init_taint_mem() {
  taint_mem_set.insert(make_pair(0 ,0));
}

void set_taint_mem(ADDRINT mem_addr, ADDRINT mem_size, bool flag) {
  cout << "\tset taint mem: " << mem_addr << " + " << mem_size << " - " << flag << endl;
  map<ADDRINT, ADDRINT>::iterator iter = taint_mem_set.begin();
  map<ADDRINT, ADDRINT>::iterator pre_iter = taint_mem_set.begin();
  for(; iter != taint_mem_set.end(); ++iter) {
    if(iter->first > mem_addr) {
      break;
    }
    pre_iter = iter;
  }
  if(flag) {
    if(iter == taint_mem_set.end() || iter->first > mem_addr + mem_size) {
      if(pre_iter->second < mem_addr) {
        taint_mem_set.insert(make_pair(mem_addr, mem_addr + mem_size));        
      }
      else {
        pre_iter->second = mem_addr + mem_size;
      }
    }
    else {
      if(pre_iter->second < mem_addr) {
        ADDRINT mem_end = iter->second;
        taint_mem_set.erase(iter);
        taint_mem_set.insert(make_pair(mem_addr, mem_end));
      }
      else {
        ADDRINT mem_end = iter->second;
        taint_mem_set.erase(iter);
        pre_iter->second = mem_end;
      }
    }
  }
  else {
    if(pre_iter->second > mem_addr) {
      pre_iter->second = mem_addr;
    }
    if(iter != taint_mem_set.end() && iter->first < mem_addr + mem_size) {
      ADDRINT mem_end = iter->second;
      taint_mem_set.erase(iter);
      taint_mem_set.insert(make_pair(mem_addr + mem_size, mem_end));
    }
  }
}

bool get_taint_mem(ADDRINT mem_addr, ADDRINT mem_size) {
  map<ADDRINT, ADDRINT>::iterator iter = taint_mem_set.begin();
  map<ADDRINT, ADDRINT>::iterator pre_iter = taint_mem_set.begin();
  for(; iter != taint_mem_set.end(); ++iter) {
    if(iter->first > mem_addr) {
      break;
    }
    pre_iter = iter;
  }
  if(pre_iter->second > mem_addr) {
    return true;
  }
  if(iter != taint_mem_set.end() && iter->first < mem_addr + mem_size) {
    return true;
  }
  return false;
}

void set_taint_reg(REG reg, bool flag) {
  cout << "\tset taint reg: " << REG_StringShort(reg) << " - " << flag << endl;  
  REG full_reg = REG_FullRegName(reg);
  uint32_t off = 0;
  if(reg_to_full.find(reg) != reg_to_full.end()) {
    off = reg_to_full[reg];
  }
  if(taint_reg_set.find(full_reg) == taint_reg_set.end()) {
    taint_reg_set[full_reg] = vector<bool>(REG_Size(full_reg), false);
  }
  for(uint32_t i = 0; i < REG_Size(reg); ++i) {
    taint_reg_set[full_reg][off + i] = flag;
  }
}

bool get_taint_reg(REG reg) {
  REG full_reg = REG_FullRegName(reg);
  uint32_t off = 0;
  if(reg_to_full.find(reg) != reg_to_full.end()) {
    off = reg_to_full[reg];
  }
  if(taint_reg_set.find(full_reg) == taint_reg_set.end()) {
    taint_reg_set[full_reg] = vector<bool>(REG_Size(full_reg), false);
  }
  for(uint32_t i = 0; i < REG_Size(reg); ++i) {
    if(taint_reg_set[full_reg][off + i]) {
      return true;
    }
  }
  return false;
}

void propagate_taint(vector<REG> src_reg_set, vector<REG> des_reg_set, vector<pair<ADDRINT, UINT32> > src_mem_set, vector<pair<ADDRINT, UINT32> > des_mem_set) {
  bool is_tainted = false;
  for(vector<REG>::iterator iter = src_reg_set.begin(); iter != src_reg_set.end(); ++iter) {
    if(get_taint_reg(*iter)) {
      is_tainted = true;
      break;
    }
  }
  if(!is_tainted) {
    for(vector<pair<ADDRINT, UINT32> >::iterator iter = src_mem_set.begin(); iter != src_mem_set.end(); ++iter) {
      if(get_taint_mem(iter->first, iter->second)) {
        is_tainted = true;
        break;
      }
    }
  }
  for(vector<REG>::iterator iter = des_reg_set.begin(); iter != des_reg_set.end(); ++iter) {
    set_taint_reg(*iter, is_tainted);
  }
  for(vector<pair<ADDRINT, UINT32> >::iterator iter = des_mem_set.begin(); iter != des_mem_set.end(); ++iter) {
    set_taint_mem(iter->first, iter->second, is_tainted);
  }
}

KNOB<uint64_t> StartAddr(KNOB_MODE_WRITEONCE, "pintool", "s", "0", "start address");
KNOB<uint64_t> EndAddr(KNOB_MODE_WRITEONCE, "pintool", "e", "0", "end address");

INT32 Usage() {
    cerr << "This tool analysis indirect branch with taint propagate" << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

void syscall_entry(THREADID tid, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* v) {
  ADDRINT syscall_num = PIN_GetSyscallNumber(ctxt, std);
  cout << "===syscall entry===" << endl << "syscall num: " << syscall_num << endl;
  // if(ignore_syscall_set.find(syscall_num) != ignore_syscall_set.end())
  if(sensitive_syscall_set.find(syscall_num) == sensitive_syscall_set.end())
    return;
  if(PIN_GetSyscallArgument(ctxt, std, 0) == 0) {
    ADDRINT mem_addr = PIN_GetSyscallArgument(ctxt, std, 1);
    ADDRINT mem_size = PIN_GetSyscallArgument(ctxt, std, 2);
    
    set_taint_mem(mem_addr, mem_size, true);
  }
}

VOID before_inst(ADDRINT inst_addr, ADDRINT read_reg_id_1, ADDRINT read_reg_id_2, ADDRINT read_reg_id_3, ADDRINT read_reg_id_4, ADDRINT read_reg_id_5, ADDRINT read_reg_id_6, ADDRINT written_reg_id_1, ADDRINT written_reg_id_2, ADDRINT written_reg_id_3, ADDRINT written_reg_id_4, ADDRINT written_reg_id_5, ADDRINT written_reg_id_6, BOOL have_read_mem_1, ADDRINT read_mem_addr_1, UINT32 read_mem_size_1, BOOL have_read_mem_2, ADDRINT read_mem_addr_2, UINT32 read_mem_size_2, BOOL have_written_mem, ADDRINT written_mem_addr, UINT32 written_mem_size, CONTEXT* ctxt) {
  REG read_reg[6] = {(REG)read_reg_id_1, (REG)read_reg_id_2, (REG)read_reg_id_3, (REG)read_reg_id_4, (REG)read_reg_id_5, (REG)read_reg_id_6};
  REG written_reg[6] = {(REG)written_reg_id_1, (REG)written_reg_id_2, (REG)written_reg_id_3, (REG)written_reg_id_4, (REG)written_reg_id_5, (REG)written_reg_id_6};
  
  cout << "0x" << hex << inst_addr << endl;
  
  vector<REG> read_reg_set, written_reg_set;
  vector<pair<ADDRINT, UINT32> > read_mem_set, written_mem_set;
  
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
    
    read_reg_set.push_back(read_reg[i]);
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
    
    written_reg_set.push_back(written_reg[i]);
  }
  
  if(have_read_mem_1) {
    cout << "\tread mem: " << hex << read_mem_addr_1 << endl;
    read_mem_set.push_back(make_pair(read_mem_addr_1, read_mem_size_1));
  }
  if(have_read_mem_2) {
    cout << "\tread mem: " << hex << read_mem_addr_2 << endl;
    read_mem_set.push_back(make_pair(read_mem_addr_2, read_mem_size_2));    
  }
  if(have_written_mem) {
    cout << "\twritten mem: " << hex << written_mem_addr << endl;
    written_mem_set.push_back(make_pair(written_mem_addr, written_mem_size));
  }
  
  propagate_taint(read_reg_set, written_reg_set, read_mem_set, written_mem_set);
}

VOID inst_instrument(INS inst, VOID *v) {
  cout << "0x" << hex << INS_Address(inst) << ": " << INS_Disassemble(inst) << endl;
  
  ADDRINT read_reg_id[6] = {0};
  ADDRINT written_reg_id[6] = {0};

  bool have_read_mem_1 = false, have_read_mem_2 = false, have_written_mem = false;
    
  uint32_t regR_num = INS_MaxNumRRegs(inst);
  assert(regR_num <= 6);
  for(uint32_t i = 0; i < regR_num ; ++i) {
    read_reg_id[i] = INS_RegR(inst, i);
  }

  if(INS_IsMemoryRead(inst)) {
    cout << "have read mem 1" << endl;
    have_read_mem_1 = true;
  }
  if(INS_HasMemoryRead2(inst)) {
    cout << "have read mem 2" << endl;
    have_read_mem_2 = true;
  }

  uint32_t regW_num = INS_MaxNumWRegs(inst);
  assert(regW_num <= 6);
  for(uint32_t i = 0; i < regW_num ; ++i) {
    written_reg_id[i] = INS_RegW(inst, i);
  }
  
  if(INS_IsMemoryWrite(inst)) {
    cout << "have written mem" << endl;
    have_written_mem = true;
  }
  
  if(have_read_mem_1 == true) {
    if(have_read_mem_2 == true) {
      if(have_written_mem == true) {
        INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst, IARG_INST_PTR, IARG_ADDRINT, read_reg_id[0], IARG_ADDRINT, read_reg_id[1], IARG_ADDRINT, read_reg_id[2], IARG_ADDRINT, read_reg_id[3], IARG_ADDRINT, read_reg_id[4], IARG_ADDRINT, read_reg_id[5], IARG_ADDRINT, written_reg_id[0], IARG_ADDRINT, written_reg_id[1], IARG_ADDRINT, written_reg_id[2], IARG_ADDRINT, written_reg_id[3], IARG_ADDRINT, written_reg_id[4], IARG_ADDRINT, written_reg_id[5], IARG_BOOL, have_read_mem_1, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_BOOL, have_read_mem_2, IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, IARG_BOOL, have_written_mem, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_EA, IARG_CONTEXT, IARG_END);
      }
      else {
        INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst, IARG_INST_PTR, IARG_ADDRINT, read_reg_id[0], IARG_ADDRINT, read_reg_id[1], IARG_ADDRINT, read_reg_id[2], IARG_ADDRINT, read_reg_id[3], IARG_ADDRINT, read_reg_id[4], IARG_ADDRINT, read_reg_id[5], IARG_ADDRINT, written_reg_id[0], IARG_ADDRINT, written_reg_id[1], IARG_ADDRINT, written_reg_id[2], IARG_ADDRINT, written_reg_id[3], IARG_ADDRINT, written_reg_id[4], IARG_ADDRINT, written_reg_id[5], IARG_BOOL, have_read_mem_1, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_BOOL, have_read_mem_2, IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, IARG_BOOL, have_written_mem, IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_CONTEXT, IARG_END);
      }
    }
    else {
      if(have_written_mem == true) {
        INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst, IARG_INST_PTR, IARG_ADDRINT, read_reg_id[0], IARG_ADDRINT, read_reg_id[1], IARG_ADDRINT, read_reg_id[2], IARG_ADDRINT, read_reg_id[3], IARG_ADDRINT, read_reg_id[4], IARG_ADDRINT, read_reg_id[5], IARG_ADDRINT, written_reg_id[0], IARG_ADDRINT, written_reg_id[1], IARG_ADDRINT, written_reg_id[2], IARG_ADDRINT, written_reg_id[3], IARG_ADDRINT, written_reg_id[4], IARG_ADDRINT, written_reg_id[5], IARG_BOOL, have_read_mem_1, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_BOOL, have_read_mem_2, IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_BOOL, have_written_mem, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_CONTEXT, IARG_END);
      }
      else {
        INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst, IARG_INST_PTR, IARG_ADDRINT, read_reg_id[0], IARG_ADDRINT, read_reg_id[1], IARG_ADDRINT, read_reg_id[2], IARG_ADDRINT, read_reg_id[3], IARG_ADDRINT, read_reg_id[4], IARG_ADDRINT, read_reg_id[5], IARG_ADDRINT, written_reg_id[0], IARG_ADDRINT, written_reg_id[1], IARG_ADDRINT, written_reg_id[2], IARG_ADDRINT, written_reg_id[3], IARG_ADDRINT, written_reg_id[4], IARG_ADDRINT, written_reg_id[5], IARG_BOOL, have_read_mem_1, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_BOOL, have_read_mem_2, IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_BOOL, have_written_mem, IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_CONTEXT, IARG_END);
      }
    }
  }
  else {
    if(have_written_mem == true) {
      INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst, IARG_INST_PTR, IARG_ADDRINT, read_reg_id[0], IARG_ADDRINT, read_reg_id[1], IARG_ADDRINT, read_reg_id[2], IARG_ADDRINT, read_reg_id[3], IARG_ADDRINT, read_reg_id[4], IARG_ADDRINT, read_reg_id[5], IARG_ADDRINT, written_reg_id[0], IARG_ADDRINT, written_reg_id[1], IARG_ADDRINT, written_reg_id[2], IARG_ADDRINT, written_reg_id[3], IARG_ADDRINT, written_reg_id[4], IARG_ADDRINT, written_reg_id[5], IARG_BOOL, have_read_mem_1, IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_BOOL, have_read_mem_2, IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_BOOL, have_written_mem, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_CONTEXT, IARG_END);
    }
    else {
      INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst, IARG_INST_PTR, IARG_ADDRINT, read_reg_id[0], IARG_ADDRINT, read_reg_id[1], IARG_ADDRINT, read_reg_id[2], IARG_ADDRINT, read_reg_id[3], IARG_ADDRINT, read_reg_id[4], IARG_ADDRINT, read_reg_id[5], IARG_ADDRINT, written_reg_id[0], IARG_ADDRINT, written_reg_id[1], IARG_ADDRINT, written_reg_id[2], IARG_ADDRINT, written_reg_id[3], IARG_ADDRINT, written_reg_id[4], IARG_ADDRINT, written_reg_id[5], IARG_BOOL, have_read_mem_1, IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_BOOL, have_read_mem_2, IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_BOOL, have_written_mem, IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_CONTEXT, IARG_END);
    }
  }
}

int main(int argc, char *argv[]) {
  // init_ignore_syscall_set();
  init_sensitive_syscall_set();

  init_taint_mem();
  init_reg_to_full();

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
