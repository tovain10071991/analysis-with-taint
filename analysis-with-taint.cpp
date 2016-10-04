#include "pin.H"
extern "C" {
#include "../../../extras/xed-intel64/include/xed-interface.h"
}

#include <iostream>
#include <bitset>
#include <set>
#include <vector>
#include <list>
#include <map>
#include <string>
#include <sstream>
#include <memory>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <openssl/md5.h>

using namespace std;

// #include "syscall_num.inc"
#include "syscall_num_sensitive.inc"
#include "reg_to_full.inc"

map<ADDRINT, ADDRINT> taint_mem_set;
map<REG, vector<bool> > taint_reg_set;

#define HASH_PROG "/home/user/Documents/test/compute_hash_for_pin/compute_hash_for_pin"
#define HASH_FIFO "/home/user/Documents/test/compute_hash_for_pin/hash.fifo"
#define COMPUTE_CMD 0xc
#define TERMINATE_CMD 0xf
int hash_req;
int hash_pid;

void init_taint_mem() {
  taint_mem_set.insert(make_pair(0 ,0));
  taint_mem_set.insert(make_pair(0xffffffffffffffff ,0xffffffffffffffff));
}

void set_taint_mem(ADDRINT mem_addr, ADDRINT mem_size, bool flag) {
#ifdef DEBUG
  cout << "\tset taint mem: 0x" << hex << mem_addr << " + 0x" << mem_size << " - " << flag << endl;
#endif
  map<ADDRINT, ADDRINT>::iterator iter = taint_mem_set.begin();
  map<ADDRINT, ADDRINT>::iterator pre_iter = taint_mem_set.begin();
  ADDRINT mem_end = mem_addr + mem_size;
  for(; iter != taint_mem_set.end(); ++iter) {
    if(iter->first > mem_addr) {
      break;
    }
    pre_iter = iter;
  }
#ifdef DEBUG
  cout << "pre_iter: 0x" << pre_iter->first << " ~ 0x" << pre_iter->second << endl;
  cout << "iter: 0x" << iter->first << " ~ 0x" << iter->second << endl;
#endif
  if(flag) {
    if(mem_addr >= pre_iter->first && mem_end <= pre_iter->second) {
    }
    else if(mem_addr <= pre_iter->second && mem_end > pre_iter->second && mem_end < iter->first) {
      pre_iter->second = mem_end;
    }
    else if(mem_addr <= pre_iter->second && mem_end >= iter->first && mem_end <= iter->second) {
      pre_iter->second = iter->second;
      taint_mem_set.erase(iter);
    }
    else if(mem_addr <= pre_iter->second && mem_end > iter->second) {
      pre_iter->second = mem_end;
      taint_mem_set.erase(iter);
    }
    else if(mem_addr > pre_iter->second && mem_end < iter->first) {
      taint_mem_set.insert(make_pair(mem_addr, mem_end));
    }
    else if(mem_addr > pre_iter->second && mem_end >= iter->first && mem_end <= iter->second) {
      ADDRINT temp_mem_addr = mem_addr;
      ADDRINT temp_mem_end = iter->second;
      taint_mem_set.erase(iter);
      taint_mem_set.insert(make_pair(temp_mem_addr, temp_mem_end));
    }
    else if(mem_addr > pre_iter->second && mem_end > iter->second) {
      taint_mem_set.erase(iter);
      taint_mem_set.insert(make_pair(mem_addr, mem_end));
    }
    else {
      assert(0 && "unreachable");
    }
  }
  else {
    if(mem_addr == pre_iter->first &&  mem_end < pre_iter->second) {
      ADDRINT temp_mem_addr = mem_end;
      ADDRINT temp_mem_end = pre_iter->second;
      taint_mem_set.erase(pre_iter);
      taint_mem_set.insert(make_pair(temp_mem_addr, temp_mem_end));
    }
    else if(mem_addr == pre_iter->first && mem_end >= pre_iter->second &&  mem_end <= iter->first) {
      taint_mem_set.erase(pre_iter);
    }
    else if(mem_addr == pre_iter->first && mem_end > iter->first && mem_end < iter->second) {
      ADDRINT temp_mem_addr = mem_end;
      ADDRINT temp_mem_end = iter->second;
      ADDRINT iter_mem_addr = iter->first;
      taint_mem_set.erase(pre_iter);
      iter = taint_mem_set.find(iter_mem_addr);
      taint_mem_set.erase(iter);
      taint_mem_set.insert(make_pair(temp_mem_addr, temp_mem_end));
    }
    else if(mem_addr == pre_iter->first && mem_end >= iter->second) {
      ADDRINT iter_mem_addr = iter->first;
      taint_mem_set.erase(pre_iter);
      iter = taint_mem_set.find(iter_mem_addr);
      taint_mem_set.erase(iter);
    }
    else if(mem_addr > pre_iter->first && mem_end < pre_iter->second) {
      ADDRINT temp_mem_addr = mem_end;
      ADDRINT temp_mem_end = pre_iter->second;
      pre_iter->second = mem_addr;
      taint_mem_set.insert(make_pair(temp_mem_addr, temp_mem_end));
    }
    else if(mem_addr > pre_iter->first && mem_addr < pre_iter->second && mem_end >= pre_iter->second && mem_end <= iter->first) {
      pre_iter->second = mem_addr;
    }
    else if(mem_addr > pre_iter->first && mem_addr < pre_iter->second && mem_end > iter->first && mem_end < iter->second) {
      pre_iter->second = mem_addr;
      ADDRINT temp_mem_end = iter->second;
      ADDRINT temp_mem_addr = mem_end;
      taint_mem_set.erase(iter);
      taint_mem_set.insert(make_pair(temp_mem_addr, temp_mem_end));
    }
    else if(mem_addr > pre_iter->first && mem_addr < pre_iter->second && mem_end >= iter->second) {
      pre_iter->second = mem_addr;
      taint_mem_set.erase(iter);
    }
    else if(mem_addr >= pre_iter->second && mem_end <= iter->first) {
    }
    else if(mem_addr >= pre_iter->second && mem_end > iter->first && mem_end < iter->second) {
      ADDRINT temp_mem_addr = mem_end;
      ADDRINT temp_mem_end = iter->second;
      taint_mem_set.erase(iter);
      taint_mem_set.insert(make_pair(temp_mem_addr, temp_mem_end));
    }
    else if(mem_addr >= pre_iter->second && mem_end >= iter->second) {
      taint_mem_set.erase(iter);
    }
    else {
      assert(0 && "unreachable");
    }
  }
}

bool get_taint_mem(ADDRINT mem_addr, ADDRINT mem_size) {
#ifdef DEBUG
  cout << "get taint mem: 0x" << hex << mem_addr << " + 0x" << mem_size << endl;
#endif
  map<ADDRINT, ADDRINT>::iterator iter = taint_mem_set.begin();
  map<ADDRINT, ADDRINT>::iterator pre_iter = taint_mem_set.begin();
  for(; iter != taint_mem_set.end(); ++iter) {
    if(iter->first > mem_addr) {
      break;
    }
    pre_iter = iter;
  }
#ifdef DEBUG
  cout << "pre_iter: 0x" << pre_iter->first << " ~ 0x" << pre_iter->second << endl;
  cout << "iter: 0x" << iter->first << " ~ 0x" << iter->second << endl;
#endif
  if(pre_iter->second > mem_addr) {
    return true;
  }
  if(iter != taint_mem_set.end() && iter->first < mem_addr + mem_size) {
    return true;
  }
  return false;
}

void set_taint_reg(REG reg, bool flag) {
  REG full_reg = REG_FullRegName(reg);
  uint32_t off = 0;
  if(reg_to_full.find(reg) != reg_to_full.end()) {
    off = reg_to_full[reg];
  }
  if(taint_reg_set.find(full_reg) == taint_reg_set.end()) {
    taint_reg_set[full_reg] = vector<bool>(REG_Size(full_reg), false);
  }
  if(full_reg == REG_RFLAGS) {
    return;
  }
#ifdef DEBUG
  cout << "\tset taint reg: " << REG_StringShort(reg) << " - " << flag << endl;
#endif
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

void propagate_taint(vector<REG> src_reg_set, vector<REG> des_reg_set, set<REG> updated_reg_set, vector<pair<ADDRINT, UINT32> > src_mem_set, vector<pair<ADDRINT, UINT32> > des_mem_set, map<ADDRINT, UINT32> updated_mem_set) {
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
    if(updated_reg_set.find(*iter) == updated_reg_set.end()) {
      set_taint_reg(*iter, is_tainted);
    }
  }
  for(vector<pair<ADDRINT, UINT32> >::iterator iter = des_mem_set.begin(); iter != des_mem_set.end(); ++iter) {
    if(updated_mem_set.find(iter->first) == updated_mem_set.end()) {
      set_taint_mem(iter->first, iter->second, is_tainted);
    }
  }
}

KNOB<uint64_t> StartAddr(KNOB_MODE_WRITEONCE, "pintool", "s", "0", "start address");
KNOB<uint64_t> EndAddr(KNOB_MODE_WRITEONCE, "pintool", "e", "0", "end address");

INT32 Usage() {
    cerr << "This tool analysis indirect branch with taint propagate" << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

map<uint64_t, string> base_module_set;
map<uint64_t, uint64_t> base_high_set;

VOID load_image(IMG img, void* v) {
#ifdef DEBUG
  cout << "====load image====" << endl;
  cout << IMG_Name(img) << endl;
  cout << "load offset: " << hex << IMG_LoadOffset(img) << endl;
  cout << "low address: " << IMG_LowAddress(img) << endl;
  cout << "high address: " << IMG_HighAddress(img) << endl;
  cout << "start address: " << IMG_StartAddress(img) << endl;
  cout << "size mapped: " << IMG_SizeMapped(img) << endl;
#endif
  base_module_set.insert(make_pair(IMG_LoadOffset(img), IMG_Name(img)));
  base_high_set.insert(make_pair(IMG_LoadOffset(img), IMG_HighAddress(img)));
}

void syscall_entry(THREADID tid, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* v) {
  ADDRINT syscall_num = PIN_GetSyscallNumber(ctxt, std);
  // cout << "===syscall entry===" << endl << "syscall num: " << syscall_num << endl;
  // if(ignore_syscall_set.find(syscall_num) != ignore_syscall_set.end())
  if(sensitive_syscall_set.find(syscall_num) == sensitive_syscall_set.end())
    return;
  if(PIN_GetSyscallArgument(ctxt, std, 0) == 0) {
    ADDRINT mem_addr = PIN_GetSyscallArgument(ctxt, std, 1);
    ADDRINT mem_size = PIN_GetSyscallArgument(ctxt, std, 2);

    set_taint_mem(mem_addr, mem_size, true);
  }
}

void analysis_sematic(xed_iclass_enum_t opcode, vector<REG> read_reg_set, vector<REG> written_reg_set, set<REG>& updated_reg_set, vector<pair<ADDRINT, UINT32> > read_mem_set, vector<pair<ADDRINT, UINT32> > written_mem_set, map<ADDRINT, UINT32>& updated_mem_set) {
  if(opcode == XED_ICLASS_PXOR || opcode == XED_ICLASS_VPXOR || opcode == XED_ICLASS_VPXORD || opcode == XED_ICLASS_VPXORQ || opcode == XED_ICLASS_VXORPD || opcode == XED_ICLASS_VXORPS || opcode == XED_ICLASS_XOR || opcode == XED_ICLASS_XORPD || opcode == XED_ICLASS_XORPS || opcode == XED_ICLASS_XOR_LOCK)
  {
    if(read_reg_set.size() == 2) {
      if(read_reg_set[0] == read_reg_set[1]) {
        for(vector<REG>::iterator iter = written_reg_set.begin(); iter != written_reg_set.end(); ++iter) {
          set_taint_reg(*iter, false);
          updated_reg_set.insert(*iter);
        }
      }
    }
  }
  else if(opcode == XED_ICLASS_JMP && read_mem_set.empty() && read_reg_set.empty()) {
      set_taint_reg(REG_RIP, false);
      updated_reg_set.insert(REG_RIP);
  }
  else if(opcode >= XED_ICLASS_JB && opcode <= XED_ICLASS_JZ && read_mem_set.empty() && read_reg_set.size() == 2) {
      set_taint_reg(REG_RIP, false);
      updated_reg_set.insert(REG_RIP);
  }
  else if((opcode >= XED_ICLASS_PUSH && opcode <= XED_ICLASS_PUSHFQ) || (opcode >= XED_ICLASS_POP && opcode <= XED_ICLASS_POPFQ)) {
      set_taint_reg(REG_RSP, get_taint_reg(REG_RSP));
      updated_reg_set.insert(REG_RSP);
  }
}

void compute_hash(uint64_t inst_addr) {
  map<uint64_t, string>::iterator iter = base_module_set.begin();
  for(; iter != base_module_set.end(); ++iter) {
    if(inst_addr >= iter->first && inst_addr <= base_high_set[iter->first])
      break;
  }
  assert(iter != base_module_set.end());
  string module_base = iter->second;
  stringstream ss;
  string base_str;
  ss << hex << iter->first;
  ss >> base_str;
  module_base += base_str;

  uint8_t cmd = COMPUTE_CMD;
  write(hash_req, &cmd, 1);
  size_t len = module_base.size();
  write(hash_req, &len, sizeof(len));
  write(hash_req, module_base.c_str(), len);

#ifdef DEBUG
  cout << "str to be hashed: " << module_base << endl;
#endif
}

VOID before_inst(ADDRINT inst_addr, UINT64 opcode, ADDRINT read_reg_id_1, ADDRINT read_reg_id_2, ADDRINT read_reg_id_3, ADDRINT read_reg_id_4, ADDRINT read_reg_id_5, ADDRINT read_reg_id_6, ADDRINT written_reg_id_1, ADDRINT written_reg_id_2, ADDRINT written_reg_id_3, ADDRINT written_reg_id_4, ADDRINT written_reg_id_5, ADDRINT written_reg_id_6, BOOL have_read_mem_1, ADDRINT read_mem_addr_1, UINT32 read_mem_size_1, BOOL have_read_mem_2, ADDRINT read_mem_addr_2, UINT32 read_mem_size_2, BOOL have_written_mem, ADDRINT written_mem_addr, UINT32 written_mem_size, CONTEXT* ctxt, bool is_branch) {
  REG read_reg[6] = {(REG)read_reg_id_1, (REG)read_reg_id_2, (REG)read_reg_id_3, (REG)read_reg_id_4, (REG)read_reg_id_5, (REG)read_reg_id_6};
  REG written_reg[6] = {(REG)written_reg_id_1, (REG)written_reg_id_2, (REG)written_reg_id_3, (REG)written_reg_id_4, (REG)written_reg_id_5, (REG)written_reg_id_6};
#ifdef DEBUG
  cout << "0x" << hex << inst_addr << ": " << xed_iclass_enum_t2str((xed_iclass_enum_t)opcode) << endl;
#endif
  vector<REG> read_reg_set, written_reg_set;
  vector<pair<ADDRINT, UINT32> > read_mem_set, written_mem_set;

  for(int i = 0; i < 6; ++i) {
    if(!REG_valid(read_reg[i])) {
      continue;
    }
#ifdef DEBUG
    cout << "\tread reg: " << REG_StringShort(read_reg[i]) << endl;
    cout << "\t\t";
    UINT8 val_buf[512];
    UINT32 reg_size = REG_Size(read_reg[i]);
    PIN_GetContextRegval(ctxt, read_reg[i], val_buf);
    cout << hex;
    for(UINT32 j = 0; j < reg_size; ++j) {
      cout << " " << int(val_buf[j]);
    }
    cout << endl;
#endif
    read_reg_set.push_back(read_reg[i]);
  }

  for(int i = 0; i < 6; ++i) {
    if(!REG_valid(written_reg[i])) {
      continue;
    }
#ifdef DEBUG
    cout << "\twritten reg: " << REG_StringShort(written_reg[i]) << endl;
    cout << "\t\t";
    UINT8 val_buf[512];
    UINT32 reg_size = REG_Size(written_reg[i]);
    PIN_GetContextRegval(ctxt, written_reg[i], val_buf);
    cout << hex;
    for(UINT32 j = 0; j < reg_size; ++j) {
      cout << " " << int(val_buf[j]);
    }
    cout << endl;
#endif
    written_reg_set.push_back(written_reg[i]);
  }

  if(have_read_mem_1) {
#ifdef DEBUG
    cout << "\tread mem: " << hex << read_mem_addr_1 << endl;
#endif
    read_mem_set.push_back(make_pair(read_mem_addr_1, read_mem_size_1));
  }
  if(have_read_mem_2) {
#ifdef DEBUG
    cout << "\tread mem: " << hex << read_mem_addr_2 << endl;
#endif
    read_mem_set.push_back(make_pair(read_mem_addr_2, read_mem_size_2));
  }
  if(have_written_mem) {
#ifdef DEBUG
    cout << "\twritten mem: " << hex << written_mem_addr << endl;
#endif
    written_mem_set.push_back(make_pair(written_mem_addr, written_mem_size));
  }

  set<REG> updated_reg_set;
  map<ADDRINT, UINT32> updated_mem_set;
  analysis_sematic((xed_iclass_enum_t)opcode, read_reg_set, written_reg_set, updated_reg_set, read_mem_set, written_mem_set, updated_mem_set);
  propagate_taint(read_reg_set, written_reg_set, updated_reg_set, read_mem_set, written_mem_set, updated_mem_set);

  if(get_taint_reg(REG_RIP)) {
    cout << "maybe meet bug: 0x" << hex << inst_addr << endl;
    cerr << "maybe meet bug: 0x" << hex << inst_addr << endl;
    exit(-1);
  }

  // compute control flow hash in branch
  if(is_branch) {
#ifdef DEBUG
    cout << "it is branch" << endl;
#endif
    compute_hash(inst_addr);
  }
}

VOID inst_instrument(INS inst, VOID *v) {
#ifdef DEBUG
  cout << "0x" << hex << INS_Address(inst) << ": " << INS_Disassemble(inst) << endl;
#endif
  ADDRINT read_reg_id[6] = {0};
  ADDRINT written_reg_id[6] = {0};

  bool have_read_mem_1 = false, have_read_mem_2 = false, have_written_mem = false;

  uint32_t regR_num = INS_MaxNumRRegs(inst);
  assert(regR_num <= 6);
  for(uint32_t i = 0; i < regR_num ; ++i) {
    read_reg_id[i] = INS_RegR(inst, i);
  }

  if(INS_IsMemoryRead(inst)) {
    // cout << "have read mem 1" << endl;
    have_read_mem_1 = true;
  }
  if(INS_HasMemoryRead2(inst)) {
    // cout << "have read mem 2" << endl;
    have_read_mem_2 = true;
  }

  uint32_t regW_num = INS_MaxNumWRegs(inst);
  assert(regW_num <= 6);
  for(uint32_t i = 0; i < regW_num ; ++i) {
    written_reg_id[i] = INS_RegW(inst, i);
  }

  if(INS_IsMemoryWrite(inst)) {
    // cout << "have written mem" << endl;
    have_written_mem = true;
  }

  bool is_branch = false;
  if(INS_IsBranchOrCall(inst) || INS_IsRet(inst)) {
    is_branch = true;
  }

  if(have_read_mem_1 == true) {
    if(have_read_mem_2 == true) {
      if(have_written_mem == true) {
        INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst, IARG_INST_PTR, IARG_UINT64, INS_Opcode(inst), IARG_ADDRINT, read_reg_id[0], IARG_ADDRINT, read_reg_id[1], IARG_ADDRINT, read_reg_id[2], IARG_ADDRINT, read_reg_id[3], IARG_ADDRINT, read_reg_id[4], IARG_ADDRINT, read_reg_id[5], IARG_ADDRINT, written_reg_id[0], IARG_ADDRINT, written_reg_id[1], IARG_ADDRINT, written_reg_id[2], IARG_ADDRINT, written_reg_id[3], IARG_ADDRINT, written_reg_id[4], IARG_ADDRINT, written_reg_id[5], IARG_BOOL, have_read_mem_1, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_BOOL, have_read_mem_2, IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, IARG_BOOL, have_written_mem, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_EA, IARG_CONTEXT, IARG_BOOL, is_branch, IARG_END);
      }
      else {
        INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst, IARG_INST_PTR, IARG_UINT64, INS_Opcode(inst), IARG_ADDRINT, read_reg_id[0], IARG_ADDRINT, read_reg_id[1], IARG_ADDRINT, read_reg_id[2], IARG_ADDRINT, read_reg_id[3], IARG_ADDRINT, read_reg_id[4], IARG_ADDRINT, read_reg_id[5], IARG_ADDRINT, written_reg_id[0], IARG_ADDRINT, written_reg_id[1], IARG_ADDRINT, written_reg_id[2], IARG_ADDRINT, written_reg_id[3], IARG_ADDRINT, written_reg_id[4], IARG_ADDRINT, written_reg_id[5], IARG_BOOL, have_read_mem_1, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_BOOL, have_read_mem_2, IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, IARG_BOOL, have_written_mem, IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_CONTEXT, IARG_BOOL, is_branch, IARG_END);
      }
    }
    else {
      if(have_written_mem == true) {
        INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst, IARG_INST_PTR, IARG_UINT64, INS_Opcode(inst), IARG_ADDRINT, read_reg_id[0], IARG_ADDRINT, read_reg_id[1], IARG_ADDRINT, read_reg_id[2], IARG_ADDRINT, read_reg_id[3], IARG_ADDRINT, read_reg_id[4], IARG_ADDRINT, read_reg_id[5], IARG_ADDRINT, written_reg_id[0], IARG_ADDRINT, written_reg_id[1], IARG_ADDRINT, written_reg_id[2], IARG_ADDRINT, written_reg_id[3], IARG_ADDRINT, written_reg_id[4], IARG_ADDRINT, written_reg_id[5], IARG_BOOL, have_read_mem_1, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_BOOL, have_read_mem_2, IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_BOOL, have_written_mem, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_CONTEXT, IARG_BOOL, is_branch, IARG_END);
      }
      else {
        INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst, IARG_INST_PTR, IARG_UINT64, INS_Opcode(inst), IARG_ADDRINT, read_reg_id[0], IARG_ADDRINT, read_reg_id[1], IARG_ADDRINT, read_reg_id[2], IARG_ADDRINT, read_reg_id[3], IARG_ADDRINT, read_reg_id[4], IARG_ADDRINT, read_reg_id[5], IARG_ADDRINT, written_reg_id[0], IARG_ADDRINT, written_reg_id[1], IARG_ADDRINT, written_reg_id[2], IARG_ADDRINT, written_reg_id[3], IARG_ADDRINT, written_reg_id[4], IARG_ADDRINT, written_reg_id[5], IARG_BOOL, have_read_mem_1, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_BOOL, have_read_mem_2, IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_BOOL, have_written_mem, IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_CONTEXT, IARG_BOOL, is_branch, IARG_END);
      }
    }
  }
  else {
    if(have_written_mem == true) {
      INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst, IARG_INST_PTR, IARG_UINT64, INS_Opcode(inst), IARG_ADDRINT, read_reg_id[0], IARG_ADDRINT, read_reg_id[1], IARG_ADDRINT, read_reg_id[2], IARG_ADDRINT, read_reg_id[3], IARG_ADDRINT, read_reg_id[4], IARG_ADDRINT, read_reg_id[5], IARG_ADDRINT, written_reg_id[0], IARG_ADDRINT, written_reg_id[1], IARG_ADDRINT, written_reg_id[2], IARG_ADDRINT, written_reg_id[3], IARG_ADDRINT, written_reg_id[4], IARG_ADDRINT, written_reg_id[5], IARG_BOOL, have_read_mem_1, IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_BOOL, have_read_mem_2, IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_BOOL, have_written_mem, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_CONTEXT, IARG_BOOL, is_branch, IARG_END);
    }
    else {
      INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)before_inst, IARG_INST_PTR, IARG_UINT64, INS_Opcode(inst), IARG_ADDRINT, read_reg_id[0], IARG_ADDRINT, read_reg_id[1], IARG_ADDRINT, read_reg_id[2], IARG_ADDRINT, read_reg_id[3], IARG_ADDRINT, read_reg_id[4], IARG_ADDRINT, read_reg_id[5], IARG_ADDRINT, written_reg_id[0], IARG_ADDRINT, written_reg_id[1], IARG_ADDRINT, written_reg_id[2], IARG_ADDRINT, written_reg_id[3], IARG_ADDRINT, written_reg_id[4], IARG_ADDRINT, written_reg_id[5], IARG_BOOL, have_read_mem_1, IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_BOOL, have_read_mem_2, IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_BOOL, have_written_mem, IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_CONTEXT, IARG_BOOL, is_branch, IARG_END);
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

  IMG_AddInstrumentFunction(load_image, 0);
  INS_AddInstrumentFunction(inst_instrument, 0);
  PIN_AddSyscallEntryFunction(syscall_entry, NULL);

  hash_pid = fork();
  assert(hash_pid!=-1);
  if(hash_pid==0) {
    execl(HASH_PROG, HASH_PROG, NULL);
  }
  hash_req = open(HASH_FIFO, O_WRONLY);

  PIN_StartProgram();

  uint8_t cmd = TERMINATE_CMD;
  write(hash_req, &cmd, 1);
  close(hash_req);
  return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
