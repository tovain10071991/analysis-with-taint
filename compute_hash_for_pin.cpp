// g++ -g -o compute_hash_for_pin compute_hash_for_pin.cpp -lcrypto -lssl

#include <openssl/md5.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <stdint.h>

#include <list>
#include <vector>
#include <string>
#include <map>
#include <fstream>

using namespace std;

// #define DEBUG

#define HASH_FIFO "/home/user/Documents/test/compute_hash_for_pin/hash.fifo"
#define HASH_OUT "/home/user/Documents/test/compute_hash_for_pin/hash.out2"
#define COMPUTE_CMD 0xc
#define TERMINATE_CMD 0xf

list<pair<vector<unsigned char>, uint64_t>  > control_hash_list;
#ifdef DEBUG
map<string, vector<unsigned char> > module_base_hash_set;
#endif
unsigned char module_base[1000];

int main() {
  if(access(HASH_FIFO, F_OK)) {
    if(mkfifo(HASH_FIFO, S_IRUSR|S_IWUSR)==-1) {
      perror("");
      return -1;
    }
  }
  int hash_rev = open(HASH_FIFO, O_RDONLY);
  uint8_t cmd;
  size_t len;

#ifdef DEBUG
  ofstream fout(HASH_OUT);
#endif

  unsigned char outmd[16];
  while(1) {
    while(!read(hash_rev, &cmd, 1));
    // cmd = COMPUTE_CMD;
    if(cmd == TERMINATE_CMD)
      break;
    assert(cmd == COMPUTE_CMD);
    read(hash_rev, &len, sizeof(len));
    // len = 13;
    // unsigned char* module_base = new unsigned char[len + 1];
    assert(len < 999);
    module_base[len] = '\0';
    read(hash_rev, module_base, len);
    // string module_base = "/bin/ls400890";
    vector<unsigned char> bytes;
    if(!control_hash_list.empty()) {
      bytes = control_hash_list.back().first;
    }
    for(int i = 0; i < len; ++i)
      bytes.push_back((unsigned char)module_base[i]);


    MD5(bytes.data(), len, outmd);

    uint64_t target_addr;
    read(hash_rev, &target_addr, 8);

    control_hash_list.push_back(make_pair(vector<unsigned char>(outmd, outmd + 16), target_addr));
#ifdef DEBUG
    module_base_hash_set[string(module_base, module_base + len + 1)] = vector<unsigned char>(outmd, outmd + 16);
    fout << "(" << hex << len << ")" << module_base << ": ";
    fout << hex;
    for(int i = 0; i < 16; ++i)
      fout << (int)outmd[i] << " ";
    fout /*<< ": 0x" << target_addr*/ << endl;
#endif

    // delete[] module_base;
  }
  close(hash_rev);
  return 0;
}
