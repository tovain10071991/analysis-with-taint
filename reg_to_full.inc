map<REG, uint32_t> reg_to_full;

void init_reg_to_full() {
  reg_to_full.insert(make_pair(REG_AH, 1));
  reg_to_full.insert(make_pair(REG_CH, 1));
  reg_to_full.insert(make_pair(REG_DH, 1));
  reg_to_full.insert(make_pair(REG_BH, 1));
}