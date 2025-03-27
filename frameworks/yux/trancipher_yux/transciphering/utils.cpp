#include <iostream>
#include <iomanip>
#include <vector>
#include "utils.h"

void printState(NTL::Vec<uint8_t>& st)
{
  std::cerr << "[";
  for (long i=0; i<st.length() && i<32; i++) {
    std::cerr << std::hex << std::setw(2) << (long) st[i] << " ";
  }
  if (st.length()>32) std::cerr << "...";
  std::cerr << std::dec << "]"<< std::endl;
}


void printState_p(NTL::Vec<uint64_t>& st)
{
  std::cerr << "[";
  for (long i=0; i<st.length() && i<32; i++) {
    std::cerr << std::hex << std::setw(5) << (long) st[i] << " ";
  }
  if (st.length()>32) std::cerr << "...";
  std::cerr << std::dec << "]" << std::endl;
}

void printState_p(std::vector<uint64_t>& st)
{
  std::cerr << "[";
  for (long i=0; i<st.size() && i<32; i++) {
    std::cerr << std::hex << std::setw(5) << (long) st[i] << " ";
  }
  if (st.size()>32) std::cerr << "...";
  std::cerr << std::dec << "]" << std::endl;
}

void printState_p(std::vector<long>& st)
{
  std::cerr << "[";
  for (long i=0; i<st.size() && i<64; i++) {
    std::cerr << std::hex << std::setw(5) << (long) st[i] << " ";
    if((i+1)%16 ==0) std::cerr << "\n";
  }
  if (st.size()>64) std::cerr << "...";
  std::cerr << std::dec << "]" << std::endl;
}

static void print_vector(std::string info, std::vector<uint64_t> vec,
                         std::ostream& out) {
  std::ios_base::fmtflags f(out.flags());  // get flags
  if (!info.empty()) {
    out << info << " ";
  }
  out << "{";
  const auto delim = ", ";
  for (auto a : vec) {
    out << std::hex << std::setw(2) << std::setfill('0');
    out << int(a) << delim;
  }
  out << "}\n";

  out.flags(f);  // reset flags
}