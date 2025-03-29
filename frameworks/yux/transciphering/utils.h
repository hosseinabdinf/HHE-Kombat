#include <stdlib.h>
#include <NTL/ZZX.h>

void printState(NTL::Vec<uint8_t>& st);
void printState_p(NTL::Vec<uint64_t>& st);
void printState_p(std::vector<uint64_t>& st);
void printState_p(std::vector<long>& st);
static void print_vector(std::string info, std::vector<uint8_t> vec, std::ostream& out);