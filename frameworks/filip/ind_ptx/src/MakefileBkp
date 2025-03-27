CCX = g++
CCXFLAGS = -O3 -funroll-loops -march=native -std=c++11 -pthread -I. -I./include_final
DEPS = -lntl -lgmp -lfftw3 -lm

all: test_final test_final_mod_p test_homomorphic_filip_mod_p
	 
clean:
	$(RM) test_final test_final_mod_p test_filip test_homomorphic_filip_mod_p *.o libfinal.a
	$(RM) tiny-aes/test.o tiny-aes/test.elf tiny-aes/test.map tiny-aes/aes.o

test_final: FINAL.h libfinal.a
	$(CCX) $(CCXFLAGS) -o test_final test_final.cpp libfinal.a $(DEPS)

test_final_mod_p: FINAL.h libfinal.a test_final_mod_p.cpp utils.o
	$(CCX) $(CCXFLAGS) -o test_final_mod_p test_final_mod_p.cpp utils.o libfinal.a $(DEPS)

libfinal.a: include_final/params.h ntruhe.o lwehe.o keygen.o fft.o sampler.o
	$(AR) -q libfinal.a ntruhe.o lwehe.o keygen.o fft.o sampler.o

ntruhe.o: include_final/ntruhe.h keygen.o sampler.o lwehe.o src_final/ntruhe.cpp
	$(CCX) $(CCXFLAGS) -c src_final/ntruhe.cpp

lwehe.o: include_final/lwehe.h keygen.o sampler.o src_final/lwehe.cpp
	$(CCX) $(CCXFLAGS) -c src_final/lwehe.cpp

keygen.o: include_final/keygen.h sampler.o fft.o src_final/keygen.cpp
	$(CCX) $(CCXFLAGS) -c src_final/keygen.cpp

fft.o: include_final/fft.h
	$(CCX) $(CCXFLAGS) -c src_final/fft.cpp

sampler.o: include_final/sampler.h include_final/params.h src_final/sampler.cpp
	$(CCX) $(CCXFLAGS) -c src_final/sampler.cpp

libaes: 
	$(MAKE) -C ./tiny-aes

csprng.o: libaes csprng.h csprng.cpp
	$(CXX) $(CCXFLAGS) -c csprng.cpp -o csprng.o -g -Wall -msse2 -msse -maes


test_filip: filip.o test_filip.cpp libfinal.a csprng.o
	#$(CCX) $(CCXFLAGS) -o test_filip test_filip.cpp filip.o utils.o csprng.o ./tiny-aes/aes.o  ./final/libfinal.a $(DEPS)
	$(CCX) $(CCXFLAGS) -o test_filip test_filip.cpp filip.o utils.o csprng.o ./tiny-aes/aes.o  libfinal.a $(DEPS)

filip.o: filip.h filip.cpp utils.o
	$(CCX) $(CCXFLAGS) -c filip.cpp -o filip.o

utils.o: utils.h utils.cpp
	$(CCX) $(CCXFLAGS) -c utils.cpp -o utils.o

homomorphic_filip_mod_p.o: homomorphic_filip_mod_p.h homomorphic_filip_mod_p.cpp
	$(CCX) $(CCXFLAGS) -c homomorphic_filip_mod_p.cpp -o homomorphic_filip_mod_p.o

test_homomorphic_filip_mod_p: homomorphic_filip_mod_p.o test_homomorphic_filip_mod_p.cpp filip.o utils.o csprng.o
	$(CCX) $(CCXFLAGS) -o test_homomorphic_filip_mod_p test_homomorphic_filip_mod_p.cpp homomorphic_filip_mod_p.o filip.o utils.o csprng.o ./tiny-aes/aes.o  libfinal.a $(DEPS)
