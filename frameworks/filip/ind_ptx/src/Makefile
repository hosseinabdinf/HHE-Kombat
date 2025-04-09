CCX = g++
CCXFLAGS = -O3 -funroll-loops -march=native -std=c++11 -pthread -I. -I./include_final -I./bench_utils
DEPS = -lntl -lgmp -lfftw3 -lm
DIR = run
AES_SRC_DIR = tiny-aes
AES_BUILD_DIR = $(AES_SRC_DIR)/run

all: $(DIR) $(AES_BUILD_DIR) test_final test_final_mod_p test_homomorphic_filip_mod_p

$(DIR):
	@echo "---> Creating directory: $(DIR)"
	mkdir -p $(DIR)

$(AES_BUILD_DIR):
	@echo "---> Creating directory: $(AES_BUILD_DIR)"
	mkdir -p $(AES_BUILD_DIR)

clean:
	$(RM) -r $(DIR)
	$(RM) -r $(AES_BUILD_DIR)

test_final: FINAL.h libfinal.a | $(DIR)
	$(CCX) $(CCXFLAGS) -o $(DIR)/test_final test_final.cpp $(DIR)/libfinal.a $(DEPS)

test_final_mod_p: FINAL.h libfinal.a test_final_mod_p.cpp utils.o | $(DIR)
	$(CCX) $(CCXFLAGS) -o $(DIR)/test_final_mod_p test_final_mod_p.cpp $(DIR)/utils.o $(DIR)/libfinal.a $(DEPS)

libfinal.a: include_final/params.h ntruhe.o lwehe.o keygen.o fft.o sampler.o | $(DIR)
	$(AR) -q $(DIR)/libfinal.a $(DIR)/ntruhe.o $(DIR)/lwehe.o $(DIR)/keygen.o $(DIR)/fft.o $(DIR)/sampler.o

ntruhe.o: include_final/ntruhe.h keygen.o sampler.o lwehe.o src_final/ntruhe.cpp | $(DIR)
	$(CCX) $(CCXFLAGS) -c src_final/ntruhe.cpp -o $(DIR)/ntruhe.o

lwehe.o: include_final/lwehe.h keygen.o sampler.o src_final/lwehe.cpp | $(DIR)
	$(CCX) $(CCXFLAGS) -c src_final/lwehe.cpp -o $(DIR)/lwehe.o

keygen.o: include_final/keygen.h sampler.o fft.o src_final/keygen.cpp | $(DIR)
	$(CCX) $(CCXFLAGS) -c src_final/keygen.cpp -o $(DIR)/keygen.o

fft.o: include_final/fft.h | $(DIR)
	$(CCX) $(CCXFLAGS) -c src_final/fft.cpp -o $(DIR)/fft.o

sampler.o: include_final/sampler.h include_final/params.h src_final/sampler.cpp | $(DIR)
	$(CCX) $(CCXFLAGS) -c src_final/sampler.cpp -o $(DIR)/sampler.o

libaes: | $(AES_BUILD_DIR)
	$(MAKE) -C $(AES_SRC_DIR) 
# AES_BUILD_DIR=$(AES_BUILD_DIR)

csprng.o: libaes csprng.h csprng.cpp | $(DIR)
	$(CCX) $(CCXFLAGS) -c csprng.cpp -o $(DIR)/csprng.o -g -Wall -msse2 -msse -maes

test_filip: filip.o test_filip.cpp libfinal.a csprng.o | $(DIR)
	$(CCX) $(CCXFLAGS) -o $(DIR)/test_filip test_filip.cpp $(DIR)/filip.o $(DIR)/utils.o $(DIR)/csprng.o $(AES_BUILD_DIR)/aes.o $(DIR)/libfinal.a $(DEPS)

filip.o: filip.h filip.cpp utils.o | $(DIR)
	$(CCX) $(CCXFLAGS) -c filip.cpp -o $(DIR)/filip.o

utils.o: utils.h utils.cpp | $(DIR)
	$(CCX) $(CCXFLAGS) -c utils.cpp -o $(DIR)/utils.o

bench_utils.o: bench_utils/bench_utils.c bench_utils/bench_utils.h | $(DIR)
	$(CCX) $(CCXFLAGS) -c bench_utils/bench_utils.c -o $(DIR)/bench_utils.o

bench_printer.o: bench_utils/bench_printer.cpp bench_utils/bench_printer.h | $(DIR)
	$(CCX) $(CCXFLAGS) -c bench_utils/bench_printer.cpp -o $(DIR)/bench_printer.o

homomorphic_filip_mod_p.o: homomorphic_filip_mod_p.h homomorphic_filip_mod_p.cpp | $(DIR)
	$(CCX) $(CCXFLAGS) -c homomorphic_filip_mod_p.cpp -o $(DIR)/homomorphic_filip_mod_p.o

test_homomorphic_filip_mod_p: homomorphic_filip_mod_p.o test_homomorphic_filip_mod_p.cpp filip.o utils.o bench_utils.o bench_printer.o csprng.o | $(DIR)
	$(CCX) $(CCXFLAGS) -o $(DIR)/test_homomorphic_filip_mod_p test_homomorphic_filip_mod_p.cpp $(DIR)/homomorphic_filip_mod_p.o $(DIR)/filip.o $(DIR)/utils.o $(DIR)/bench_utils.o $(DIR)/bench_printer.o $(DIR)/csprng.o $(AES_BUILD_DIR)/aes.o $(DIR)/libfinal.a $(DEPS)
