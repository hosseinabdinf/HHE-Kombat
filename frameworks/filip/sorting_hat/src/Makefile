# This make file will compile the test files for the PDTE transciphering
# algorithm. The test files are:
# - test_filip.cpp: tests the Filip class
# - test_node.cpp: tests the Node class
# - test_homomorphic_filip.cpp: tests the HomomorphicFilip class
# - test_pdte_transciphering.cpp: tests the PDTE transciphering algorithm
# The make file will also compile the Filip, Node, and HomomorphicFilip classes
# and the utils file. The final library will be compiled as well. The final
# library contains the PDTE transciphering algorithm.
# All the executables will be placed in the run directory.

CCX = g++
CCXFLAGS = -O3 -funroll-loops -march=native -std=c++17 -pthread -I. -I.final/include -I./bench_utils
DEPS = -lntl -lgmp -lfftw3 -lm
OUTDIR = ./run

all: clean setup test_filip test_node test_homomorphic_filip test_pdte_transciphering

setup:
	mkdir -p $(OUTDIR)

clean:
	$(RM) -r $(OUTDIR)

test_pdte_transciphering: test_pdte_transciphering.cpp libfinal.a node.o
	$(CCX) $(CCXFLAGS) -o $(OUTDIR)/test_pdte_transciphering test_pdte_transciphering.cpp $(OUTDIR)/node.o ./final/libfinal.a $(DEPS)

libfinal.a:
	$(MAKE) -C ./final

test_filip: filip.o test_filip.cpp libfinal.a utils.o
	$(CCX) $(CCXFLAGS) -o $(OUTDIR)/test_filip test_filip.cpp $(OUTDIR)/filip.o $(OUTDIR)/utils.o ./final/libfinal.a $(DEPS)

filip.o: filip.h filip.cpp utils.o
	$(CCX) $(CCXFLAGS) -c filip.cpp -o $(OUTDIR)/filip.o

utils.o: utils.h utils.cpp
	$(CCX) $(CCXFLAGS) -c utils.cpp -o $(OUTDIR)/utils.o

# Benchmarking library
bench_utils.o: bench_utils/bench_utils.c bench_utils/bench_utils.h | $(OUTDIR)
	$(CCX) $(CCXFLAGS) -c bench_utils/bench_utils.c -o $(OUTDIR)/bench_utils.o

bench_printer.o: bench_utils/bench_printer.cpp bench_utils/bench_printer.h | $(OUTDIR)
	$(CCX) $(CCXFLAGS) -c bench_utils/bench_printer.cpp -o $(OUTDIR)/bench_printer.o
# End of the benchmarking library

node.o: node.h node.cpp
	$(CCX) $(CCXFLAGS) -c node.cpp -o $(OUTDIR)/node.o

test_node: node.o test_node.cpp libfinal.a
	$(CCX) $(CCXFLAGS) $(OUTDIR)/node.o test_node.cpp -o $(OUTDIR)/test_node ./final/libfinal.a $(DEPS)

test_homomorphic_filip: filip.o utils.o bench_utils.o bench_printer.o homomorphic_filip.o test_homomorphic_filip.cpp libfinal.a
	$(CCX) $(CCXFLAGS) -o $(OUTDIR)/test_homomorphic_filip test_homomorphic_filip.cpp $(OUTDIR)/homomorphic_filip.o $(OUTDIR)/filip.o $(OUTDIR)/utils.o $(OUTDIR)/bench_utils.o $(OUTDIR)/bench_printer.o ./final/libfinal.a $(DEPS)

homomorphic_filip.o: filip.o utils.o homomorphic_filip.h homomorphic_filip.cpp
	$(CCX) $(CCXFLAGS) -c homomorphic_filip.cpp -o $(OUTDIR)/homomorphic_filip.o
