MOSFHET_DIR = ./src/mosfhet/
include $(MOSFHET_DIR)/Makefile.def
INCLUDE_DIRS += ./include/
OPT_FLAGS +=
CC = gcc

SRC = cipher.c cipher_mt.c f2_arithm.c vertical_packing.c

all: main_cipher main_cipher_mp

main_cipher: $(SRC_MOSFHET) $(addprefix ./src/, $(SRC)) main_cipher.c
	$(CC) -g -o main_cipher $^ $(OPT_FLAGS) $(LIBS)

main_cipher_mp: $(SRC_MOSFHET) $(addprefix ./src/, $(SRC)) main_cipher_mp.c
	$(CC) -g -o main_cipher_mp $^ $(OPT_FLAGS) $(LIBS)


run: main_cipher
	./main_cipher