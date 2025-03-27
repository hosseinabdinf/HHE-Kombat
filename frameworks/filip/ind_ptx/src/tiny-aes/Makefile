CC           = gcc
LD           = gcc
AR           = ar
ARFLAGS      = rcs
CFLAGS       = -Wall -Os -c
LDFLAGS      = -Wall -Os -Wl,-Map,$(AES_BUILD_DIR)/test.map
ifdef AES192
CFLAGS += -DAES192=1
endif
ifdef AES256
CFLAGS += -DAES256=1
endif

AES_BUILD_DIR = run

OBJCOPYFLAGS = -j .text -O ihex
OBJCOPY      = objcopy

default: $(AES_BUILD_DIR) $(AES_BUILD_DIR)/test.elf

# $(AES_BUILD_DIR):
# 	@echo "---> Creating directory: $(AES_BUILD_DIR)"
# 	mkdir -p $(AES_BUILD_DIR)

$(AES_BUILD_DIR)/test.hex : $(AES_BUILD_DIR)/test.elf
	echo copy object-code to new image and format in hex
	$(OBJCOPY) ${OBJCOPYFLAGS} $< $@

$(AES_BUILD_DIR)/test.o : test.c aes.h $(AES_BUILD_DIR)/aes.o | $(AES_BUILD_DIR)
	echo [CC] $@ $(CFLAGS)
	$(CC) $(CFLAGS) -o $@ $<

$(AES_BUILD_DIR)/aes.o : aes.c aes.h | $(AES_BUILD_DIR)
	echo [CC] $@ $(CFLAGS)
	$(CC) $(CFLAGS) -o $@ $<

$(AES_BUILD_DIR)/test.elf : $(AES_BUILD_DIR)/aes.o $(AES_BUILD_DIR)/test.o | $(AES_BUILD_DIR)
	echo [LD] $@
	$(LD) $(LDFLAGS) -o $@ $^

$(AES_BUILD_DIR)/aes.a : $(AES_BUILD_DIR)/aes.o | $(AES_BUILD_DIR)
	echo [AR] $@
	$(AR) $(ARFLAGS) $@ $^

lib : $(AES_BUILD_DIR)/aes.a

clean:
	rm -f $(AES_BUILD_DIR)/*.OBJ $(AES_BUILD_DIR)/*.LST $(AES_BUILD_DIR)/*.o $(AES_BUILD_DIR)/*.gch $(AES_BUILD_DIR)/*.out $(AES_BUILD_DIR)/*.hex $(AES_BUILD_DIR)/*.map $(AES_BUILD_DIR)/*.elf $(AES_BUILD_DIR)/*.a

test:
	make clean && make && $(AES_BUILD_DIR)/test.elf
	make clean && make AES192=1 && $(AES_BUILD_DIR)/test.elf
	make clean && make AES256=1 && $(AES_BUILD_DIR)/test.elf

lint:
	$(call SPLINT)
