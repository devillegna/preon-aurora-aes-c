CC = gcc
LD = gcc


PROJ ?= avx2
#PROJ ?= ref


ARCH := $(shell uname -m)
ifeq  ($(ARCH), arm64)
PROJ  =  neon
endif


SLIBNAME = gf264btfy
SLIBPATH = ./polyeval/btfy/gf264


CFLAGS   := -O3 -std=c11 -Wall -Wextra -Wpedantic -fno-omit-frame-pointer  #-Werror
INCPATH  := -I/usr/local/include -I/opt/local/include -I/usr/include -I./src -I./polyeval/include
LDFLAGS  := $(LDFLAGS) -L$(SLIBPATH)
LIBS     := -lcrypto -l$(SLIBNAME)


EXT_SRC_DIRS  =

ifdef ASAN
CFLAGS  += -fsanitize=address -fno-sanitize-recover=all
LDFLAGS += -fsanitize=address -fno-sanitize-recover=all
endif


ifeq ($(PROJ),ref)

EXT_SRC_DIRS  += ./src/ref
INCPATH      += -I./src/ref

else ifeq ($(PROJ),avx2)

EXT_SRC_DIRS  += ./src/avx2
INCPATH      += -I./src/avx2
CFLAGS       += -mavx2 -mpclmul

else ifeq ($(PROJ),neon)

EXT_SRC_DIRS  += ./src/neon
INCPATH      += -I./src/neon

endif


TESTINCPATH  := $(INCPATH) -I./benchmark -I./unit_tests



#############################

CSRC        := $(wildcard $(EXT_SRC_DIRS)/*.c)
CSRC        += $(wildcard src/*.c)
SRC_O       := $(CSRC:.c=.o)
SRC_O_NODIR := $(notdir $(SRC_O))
OBJS   = $(SRC_O_NODIR)

#############################

OS := $(shell uname -s)
ARCH := $(shell uname -m)
ifeq  ($(OS), Darwin)
ifeq  ($(ARCH), arm64)
CFLAGS    +=  -D_APPLE_SILICON_
OBJS      += m1cycles.o
endif
endif


#############################

.INTERMEDIATE:  $(OBJS)

.PHONY: all clean


all: $(SLIBPATH)/lib$(SLIBNAME).a submodule-test


$(SLIBPATH)/lib$(SLIBNAME).a:
	cd polyeval && $(MAKE) PROJ=$(PROJ) lib

%-test:  %-test.o
	$(LD) $(LDFLAGS) $(LIBPATH) -o $@ $<  $(LIBS)

%-benchmark:  %-benchmark.o
	$(LD) $(LDFLAGS) $(LIBPATH) -o $@ $<  $(LIBS)

%.o: unit-tests/%.c
	$(CC) $(CFLAGS) $(TESTINCPATH) -o $@ -c $<

%.o: benchmark/%.c
	$(CC) $(CFLAGS) $(TESTINCPATH) -o $@ -c $<

m1cycles.o: benchmark/m1cycles.c
	$(CC) $(CFLAGS) $(TESTINCPATH) -o $@ -c $<

%.o: src/%.c
	$(CC) $(CFLAGS) $(INCPATH) -o $@ -c $<

%.o: src/%.S
	$(CC) $(CFLAGS) $(INCPATH) -o $@ -c $<

define GEN_O
%.o: $(1)/%.c
	$(CC) $(CFLAGS) $(INCPATH) -o $$@ -c $$<
endef
$(foreach dir, $(EXT_SRC_DIRS), $(eval $(call GEN_O,$(dir))))


%.S: %.c
	$(CC) $(CFLAGS) -S -c  -o$@ $^


#############################

clean:
	-rm *.o *.s *.q *.a test speed *-test

