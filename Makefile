CC = gcc

CFLAGS = -Wall -Wextra -Wpedantic -fPIC -O3

LDFLAGS = -L./sha512.c/lib -L./curve25519.c/lib -l:libcurve25519.a -l:libsha512.a -lbcrypt 

OBJDIR = objs

LIBDIR = lib

STATIC_LIB_NAME = libhkdf.a
ifeq ($(OS),Windows_NT)
    SHARED_LIB_NAME = libhkdf.dll
else
    SHARED_LIB_NAME = libhkdf.so
endif
STATIC_LIB = $(addprefix $(LIBDIR)/, $(STATIC_LIB_NAME))
SHARED_LIB = $(addprefix $(LIBDIR)/, $(SHARED_LIB_NAME))

HKDF_OBJ = $(OBJDIR)/hkdf.o

all: $(STATIC_LIB) $(SHARED_LIB)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(LIBDIR):
	@mkdir -p $(LIBDIR)

$(HKDF_OBJ): src/hkdf.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(STATIC_LIB): $(HKDF_OBJ) | $(LIBDIR)
	ar rcs $@ $^

$(SHARED_LIB): $(HKDF_OBJ) | $(LIBDIR)
	$(CC) $(CFLAGS) -shared -o $@ $< $(LDFLAGS)

clean_test:
	rm -f $(TEST_FILES) out.txt test*.exe objs/*

clean_all:
	rm -f $(TEST_FILES) out.txt test*.exe lib/* objs/*

.PHONY: test clean_all clean_test