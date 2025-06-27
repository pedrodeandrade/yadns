# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

# binary name
APP = yadns

# all source are stored in SRCS-y
SRCS-y := $(wildcard src/*.c)
HDRS-y := $(wildcard src/*.h)

# --- MODIFICATION START ---
# Path to the shared library installations
CRYPTOPANT_DIR = $(CURDIR)/lib/install/cryptopANT
OPENSSL_DIR = $(CURDIR)/lib/install/openssl
# --- MODIFICATION END ---

PKGCONF ?= pkg-config

# Build using pkg-config variables if possible
ifneq ($(shell $(PKGCONF) --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found")
endif

all: shared
.PHONY: shared static static-debug
shared: build/$(APP)-shared
	ln -sf $(APP)-shared build/$(APP)
static: build/$(APP)-static
	ln -sf $(APP)-static build/$(APP)
static-debug: build/$(APP)-static-debug
	ln -sf $(APP)-static-debug build/$(APP)

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)

# --- MODIFICATION START ---
# Add both cryptopANT and custom OpenSSL include paths
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk) -I$(CRYPTOPANT_DIR)/include -I$(OPENSSL_DIR)/include
CFLAGS_DEBUG = -g -O0 -DDEBUG $(shell $(PKGCONF) --cflags libdpdk) -I$(CRYPTOPANT_DIR)/include -I$(OPENSSL_DIR)/include

# Shared build flags - embed runtime library paths
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk) \
                 -L$(CRYPTOPANT_DIR)/lib -L$(OPENSSL_DIR)/lib \
                 -Wl,-rpath,$(CRYPTOPANT_DIR)/lib -Wl,-rpath,$(OPENSSL_DIR)/lib \
                 -lcryptopANT -lcrypto

# Static build flags (keeping for compatibility)
LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk) \
                 -L$(CRYPTOPANT_DIR)/lib -L$(OPENSSL_DIR)/lib \
                 -lcryptopANT -lcrypto
# --- MODIFICATION END ---

ifneq (,$(filter static static-debug,$(MAKECMDGOALS)))
# check for broken pkg-config
ifeq ($(shell echo $(LDFLAGS_STATIC) | grep 'whole-archive.*l:lib.*no-whole-archive'),)
$(warning "pkg-config output list does not contain drivers between 'whole-archive'/'no-whole-archive' flags.")
$(error "Cannot generate statically-linked binaries with this version of pkg-config")
endif
endif

CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS_DEBUG += -DALLOW_EXPERIMENTAL_API

build/$(APP)-shared: $(SRCS-y) $(HDRS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED)

build/$(APP)-static: $(SRCS-y) $(HDRS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

build/$(APP)-static-debug: $(SRCS-y) $(HDRS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS_DEBUG) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f build/$(APP) build/$(APP)-static build/$(APP)-shared build/$(APP)-static-debug
	test -d build && rmdir -p build || true

# --- MODIFICATION START ---
# Convenience target to check library dependencies
.PHONY: check-deps
check-deps: build/$(APP)-shared
	@echo "=== Library dependencies for $(APP) ==="
	ldd build/$(APP)-shared
	@echo "=== cryptopANT library dependencies ==="
	ldd $(CRYPTOPANT_DIR)/lib/libcryptopANT.so
# --- MODIFICATION END ---