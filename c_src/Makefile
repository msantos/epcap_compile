CURDIR := $(shell pwd)
BASEDIR := $(abspath $(CURDIR)/..)

PROJECT ?= $(notdir $(BASEDIR))
PROJECT := $(strip $(PROJECT))

ERTS_INCLUDE_DIR ?= $(shell erl -noshell -eval "io:format(\"~s/erts-~s/include/\", [code:root_dir(), erlang:system_info(version)])." -s erlang halt)
ERLANG_ARCH ?= $(shell erl -noshell -eval "io:format(\"~B\", [erlang:system_info({wordsize,external}) * 8])." -s erlang halt)

C_SRC_DIR = $(CURDIR)
C_SRC_OUTPUT ?= $(CURDIR)/../priv/$(PROJECT).so

# System type and C compiler/flags.
CC ?= cc

UNAME_SYS := $(shell uname -s)
ifeq ($(UNAME_SYS), Darwin)
	CFLAGS ?= -O3 -arch x86_64 -finline-functions -Wall -Wmissing-prototypes
	LDFLAGS ?= -arch x86_64 -flat_namespace -undefined suppress
else ifeq ($(UNAME_SYS), FreeBSD)
	CFLAGS ?= -O3 -finline-functions -Wall -Wmissing-prototypes \
						-pedantic -fwrapv -D_FORTIFY_SOURCE=2 \
					 	-fstack-protector-strong -Wformat -Werror=format-security \
					 	-fno-strict-aliasing -Wconversion -Wshadow -Wpointer-arith \
						-Wcast-qual
else ifeq ($(UNAME_SYS), OpenBSD)
	CFLAGS ?= -O3 -finline-functions -Wall -Wmissing-prototypes \
						-pedantic -fwrapv -D_FORTIFY_SOURCE=2 \
					 	-fstack-protector-strong -Wformat -Werror=format-security \
					 	-fno-strict-aliasing -Wconversion -Wshadow -Wpointer-arith \
						-Wcast-qual
else ifeq ($(UNAME_SYS), Linux)
	CFLAGS ?= -O3 -finline-functions -Wall -Wmissing-prototypes \
						-pedantic -fwrapv -D_FORTIFY_SOURCE=2 \
					 	-fstack-protector-strong -Wformat -Werror=format-security \
					 	-fno-strict-aliasing -Wconversion -Wshadow -Wpointer-arith \
						-Wcast-qual
else ifeq ($(UNAME_SYS), SunOS)
	CFLAGS += -std=c99 -D_POSIX_C_SOURCE=200112L -lsocket -lnsl
endif

CFLAGS += -fPIC -I $(ERTS_INCLUDE_DIR)

LDFLAGS ?= -lpcap -Wl,-z,relro,-z,now -Wl,-z,noexecstack -shared

# Verbosity.

c_verbose_0 = @echo " C     " $(?F);
c_verbose = $(c_verbose_$(V))

link_verbose_0 = @echo " LD    " $(@F);
link_verbose = $(link_verbose_$(V))

SOURCES := $(shell find $(C_SRC_DIR) -type f \( -name "*.c" \))
OBJECTS = $(addsuffix .o, $(basename $(SOURCES)))

COMPILE_C = $(c_verbose) $(CC) $(CFLAGS) $(CPPFLAGS) -c

$(C_SRC_OUTPUT): privdir $(OBJECTS)
	$(link_verbose) $(CC) $(OBJECTS) $(LDFLAGS) -o $(C_SRC_OUTPUT)

%.o: %.c
	$(COMPILE_C) $(OUTPUT_OPTION) $<

clean:
	@rm -f $(C_SRC_OUTPUT) $(OBJECTS) $(C_SRC_DIR)/*.a $(C_SRC_DIR)/*.o priv/*.so

privdir:
	@mkdir -p $(BASEDIR)/priv/
