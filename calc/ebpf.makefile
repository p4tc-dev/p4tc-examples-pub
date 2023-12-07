## Actual location of the makefile
ROOT_DIR=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))
## Argument for the CLANG compiler
CLANG ?= clang
INCLUDES= -I$(ROOT_DIR)/include
# Optimization flags to save space
CFLAGS+= -O2 -g -c -D__KERNEL__ -D__ASM_SYSREG_H -DBTF \
	 -Wno-unused-value  -Wno-pointer-sign \
	 -Wno-compare-distinct-pointer-types \
	 -Wno-gnu-variable-sized-type-not-at-end \
	 -Wno-address-of-packed-member -Wno-tautological-compare \
	 -Wno-unknown-warning-option -Wnoparentheses-equality

SRCS+=calc_parser.c
SRCS+=calc_control_blocks.c
OBJS=$(SRCS:.c=.o)

all: $(OBJS)

$(OBJS): %.o : %.c
	$(CLANG) $(CFLAGS) $(INCLUDES) --target=bpf -mcpu=probe -c $< -o $@

clean:
	rm -f $(OBJS)
