## call with make PROG=xxx to build
##  make PROG=xxx clean|generate|realclean
#
## Argument for the CLANG compiler
CLANG ?= clang
P4C_PNA_P4TC ?= p4c-pna-p4tc
PROG ?= drop_reason
#we need to have a headers package instead of this..
INCLUDES= -I../include
# Optimization flags to save space
CFLAGS+= -O1 -g -c -D__KERNEL__ -D__ASM_SYSREG_H -DBTF \
	 -Wno-unused-value  -Wno-pointer-sign \
	 -Wno-compare-distinct-pointer-types \
	 -Wno-gnu-variable-sized-type-not-at-end \
	 -Wno-address-of-packed-member -Wno-tautological-compare \
	 -Wno-unknown-warning-option -Wnoparentheses-equality

TMPL+=generated/$(PROG).template
TMPL+=generated/$(PROG).json
SRCS+=generated/$(PROG)_parser.c
SRCS+=generated/$(PROG)_control_blocks.c
OBJS=$(SRCS:.c=.o)
all: $(OBJS)

$(OBJS): %.o : %.c
	$(CLANG) $(CFLAGS) $(INCLUDES) --target=bpf -mcpu=probe -c $< -o $@

# Disable uninitialized_use because compiler is emitting a false positive in the parser
generate:
	$(P4C_PNA_P4TC) $(PROG).p4 --Wdisable=uninitialized_use -o generated

clean:
	rm -f $(OBJS)

realclean:
	rm -f $(OBJS) $(SRCS) $(TMPL) $(PROG)_parser.h
