##XXX: Currently Makefile not generated
## call with make PROG=xxx to build
##  make PROG=xxx clean|generate|realclean
#
## Argument for the CLANG compiler
CLANG ?= clang
PROG ?= redirect_l2
#we need to have a headers package instead of this..
INCLUDES= -I../../include
# Optimization flags to save space
CFLAGS+= -O2 -g -c -D__KERNEL__ -D__ASM_SYSREG_H -DBTF \
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

generate:
	p4c-pna-p4tc $(PROG).p4 -o ./generated

clean:
	rm -f $(OBJS)

realclean:
	rm -f $(OBJS) $(SRCS) $(TMPL) $(PROG)_parser.h
