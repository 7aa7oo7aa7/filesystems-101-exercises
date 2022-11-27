.PHONY: build test

SRC_SOLUTION := $(wildcard *.c)
HDR_SOLUTION := $(wildcard *.h)

SRC_STDLIB := $(wildcard ../stdlib/*.c)
HDR_STDLIB := $(wildcard ../stdlib/*.h)

test: build
	./a.out

build: a.out

a.out: $(SRC_SOLUTION) $(HDR_SOLUTION) $(SRC_STDLIB) $(HDR_STDLIB)
	gcc \
		-std=gnu11 -Wall -Wextra -Werror \
		-I. -I../stdlib -I/usr/include/fuse3 \
		-D_GNU_SOURCE -DFUSE_USE_VERSION=31 \
		-pthread \
		-g -Og \
		$(SRC_SOLUTION) $(SRC_STDLIB) \
		-lfuse3
