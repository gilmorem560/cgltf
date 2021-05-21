# cgltf - Makefile
#
# install/uninstall at your own risk in $(PREFIX)
PREFIX		=	/usr

AR			= 	ar rcs
CC			=	cc
CFLAGS		=	-O2 -c -fPIC
CP			=	cp
LDFLAGS		=	-shared
RM			=	rm -rf

STATIC_LIB	=	libcgltf.a
DYNAMIC_LIB	=	libcgltf.so

CGLTF		=	cgltf.o

all: $(STATIC_LIB) $(DYNAMIC_LIB)

install: all
	cp $(STATIC_LIB) $(DYNAMIC_LIB) $(PREFIX)/lib
	cp cgltf.h $(PREFIX)/include

uninstall:
	$(RM) $(PREFIX)/lib/$(STATIC_LIB)
	$(RM) $(PREFIX)/lib/$(DYNAMIC_LIB)
	$(RM) $(PREFIX)/include/cgltf.h

$(STATIC_LIB): $(CGLTF)
	$(AR) $@ $<

$(DYNAMIC_LIB): $(CGLTF)
	$(CC) $(LDFLAGS) -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	$(RM) $(STATIC_LIB) $(DYNAMIC_LIB) $(CGLTF)
