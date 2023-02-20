## Process this file with automake to produce Makefile.in

@SET_MAKE@

lib_LIBRARIES=libcargos.a

libcargos_a_SOURCES=cargos-lib.c cargos-lib-csi.c cargos-lib-mb.c \
		     cargos-lib-nt.c cargos-lib-static.h debug.h
libcargos_a_LIBADD=$(LIBOBJS)
include_HEADERS=cargos-lib.h cargos-lib-csi.h cargos-lib-mb.h cargos-lib-nt.h

bin_PROGRAMS=carlog

carlog_SOURCES=carlog.c
carlog_LDADD=$(LIBOBJS) libcargos.a
