## Process this file with automake to produce Makefile.in

@SET_MAKE@

SUBDIRS=src

dist_man_MANS=$(gdoc_MANS)
MAINTAINERCLEANFILES=$(dist_man_MANS)
EXTRA_DIST=gdoc

GDOC_SRC=$(top_srcdir)/src/*.c
GDOC_MAN_PREFIX=man/
GDOC_MAN_EXTRA_ARGS=-module "cargos\-lib" -sourceversion $(VERSION) \
	-bugsto $(PACKAGE_BUGREPORT) -includefuncprefix \
       	-copyright "2006 Georgios Portokalidis" -verbatimcopying
include $(top_srcdir)/Makefile.gdoci
