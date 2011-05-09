IDL_FLAGS = -I $(MOZ_IDLDIR)/stable 
.idl.h:
	$(XPIDL) -m header $(IDL_FLAGS)$^

.idl.xpt:
	$(XPIDL) -m typelib $(IDL_FLAGS)$^

AM_CXXFLAGS = $(XUL_CFLAGS) -std=gnu++0x -fPIC -DPIC
AM_LDFLAGS = $(XUL_LDFLAGS) $(XUL_LIBS)


noinst_PROGRAMS = libmoonshot.so

libmoonshot_so_SOURCES = 		nsHttpMoonshot.cpp \
		nsMoonshotSessionState.cpp \
		nsHttpMoonshotModule.cpp

BUILT_SOURCES = nsIHttpMoonshot.h

libmoonshot_so_LINK = $(CXX) -o $@ -shared 
libmoonshot_so_LDADD = $(AM_LDFLAGS) 

all: moonshot.xpi

XPT = nsIHttpMoonshot.xpt

XPI_INSTALL = $(srcdir)/install.js $(srcdir)/install.rdf


moonshot.xpi: $(noinst_PROGRAMS) $(XPT) $(XPI_INSTALL)
	test -d xpi ||rm -rf xpi
	mkdir -p xpi/components 
	cp libmoonshot.so xpi/components
	touch xpi/chrome.manifest
	cp $(XPI_INSTALL) xpi
	cp $(XPT) xpi/components
	cd xpi&&zip ../$@ -r .
	rm -rf xpi

MOSTLYCLEANFILES = $(BUILT_SOURCES) $(XPT)
CLEANFILES = moonshot.xpi
