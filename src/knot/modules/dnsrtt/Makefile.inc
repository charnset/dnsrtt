knot_modules_dnsrtt_la_SOURCES = knot/modules/dnsrtt/dnsrtt.c \
                              knot/modules/dnsrtt/functions.c \
                              knot/modules/dnsrtt/functions.h
EXTRA_DIST +=                 knot/modules/dnsrtt/dnsrtt.rst

if STATIC_MODULE_dnsrtt
libknotd_la_SOURCES += $(knot_modules_dnsrtt_la_SOURCES)
endif

if SHARED_MODULE_dnsrtt
knot_modules_dnsrtt_la_LDFLAGS = $(KNOTD_MOD_LDFLAGS)
knot_modules_dnsrtt_la_CPPFLAGS = $(KNOTD_MOD_CPPFLAGS)
knot_modules_dnsrtt_la_LIBADD = libcontrib.la
pkglib_LTLIBRARIES += knot/modules/dnsrtt.la
endif
