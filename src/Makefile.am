AM_CFLAGS = $(VARNISHAPI_CFLAGS) -Wall -Werror
AM_LDFLAGS = $(VARNISHAPI_LIBS) $(VMOD_LDFLAGS)

vmod_LTLIBRARIES = libvmod_noreturn.la

libvmod_noreturn_la_SOURCES = \
	vmod_noreturn.c

nodist_libvmod_noreturn_la_SOURCES = \
	vcc_noreturn_if.c \
	vcc_noreturn_if.h

dist_man_MANS = vmod_noreturn.3

@BUILD_VMOD_LETS@

AM_TESTS_ENVIRONMENT = \
	PATH="$(VMOD_TEST_PATH)" \
	LD_LIBRARY_PATH="$(VARNISH_LIBRARY_PATH)"
TEST_EXTENSIONS = .vtc
VTC_LOG_COMPILER = varnishtest -v
AM_VTC_LOG_FLAGS = -Dvmod_noreturn="$(VMOD_LETS)"

TESTS = @VMOD_TESTS@

EXTRA_DIST = \
	vmod_noreturn.vcc \
	$(VMOD_TESTS)
