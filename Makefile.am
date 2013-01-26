AM_CFLAGS = "-std=gnu99"
# Use gnu99 standard to avoid some gcc warnings

sbin_PROGRAMS = AGanNo2
AGanNo2_SOURCES = agan8021x.c
check_PROGRAMS = checklibpcapversion checklibnetversion
checklibpcapversion_SOURCES = checklibpcapversion-main.c
checklibnetversion_SOURCES = checklibnetversion-main.c
LIBNET_LIBS = -lnet
LDADD = $(PCAP_LIBS) $(LIBNET_LIBS) 
CFLAGS += $(libcrypto_CFLAGS)
LDADD += $(libcrypto_LIBS)
EXTRA_DIST = README.html autogen.sh

