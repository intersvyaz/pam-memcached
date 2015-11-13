VERSION         = 1.0.0
CC              = gcc
DEBUG           = -g
CFLAGS          = -Wall -pedantic -fPIC
SHARED          = -shared
prefix          = /usr
bindir          = $(prefix)/bin
plibdir         = lib/security
sysconfdir      = /etc

all: pam_memcache2.so

pam_memcache2.o: pam_memcache2.c pam_memcache2.h
	$(CC) $(CFLAGS) $(SHARED) -c pam_memcache2.c -o pam_memcache2.o

pam_memcache2.so: pam_memcache2.o md5.o
	ld -Bshareable pam_memcache2.o md5.o -lpam -lmemcached -o pam_memcache2.so

install: all
        install -d $(DESTDIR)/$(plibdir)
        install pam_memcache2.so $(DESTDIR)/$(plibdir)
clean:
        @rm -f *~ *.so *.o
