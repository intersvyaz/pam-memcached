######################################################################
#
#  A minimal 'Makefile', by copy-paste from Internet
#
# $Id: Makefile,v 1.1 2010/04/20 07:08:03 gureedo Exp $
#
#############################################################################

VERSION=1.0.0

######################################################################
#
# If we're really paranoid, use these flags
#CFLAGS = -Wall -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wnested-externs -Waggregate-return
#
#  If you're not using GCC, then you'll have to change the CFLAGS.
#
CFLAGS = -Wall -fPIC


######################################################################
#
#  The default rule to build everything.
#
all: pam_memcache2.so


######################################################################
#
#  Build the object file from the C source.
#
pam_memcache2.o: pam_memcache2.c pam_memcache2.h
	$(CC) $(CFLAGS) -c pam_memcache2.c -o pam_memcache2.o


######################################################################
#
#  Build the shared library.
#
#  The -Bshareable flag *should* work on *most* operating systems.
#
#  On Solaris, you might try using '-G', instead.
#
#  On systems with a newer GCC, you will need to do:
#
#	gcc -shared pam_memcache2.o md5.o -lpam -lc -o pam_memcache2.so
#
pam_memcache2.so: pam_memcache2.o md5.o
	ld -Bshareable pam_memcache2.o md5.o -lpam -lmemcached -o pam_memcache2.so

######################################################################
#
#  Clean up everything
#
clean:
	@rm -f *~ *.so *.o

######################################################################
#
# Install pam module
#
install: all
	cp ./pam_memcache2.so /lib/security