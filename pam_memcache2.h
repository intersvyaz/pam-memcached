#ifndef PAM_MEMCACHE2_H
#define PAM_MEMCACHE2_H

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>
#include <utmp.h>
#include <time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <libmemcached/memcached.h>

#include "md5.h"

typedef struct mc_conf_t {
  pam_handle_t *pamh;
  memcached_st *server;
  char *memcache_proto;
  char *memcache_addr;
  int memcache_port;
  time_t memcache_lifetime;
  char *client_id;
  int ctrl;
} mc_conf_t;

#define CONST const

/*************************************************************************
 * Useful macros and defines
 *************************************************************************/

#define _pam_forget(X) if (X) {memset(X, 0, strlen(X));free(X);X = NULL;}
#ifndef _pam_drop
#define _pam_drop(X) if (X) {free(X);X = NULL;}
#endif

#define PAM_MC_DEBUG_ARG      1
#define PAM_MC_ACCT_MGMT_CONVERSE 2

#define PAM_MC_NSPACE   "mc_auth_cache"
#define PAM_MC_EXPRTIME 15*60 // in seconds


/* Module defines */
#ifndef BUFFER_SIZE
#define BUFFER_SIZE      1024
#endif /* BUFFER_SIZE */
#define MAXPWNAM 253    /* maximum user name length. Server dependent,
                         * this is the default value
                         */
#define MAXPASS 128     /* max password length. Again, depends on server
                         * compiled in. This is the default.
                         */
#ifndef FALSE
#define FALSE 0
#undef TRUE
#define TRUE !FALSE
#endif

#endif /* PAM_MEMCACHE2_H */
