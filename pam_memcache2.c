/* $Id: pam_memcache2.c,v 1.6 2010/04/21 04:21:15 gureedo Exp $
 *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#include <limits.h>
#include <errno.h>

#include <security/pam_modules.h>

#include "pam_memcache2.h"

#define DPRINT if (conf->ctrl & PAM_MC_DEBUG_ARG) _pam_log

/* internal data */
static CONST char *pam_module_name = "pam_memcache2";

/* logging */
static void _pam_log(int err, CONST char *format, ...)
{
    va_list args;
    char buffer[BUFFER_SIZE];

    va_start(args, format);
    vsprintf(buffer, format, args);
    /* don't do openlog or closelog, but put our name in to be friendly */
    syslog(err, "%s: %s", pam_module_name, buffer);
    va_end(args);
}

/* argument parsing */
static void _pam_parse(int argc, CONST char **argv, mc_conf_t *conf)
{
  memset(conf, 0, sizeof(mc_conf_t)); /* ensure it's initialized */

  /*
   *  If either is not there, then we can't parse anything.
   */
  if ((argc == 0) || (argv == NULL)) {
    return;
  }

  conf->memcache_lifetime = PAM_MC_EXPRTIME;

  /* step through arguments */
  for (conf->ctrl=0; argc-- > 0; ++argv) {

    if (!strncmp(*argv, "client_id=", 10)) {
      if (conf->client_id) {
        _pam_log(LOG_WARNING, "ignoring duplicate '%s'", *argv);
      } else {
        conf->client_id = (char *) *argv+10; /* point to the client-id */
      }
      DPRINT(LOG_DEBUG, "Option 'client', conf->client_id = %s", conf->client_id);

    } else if (!strcmp(*argv, "acct_mgmt_converse")) {
      DPRINT(LOG_DEBUG, "Option: conversation enabled in account management");
      conf->ctrl |= PAM_MC_ACCT_MGMT_CONVERSE;

    } else if (!strncmp(*argv, "lifetime=", 9)) {
      conf->memcache_lifetime = atoi(*argv+9);
      DPRINT(LOG_DEBUG, "Using changed key life time %d seconds", conf->memcache_lifetime);

    } else if (!strncmp(*argv, "server=", 7)) {
      conf->memcache_proto = (char*) *argv+7;
      if (!strncmp(conf->memcache_proto,"tcp://",6)) {
        char *ptr;
        conf->memcache_proto[3] = '\0';
        conf->memcache_addr = conf->memcache_proto+6;
        ptr = strchr(conf->memcache_addr,':');
        if (ptr) {
          *(ptr++) = 0;
          conf->memcache_port = atoi(ptr);
        } else {
          conf->memcache_port = 11211;
        }
      } else if (!strncmp(conf->memcache_proto,"unix://",7)) {
        conf->memcache_proto[4] = '\0';
        conf->memcache_addr = conf->memcache_proto+7;
      } else {
        _pam_log(LOG_WARNING, "unrecognized memcache transport protocol, ignoring memcache");
      }
      DPRINT(LOG_DEBUG, "Option 'server', transport = %s, addr = %s, port = %d", conf->memcache_proto, conf->memcache_addr, conf->memcache_port);

    } else if (!strcmp(*argv, "debug")) {
      conf->ctrl |= PAM_MC_DEBUG_ARG;
      DPRINT(LOG_DEBUG, "Debug mode enabled");

    } else {
      _pam_log(LOG_WARNING, "unrecognized option '%s'", *argv);
    }
  }
}

/* Callback function used to free the saved return value for pam_setcred. */
void _int_free( pam_handle_t * pamh, void *x, int error_status )
{
    free(x);
}

/**************************************************************************
 * MEMCACHE CODE
 **************************************************************************/

#define MC_FAIL_CHECK(msg, ...) if (mc_ret != MEMCACHED_SUCCESS) { \
    DPRINT(LOG_DEBUG, msg, ## __VA_ARGS__); \
    retval=PAM_AUTHINFO_UNAVAIL; \
    goto memc_init_error; }
int memc_init(mc_conf_t *conf)
{
  int retval = PAM_SUCCESS;
  memcached_return mc_ret;
  conf->server = memcached_create(NULL);


  if (!strcmp(conf->memcache_proto,"unix")) {
    mc_ret = memcached_server_add_unix_socket(conf->server, conf->memcache_addr);
    MC_FAIL_CHECK("add server with unix socket '%s' failed", conf->memcache_addr);
  } else if (!strcmp(conf->memcache_proto,"tcp")) {
    mc_ret = memcached_server_add(conf->server, conf->memcache_addr, conf->memcache_port);
    MC_FAIL_CHECK("add server with tcp socket '%s:%d' failed", conf->memcache_addr, conf->memcache_port);
  } else {
    retval = PAM_AUTHINFO_UNAVAIL;
  }

memc_init_error:

  return retval;
}

void memc_free(mc_conf_t *conf)
{
  memcached_free(conf->server);
}

void memc_gen_salt( char *buf, size_t len )
{
  int i;
  for(i=0;i<len;++i) {
    buf[i] = (char)(26 * (rand() / (RAND_MAX + 1.0)) + 97);
  }
  buf[i] = '\0';
}

void memc_hash_pwd(const char *password, const char *salt, char *hexhash)
{
  int i;
  unsigned char md5digest[16];
  MD5_CTX md5ctx;
  MD5Init(&md5ctx);
  MD5Update(&md5ctx,(unsigned char*)password,strlen(password));
  MD5Update(&md5ctx,(unsigned char*)salt,strlen(salt));
  MD5Final(md5digest,&md5ctx);

  for (i=0; i<16; ++i) {
    sprintf(&hexhash[2*i],"%02x",md5digest[i]);
  }
  hexhash[32] = '\0';
}

#undef MC_FAIL_CHECK
#define MC_FAIL_CHECK(msg, ...) if (mc_ret != MEMCACHED_SUCCESS) { \
    DPRINT(LOG_DEBUG, msg, ## __VA_ARGS__); \
    retval=PAM_AUTH_ERR; \
    goto memc_check_user_error; }
int memc_check_user(mc_conf_t *conf, const char *user, const char *password)
{
  int retval;
  memcached_return mc_ret;
  uint32_t mc_flags = 0;
  char pwdhash[33];
  char *cached_pwdhash = NULL;
  char *salt = NULL;
  char *key_pass;
  char *key_salt;
  size_t value_len;

  size_t key_len = sizeof(PAM_MC_NSPACE)+strlen(user)+strlen(conf->client_id)+15;
  key_pass = (char*) alloca(key_len);
  key_salt = (char*) alloca(key_len);

  size_t key_pass_len = sprintf(key_pass, "%s:%s:%s:pwdhash", PAM_MC_NSPACE, user, conf->client_id);
  size_t key_salt_len = sprintf(key_salt, "%s:%s:%s:salt", PAM_MC_NSPACE, user, conf->client_id);
  DPRINT(LOG_DEBUG, "%s(%d) %s(%d)", key_pass, key_pass_len, key_salt, key_salt_len);

  cached_pwdhash = memcached_get(conf->server, key_pass, key_pass_len, &value_len, &mc_flags, &mc_ret);
  MC_FAIL_CHECK("Cached pwdhash not found in memcached");
  DPRINT(LOG_DEBUG, "Got cached pwdhash: %s", cached_pwdhash);

  salt = memcached_get(conf->server, key_salt, key_salt_len, &value_len, &mc_flags, &mc_ret);
  MC_FAIL_CHECK("Salt not found in memcached");
  DPRINT(LOG_DEBUG, "Got salt: %s", salt);

  memc_hash_pwd(password, salt, pwdhash);
  DPRINT(LOG_DEBUG, "Got user   pwdhash: %s", pwdhash);

  if ( strcmp(cached_pwdhash, pwdhash) != 0 ) {
    DPRINT(LOG_DEBUG, "Password mismatch");
    retval = PAM_AUTH_ERR;
  } else {
    retval = PAM_SUCCESS;
  }

memc_check_user_error:

  _pam_forget(cached_pwdhash);
  _pam_forget(salt);

  return retval;
}

#undef MC_FAIL_CHECK
#define MC_FAIL_CHECK(msg, ...) if (mc_ret != MEMCACHED_SUCCESS) { \
   DPRINT(LOG_DEBUG, msg, ## __VA_ARGS__); \
   retval=PAM_AUTH_ERR; \
   goto memc_cache_user_error; }
int memc_cache_user(mc_conf_t *conf, const char *user, const char *password)
{
  int retval = PAM_SUCCESS;
  memcached_return mc_ret;
  char salt[11];
  char pwdhash[33];
  size_t value_len;
  uint32_t mc_flags;
  char *tmpval = 0;

  size_t key_len = sizeof(PAM_MC_NSPACE)+strlen(user)+strlen(conf->client_id)+15;
  char *key_pass = (char*) alloca(key_len);
  char *key_salt = (char*) alloca(key_len);

  size_t key_pass_len = sprintf(key_pass, "%s:%s:%s:pwdhash", PAM_MC_NSPACE, user, conf->client_id);
  size_t key_salt_len = sprintf(key_salt, "%s:%s:%s:salt", PAM_MC_NSPACE, user, conf->client_id);

  tmpval = memcached_get(conf->server, key_pass, key_pass_len, &value_len, &mc_flags, &mc_ret);
  _pam_forget(tmpval);
  if (mc_ret == MEMCACHED_SUCCESS ) {
    DPRINT(LOG_DEBUG, "Already cached!!!");
    return PAM_SUCCESS;
  }

  memc_gen_salt(salt, sizeof(salt)-1);
  memc_hash_pwd(password, salt, pwdhash);

  mc_ret = memcached_set(conf->server, key_pass, key_pass_len, pwdhash, sizeof(pwdhash), conf->memcache_lifetime, 0);
  MC_FAIL_CHECK("Unable to store pwdhash on server");

  mc_ret = memcached_set(conf->server, key_salt, key_salt_len, salt, sizeof(salt), conf->memcache_lifetime, 0);
  MC_FAIL_CHECK("Unable to store salt on server");

  retval = PAM_SUCCESS;

memc_cache_user_error:

  memset(salt, 0, sizeof(salt));
  memset(pwdhash, 0, sizeof(salt));

  return retval;
}

/**************************************************************************
 * GENERAL CODE
 **************************************************************************/



#define PAM_FAIL_CHECK(msg, ...) if (retval != PAM_SUCCESS) { \
  DPRINT(LOG_DEBUG, msg, ## __VA_ARGS__); \
  int *pret = malloc( sizeof(int) );                \
  *pret = retval;                                   \
  pam_set_data( conf->pamh, "mc_setcred_return"           \
                , (void *) pret, _int_free );       \
  return retval; }

static int mc_converse(mc_conf_t *conf, int msg_style, char *message, char **password)
{
  CONST struct pam_conv *conv;
  struct pam_message resp_msg;
  CONST struct pam_message *msg[1];
  struct pam_response *resp = NULL;
  int retval;

  resp_msg.msg_style = msg_style;
  resp_msg.msg = message;
  msg[0] = &resp_msg;

  /* grab the password */
  retval = pam_get_item(conf->pamh, PAM_CONV, (CONST void **) &conv);
  PAM_FAIL_CHECK("Unable get conv from pam");

  retval = conv->conv(1, msg, &resp,conv->appdata_ptr);
  PAM_FAIL_CHECK("conv failed");

  if (password) {       /* assume msg.type needs a response */
    *password = resp->resp;
    free(resp);
  }

  return PAM_SUCCESS;
}

PAM_EXTERN int 
pam_sm_authenticate(pam_handle_t *pamh,int flags,int argc,CONST char **argv)
{
//  CONST char *rhost;
  CONST char *user;
  char *password = NULL;
  int retval = PAM_AUTH_ERR;

  mc_conf_t config;
  mc_conf_t *conf = &config;

  _pam_parse(argc, argv, conf);
  conf->pamh = pamh;

  /* grab the user name */
  retval = pam_get_user(pamh, &user, NULL);
  PAM_FAIL_CHECK("Failed get user from pam");

  /* check that they've entered something, and not too long, either */
  if ((user == NULL) || (strlen(user) > MAXPWNAM)) {
    int *pret = malloc( sizeof(int) );
    *pret = PAM_USER_UNKNOWN;
    pam_set_data( pamh, "mc_setcred_return", (void *) pret, _int_free );

    DPRINT(LOG_DEBUG, "User name was NULL, or too long");
    return PAM_USER_UNKNOWN;
  }
  DPRINT(LOG_DEBUG, "Got user name %s", user);

  /*
   * If there's no client id specified, use the service type, to help
   * keep track of which service is doing the authentication.
   */
  if (!conf->client_id) {
    retval = pam_get_item(pamh, PAM_SERVICE, (CONST void **) conf->client_id);
    PAM_FAIL_CHECK("Failed getting service from pam");
  }

  /* now we've got a socket open, so we've got to clean it up on error */
#undef PAM_FAIL_CHECK
#define PAM_FAIL_CHECK(msg, ...) if (retval != PAM_SUCCESS) { \
  DPRINT(LOG_DEBUG, msg, ## __VA_ARGS__); \
  goto pam_sm_authenticate_error; }

  /* grab the password (if any) from the previous authentication layer */
  retval = pam_get_item(pamh, PAM_AUTHTOK, (CONST void **) &password);
  PAM_FAIL_CHECK("Failed getting password from previous layer");

  if(password) {
    password = strdup(password);
    DPRINT(LOG_DEBUG, "Got password %s", password);
  }

  /* no previous password: maybe get one from the user */
  if (!password) {
      retval = mc_converse(conf, PAM_PROMPT_ECHO_OFF, "Password: ", &password);
      PAM_FAIL_CHECK("Conversation failed");
  } /* end of password == NULL */

//  /* It's the IP address of the client. */
//  retval = pam_get_item(pamh, PAM_RHOST, (CONST void **) &rhost);
//  PAM_FAIL_CHECK;

  /*
   * Init data fro workin with memcache server
   */
  retval = memc_init(conf);
  PAM_FAIL_CHECK("Memcache init failed");
  DPRINT(LOG_DEBUG, "Memcached init ok!");

  // this place is for checking password
  retval = memc_check_user(conf, user, password);
  PAM_FAIL_CHECK("User checking in memcached failed");

pam_sm_authenticate_error:

  memc_free(conf);

  /* If there was a password pass it to the next layer */
  if (password && *password) {
    pam_set_item(pamh, PAM_AUTHTOK, password);
  }

  DPRINT(LOG_DEBUG, "authentication %s", retval==PAM_SUCCESS ? "succeeded":"failed" );

  _pam_forget(password);
  {
    int *pret = malloc( sizeof(int) );
    *pret = retval;
    pam_set_data( pamh, "mc_setcred_return", (void *) pret, _int_free );
  }
  return retval;
}

/*
 * Return a value matching the return value of pam_sm_authenticate, for
 * greatest compatibility. 
 * (Always returning PAM_SUCCESS breaks other authentication modules;
 * always returning PAM_IGNORE breaks PAM when we're the only module.)
 */
PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh,int flags,int argc,CONST char **argv)
{
  int retval, *pret;

  retval = PAM_SUCCESS;
  pret = &retval;
  pam_get_data( pamh, "mc_setcred_return", (CONST void **) &pret );
  return *pret;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
		    int argc, CONST char **argv)
{
  int retval;
  retval = PAM_SUCCESS;
  return retval;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
		     int argc, CONST char **argv)
{
  int retval;
  retval = PAM_SUCCESS;
  return retval;
}

#undef PAM_FAIL_CHECK
#define PAM_FAIL_CHECK(msg, ...) if (retval != PAM_SUCCESS) { \
  DPRINT(LOG_DEBUG, msg, ## __VA_ARGS__); \
  goto acc_mgmt_clean; }

/*
 *  Do nothing for account management.  This is apparently needed by
 *  some programs.
 */
PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh,int flags,int argc,CONST char **argv)
{
  int retval;
  CONST char *user;
  CONST char *password = NULL;
  retval = PAM_SUCCESS;

  mc_conf_t config;
  mc_conf_t *conf = &config;

  _pam_parse(argc, argv, conf);
  conf->pamh = pamh;

  /* grab the user name */
  retval = pam_get_user(pamh, &user, NULL);
  PAM_FAIL_CHECK("Unable get user from pam");

  /* check that they've entered something, and not too long, either */
  if ((user == NULL) ||
      (strlen(user) > MAXPWNAM)) {
    int *pret = malloc( sizeof(int) );
    *pret = PAM_USER_UNKNOWN;

    DPRINT(LOG_DEBUG, "User name was NULL, or too long");
    return PAM_USER_UNKNOWN;
  }
  DPRINT(LOG_DEBUG, "Got user name %s", user);

  /*
   * If there's no client id specified, use the service type, to help
   * keep track of which service is doing the authentication.
   */
  if (!conf->client_id) {
    retval = pam_get_item(pamh, PAM_SERVICE, (CONST void **) conf->client_id);
    PAM_FAIL_CHECK("Unable get service from pam");
  }

  /* grab the password (if any) from the previous authentication layer */
  retval = pam_get_item(pamh, PAM_AUTHTOK, (CONST void **) &password);
  PAM_FAIL_CHECK("Unable get password from previous layer");

  if (password) {
    password = strdup(password);
    DPRINT(LOG_DEBUG, "Got password %s", password);
  } else {
    /* no previous password: maybe get one from the user */
    if (conf->ctrl & PAM_MC_ACCT_MGMT_CONVERSE) {
      retval = mc_converse(conf, PAM_PROMPT_ECHO_OFF, "Password: ", &password);
      PAM_FAIL_CHECK("Conversation failed");
    } else {
      _pam_log(LOG_WARNING, "Not found password on previous authentication layer");
      retval = PAM_AUTH_ERR;
      goto acc_mgmt_clean;
    }
  }

#undef PAM_FAIL_CHECK
#define PAM_FAIL_CHECK(msg, ...) if (retval != PAM_SUCCESS) { \
  DPRINT(LOG_DEBUG, msg, ## __VA_ARGS__); \
  memc_free(conf); \
  goto acc_mgmt_clean; }

  /*
   * Init data for working with memcache server
   */
  retval = memc_init(conf);
  PAM_FAIL_CHECK("Memcache init failed");

  retval = memc_cache_user(conf, user, password);
  PAM_FAIL_CHECK("Caching of user failed");

  memc_free(conf);

acc_mgmt_clean:

  _pam_forget(password);

  return retval;
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_radius_modstruct = {
  "pam_radius_auth",
  pam_sm_authenticate,
  pam_sm_setcred,
  pam_sm_acct_mgmt,
  pam_sm_open_session,
  pam_sm_close_session,
  pam_sm_chauthtok,
};
#endif

