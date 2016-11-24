#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <syslog.h>

#include <libmemcached/memcached.h>
#include <openssl/md5.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#define MOD_DEFAULT_EXPIRE_TIME (15*60) // 15 min
#define MOD_DEFAULT_SALT_LENGTH (16)

typedef enum mod_action {
  MOD_ACTION_UNDEFINED,
  MOD_ACTION_AUTH,
  MOD_ACTION_CACHE,
  MOD_ACTION_INVALID
} mod_action_t;

typedef struct mod_conf {
  mod_action_t action;
  const char *memcached_config;
  const char *key_prefix;
  const char *service;
  unsigned long expire_time;
  unsigned long salt_length;
  bool debug;
} mod_conf_t;

static const char mod_default_memcached_config[] = "--server=localhost";
static const char mod_default_key_prefix[] = "mc_auth_cache";

bool strtoul_safe(const char *str, unsigned long *out, int base) {
  errno = 0;
  char *endptr = NULL;
  *out = strtoul(str, &endptr, base);
  if ((errno == ERANGE) || (str == endptr)) {
    return false;
  }
  if (isspace(*endptr) || (*endptr == '\0' && endptr != str)) {
    if ((long) *out < 0) {
      if (strchr(str, '-')) {
        return false;
      }
    }
    return true;
  }

  return false;
}

static void mod_gen_salt(char *salt, size_t len) {
  for (size_t i = 0; i < len; i++) {
    salt[i] = (char) (26 * (rand() / (RAND_MAX + 1.0)) + 97);
  }
}

static void mod_hash_pass(const char *pass, size_t pass_len, const char *salt, size_t salt_len, char *hexdigest) {
  MD5_CTX ctx;
  uint8_t digest[MD5_DIGEST_LENGTH];

  MD5_Init(&ctx);
  MD5_Update(&ctx, pass, pass_len);
  MD5_Update(&ctx, salt, salt_len);
  MD5_Final(digest, &ctx);

  for (size_t i = 0; i < MD5_DIGEST_LENGTH; i++) {
    sprintf(&hexdigest[i * 2], "%02x", digest[i]);
  }
}

static bool mod_parse_args(pam_handle_t *pamh, mod_conf_t *conf, int argc, const char *argv[]) {
  // set defaults
  memset(conf, 0, sizeof(*conf));
  conf->memcached_config = mod_default_memcached_config;
  conf->key_prefix = mod_default_key_prefix;
  conf->expire_time = MOD_DEFAULT_EXPIRE_TIME;
  conf->salt_length = MOD_DEFAULT_SALT_LENGTH;

  bool success = true;
  for (int i = 0; i < argc; i++) {
    const char *value = strchr(argv[i], '=');

    if (!value || (argv[i] == value)) {
      pam_syslog(pamh, LOG_ERR, "invalid option '%s'", argv[i]);
      success = false;
      continue;
    }

    size_t key_len = value - argv[i];
    value++;

    if (!strncasecmp(argv[i], "action", key_len)) {
      if (!strcasecmp(value, "auth")) {
        conf->action = MOD_ACTION_AUTH;
      } else if (!strcasecmp(value, "cache")) {
        conf->action = MOD_ACTION_CACHE;
      } else {
        pam_syslog(pamh, LOG_ERR, "invalid option '%s'", argv[i]);
        conf->action = MOD_ACTION_INVALID;
        success = false;
      }
    } else if (!strncasecmp(argv[i], "config", key_len)) {
      conf->memcached_config = value;
    } else if (!strncasecmp(argv[i], "prefix", key_len)) {
      conf->key_prefix = value;
    } else if (!strncasecmp(argv[i], "service", key_len)) {
      conf->service = value;
    } else if (!strncasecmp(argv[i], "expire", key_len)) {
      if (!strtoul_safe(value, &conf->expire_time, 10)) {
        pam_syslog(pamh, LOG_ERR, "invalid option '%s'", argv[i]);
        success = false;
      }
    } else if (!strncasecmp(argv[i], "salt_length", key_len)) {
      if (!strtoul_safe(value, &conf->salt_length, 10)) {
        pam_syslog(pamh, LOG_ERR, "invalid option '%s'", argv[i]);
        success = false;
      }
    } else if (!strncasecmp(argv[i], "debug", key_len)) {
      unsigned long val = 0;
      if (!strtoul_safe(value, &val, 10)) {
        pam_syslog(pamh, LOG_ERR, "invalid option '%s'", argv[i]);
        success = false;
      }
      conf->debug = (val != 0);
    } else {
      pam_syslog(pamh, LOG_ERR, "unknown option '%s'", argv[i]);
    }
  }

  if (conf->action == MOD_ACTION_UNDEFINED) {
    pam_syslog(pamh, LOG_ERR, "missing option 'action'");
    success = false;
  }

  return success;
}

static int mod_check_pass(pam_handle_t *pamh, mod_conf_t *conf, const char *user, const char *pass) {
  struct memcached_st *mc = NULL;
  memcached_return_t mcret;
  uint32_t mcflags = 0;

  char *pass_key = NULL, *salt_key = NULL;
  char *pass_hash = NULL, *salt = NULL;

  int retval = PAM_SERVICE_ERR;

  mc = memcached(conf->memcached_config, strlen(conf->memcached_config));
  if (!mc) {
    pam_syslog(pamh, LOG_ERR, "auth: failed to initialize memcached instance");
    goto end;
  }

  ssize_t pass_key_len = asprintf(&pass_key, "%s:%s:%s:pwdhash", conf->key_prefix, user, conf->service);
  if (pass_key_len <= 0) {
    retval = PAM_BUF_ERR;
    goto end;
  }

  size_t pass_hash_len = 0;
  pass_hash = memcached_get(mc, pass_key, (size_t) pass_key_len, &pass_hash_len, &mcflags, &mcret);
  if (mcret == MEMCACHED_NOTFOUND) {
    if (conf->debug)
      pam_syslog(pamh, LOG_DEBUG, "auth: password hash not found in memcached (key=%s)", pass_key);
    retval = PAM_USER_UNKNOWN;
    goto end;
  } else if (mcret != MEMCACHED_SUCCESS) {
    if (conf->debug)
      pam_syslog(pamh, LOG_DEBUG, "auth: failed to get password hash from memcached (key=%s, error=%s)",
                 pass_key, memcached_strerror(mc, mcret));
    retval = PAM_SERVICE_ERR;
    goto end;
  }

  if (conf->debug)
    pam_syslog(pamh, LOG_DEBUG, "auth: fetched password hash from memcached ('%s'='%s')", pass_key, pass_hash);

  ssize_t salt_key_len = asprintf(&salt_key, "%s:%s:%s:salt", conf->key_prefix, user, conf->service);
  if (salt_key_len <= 0) {
    retval = PAM_BUF_ERR;
    goto end;
  }

  size_t salt_len = 0;
  salt = memcached_get(mc, salt_key, (size_t) salt_key_len, &salt_len, &mcflags, &mcret);
  if (mcret == MEMCACHED_NOTFOUND) {
    if (conf->debug)
      pam_syslog(pamh, LOG_DEBUG, "auth: salt not found in memcached (key=%s)", salt_key);
    retval = PAM_USER_UNKNOWN;
    goto end;
  } else if (mcret != MEMCACHED_SUCCESS) {
    if (conf->debug)
      pam_syslog(pamh, LOG_DEBUG, "auth: failed to get salt from memcached (key=%s, error=%s)",
                 pass_key, memcached_strerror(mc, mcret));
    retval = PAM_SERVICE_ERR;
    goto end;
  }

  if (conf->debug)
    pam_syslog(pamh, LOG_DEBUG, "auth: fetched salt from memcached ('%s'='%s')", salt_key, salt);

  char hexdigest[MD5_DIGEST_LENGTH * 2 + 1];
  mod_hash_pass(pass, strlen(pass), salt, (size_t) salt_len, hexdigest);
  if (conf->debug)
    pam_syslog(pamh, LOG_DEBUG, "auth: md5(%s%s)=%s", pass, salt, hexdigest);

  if (strcmp(pass_hash, hexdigest)) {
    if (conf->debug)
      pam_syslog(pamh, LOG_DEBUG, "auth: password mismatch for user %s@%s", user, conf->service);
    retval = PAM_AUTH_ERR;
    goto end;
  }

  retval = PAM_SUCCESS;

  end:
  if (salt) free(salt);
  if (pass_hash) free(pass_hash);
  if (salt_key) free(salt_key);
  if (pass_key) free(pass_key);
  if (mc) memcached_free(mc);
  return retval;
}

static int mod_cache_pass(pam_handle_t *pamh, mod_conf_t *conf, const char *user, const char *pass) {
  struct memcached_st *mc = NULL;
  memcached_return_t mcret;

  char *salt = NULL;
  char *pass_key = NULL, *salt_key = NULL;

  int retval = PAM_SERVICE_ERR;

  mc = memcached(conf->memcached_config, strlen(conf->memcached_config));
  if (!mc) {
    pam_syslog(pamh, LOG_ERR, "cache: failed to initialize memcached instance");
    goto end;
  }

  salt = malloc(conf->salt_length + 1);
  if (!salt) {
    retval = PAM_BUF_ERR;
    goto end;
  }
  mod_gen_salt(salt, conf->salt_length);
  salt[conf->salt_length] = '\0';

  ssize_t salt_key_len = asprintf(&salt_key, "%s:%s:%s:salt", conf->key_prefix, user, conf->service);
  if (salt_key_len <= 0) {
    retval = PAM_BUF_ERR;
    goto end;
  }

  mcret = memcached_set(mc, salt_key, (size_t) salt_key_len, salt, conf->salt_length, conf->expire_time, 0);
  if (mcret != MEMCACHED_SUCCESS) {
    if (conf->debug)
      pam_syslog(pamh, LOG_DEBUG, "cache: fail to save salt into memcached (key=%s, error=%s)",
                 salt_key, memcached_strerror(mc, mcret));
    retval = PAM_SERVICE_ERR;
    goto end;
  }

  if (conf->debug)
    pam_syslog(pamh, LOG_DEBUG, "cache: saved salt into memcached ('%s'='%s')", salt_key, salt);

  ssize_t pass_key_len = asprintf(&pass_key, "%s:%s:%s:pwdhash", conf->key_prefix, user, conf->service);
  if (pass_key_len <= 0) {
    retval = PAM_BUF_ERR;
    goto end;
  }

  char hexdigest[MD5_DIGEST_LENGTH * 2 + 1];
  mod_hash_pass(pass, strlen(pass), salt, conf->salt_length, hexdigest);
  if (conf->debug)
    pam_syslog(pamh, LOG_DEBUG, "cache: md5(%s%s)=%s", pass, salt, hexdigest);

  mcret = memcached_set(mc, pass_key, (size_t) pass_key_len, hexdigest, MD5_DIGEST_LENGTH * 2, conf->expire_time, 0);
  if (mcret != MEMCACHED_SUCCESS) {
    if (conf->debug)
      pam_syslog(pamh, LOG_DEBUG, "cache: fail to save password hash into memcached (key=%s, error=%s)",
                 salt_key, memcached_strerror(mc, mcret));
    retval = PAM_SERVICE_ERR;
    goto end;
  }

  if (conf->debug)
    pam_syslog(pamh, LOG_DEBUG, "cache: password hash saved into memcached ('%s'='%s')", pass_key, hexdigest);

  retval = PAM_SUCCESS;

  end:

  if (pass_key) free(pass_key);
  if (salt_key) free(salt_key);
  if (salt) free(salt);
  if (mc) memcached_free(mc);
  return retval;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char *argv[]) {
  (void) flags;

  mod_conf_t conf;
  int ret = 0;

  if (!mod_parse_args(pamh, &conf, argc, argv)) {
    return PAM_SERVICE_ERR;
  }

  const char *user = NULL;
  ret = pam_get_user(pamh, &user, NULL);
  if (ret != PAM_SUCCESS) {
    if (conf.debug)
      pam_syslog(pamh, LOG_ERR, "failed to get username from pam: %s", pam_strerror(pamh, ret));
    return PAM_SERVICE_ERR;
  }

  const char *pass = NULL;

  ret = pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);
  if (ret != PAM_SUCCESS) {
    if (conf.debug)
      pam_syslog(pamh, LOG_ERR, "failed to get password from pam: %s", pam_strerror(pamh, ret));
    return PAM_SERVICE_ERR;
  }

  if (!pass) {
    pass = "";
  }

  if (!conf.service) {
    ret = pam_get_item(pamh, PAM_SERVICE, (const void **) &conf.service);
    if (ret != PAM_SUCCESS || !conf.service) {
      if (conf.debug)
        pam_syslog(pamh, LOG_ERR, "failed to get service name from pam: %s", pam_strerror(pamh, ret));
      return PAM_SERVICE_ERR;
    }
  }

  if (conf.action == MOD_ACTION_AUTH) {
    ret = mod_check_pass(pamh, &conf, user, pass);
    if (conf.debug) {
      if (ret == PAM_SUCCESS) {
        pam_syslog(pamh, LOG_DEBUG, "auth: success for %s:%s@%s", user, pass, conf.service);
      } else if (conf.debug) {
        pam_syslog(pamh, LOG_DEBUG, "auth: fail for %s:%s@%s", user, pass, conf.service);
      }
    }
    return ret;
  } else {
    ret = mod_cache_pass(pamh, &conf, user, pass);
    if (conf.debug) {
      if (ret == PAM_SUCCESS) {
        pam_syslog(pamh, LOG_DEBUG, "cache: success for %s:%s@%s", user, pass, conf.service);
      } else {
        pam_syslog(pamh, LOG_DEBUG, "cache: fail for %s:%s@%s", user, pass, conf.service);
      }
    }
    return ret;
  }
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  (void) pamh;
  (void) flags;
  (void) argc;
  (void) argv;
  return PAM_SUCCESS;
}

#ifdef PAM_STATIC
struct pam_module _pam_memcached_modstruct = {
  "pam_memcached",
  pam_sm_authenticate,
  pam_sm_setcred,
  NULL,
  NULL,
  NULL,
  NULL,
};
#endif
