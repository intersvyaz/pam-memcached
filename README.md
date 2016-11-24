pam-memcached
============

PAM module for caching authentication results in memcached and reuse them later.

#### Configuration example
```
auth    [success=done auth_err=die default=ignore]    pam_memcached.so  action=auth service=http
auth    [success=ok default=die]                      pam_unix.so
auth    [default=ignore]                              pam_memcached.so  action=cache service=http
```

#### Available options
- `action` - one of `auth` or `cache`, required value;
- `config` - memcached configuration string, default value is `--server=localhost`;
- `prefix` - memcached key prefix, default value is `mc_auth_cache`;
- `service` - service name, if no value provided, then module will try to get service name from PAM;
- `expire_time` - memcached expiration time in seconds, default value is 15 mins;
- `salt_length` - salt length to generate, default value is 16 symbols;
- `debug` - enable extra debug logging to syslog.


