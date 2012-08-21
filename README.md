# pam_memcache2

Based on pam_radius_auth code.
Uses libmemcached version 0.38 and later.

How it works:
At start pam_memcached2 fails because no data stored in memcached server.
Then pam tries nex auth module, if it success then invoked accounting part of pam_memcache2 witch stores auth data in memcached server.
At next invokation of pam_memcache2 auth there will be data in server and all will be done sucessfully.
Default key liftime in mecached server 15 minutes.

Use like this:
```
auth sufficient pam_memcache2.so server=<addr_here> client_id=<service_here>
<here goes some other auth modules>
account optional pam_memcache2.so server=<server_here> client_id=<service_here> acct_mgmt_converse
```

See sources for more features and details.