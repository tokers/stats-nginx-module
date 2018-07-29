Name
====

**stats-nginx-module** - stats aggregation continuously.


Status
======

This Nginx module is still experimental.


Synopsis
========

```nginx
http {
    stats_format main '${remote_addr:i} $bytes_sent $body_bytes_sent';
    stats_zone $http_host zone=stats:10m format=main;

    server {
        listen 8080;

        location / {
            return 200 "hello";
            stats zone=stats;
        }

        location /echo {
            stats_echo key=$http_host zone=stats;
        }

        location /dump {
            stats_echo zone=stats clear;
        }
    }
}
```
