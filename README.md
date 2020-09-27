# [Geoip2Influx](https://github.com/gilbN/geoip2influx)

Fork of [Geoip2Influx](https://github.com/gilbN/geoip2influx), refactoring the code, removing the dependency to geo2ip nginx module, and adding docker support for arm targets.

Nginx.cong log configuration:

```
log_format custom '$remote_addr - $remote_user [$time_local]'
 11            '"$request" $status $body_bytes_sent'
 12            '"$http_referer" $host "$http_user_agent"'
 13            '"$request_time" "$upstream_connect_time"';
 14 access_log  /var/log/nginx/vivc/access.log custom;
 ```
