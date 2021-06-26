I know this comparison is unfair too. But let's do it anyway!

# Machine

A virtual machine with Intel(R) Xeon(R) CPU E5-2682 v4 @ 2.50GHz, 4 cores.

The test client and server (Nginx and Phorklift) are at the same matchine.

The result numbers have little meaning. The comparison is the point.


# Test Cases

Response:

- echo, response a static string
- static, response a file as static service
- proxy, pass requests to backend as reverse-proxy

Concurrent:

- a), HTTP1, 10 concurrent connections
- b), HTTP1, 100 connections connections
- c), HTTP2, 10 concurrent connections and 10 streams
- d), HTTP2, 100 concurrent connections and 10 streams
- e), HTTP2, 10 concurrent connections and 100 streams


# Result

Phorklift is faster than Nginx in all cases, and much faster in most HTTP2 cases.

    ----------+---------+-----------+--------
      r/s     |  nginx  | phorklift |  rate
    ==========+=========+===========+========
      echo a) |  53.3k  |   66.6k   |   1.2
           b) |  50.2k  |   76.6k   |   1.5
           c) |  72.3k  |  228.9k   |   3.2
           d) |  65.2k  |  174.2k   |   2.7
           e) |  76.4k  |  304.6k   |   4.0
    static a) |  28.1k  |   43.8k   |   1.5
           b) |  29.2k  |   52.3k   |   1.8
           c) |  38.8k  |  105.9k   |   2.7
           d) |  34.9k  |   94.7k   |   2.7
           e) |  40.1k  |   98.3k   |   2.5
     proxy a) |  24.2k  |   27.9k   |   1.1
           b) |  22.3k  |   33.1k   |   1.5
           c) |  32.8k  |   54.0k   |   1.6
           d) |  18.8k  |   28.8k   |   1.5
           e) |  15.6k  |   22.2k   |   1.4
    ----------+---------+-----------+--------

# Nginx Configuration

  ```
  worker_processes  1;
  
  events {
      worker_connections 10000;
  }

  http {
      upstream backend {
          server 127.0.0.1:8282;
          keepalive 100;
      }
      server {
          listen              1447 ssl http2;
          ssl_certificate     misc/unsafe-test-only.crt;
          ssl_certificate_key misc/unsafe-test-only.key;
          keepalive_requests  100000;
          http2_max_requests  100000;
  
          location /echo {
              return 200 "hello, world!\n";
          }
          location /static {
              root src/;
          }
          location /proxy {
              proxy_http_version 1.1;
              proxy_set_header Connection "";
              proxy_pass http://backend;
          }
      }
  }
  ```

# Phorklift Configuration

  ```Lua
  Runtime {
      worker = 1
  }
  
  Listen "1449" {
      ssl = {
          certificate = "misc/unsafe-test-only.crt",
          private_key = "misc/unsafe-test-only.key",
      },
      Path "/echo" {
          echo = "hello, world!\n",
      },
      Path "/static" {
          static = "src/",
      },
      Path "/proxy" {
          proxy = {{ "127.0.0.1:8282" }},
      },
  }
  ```

# Origin Backend Phorklift Configuration

  ``` Lua
  Listen "8282" {
      echo = "hello, world!\n",
  }
  ```


# Client

We use [h2load](https://nghttp2.org/documentation/h2load-howto.html) as client.

Here is the script:

  ```bash
  run()
  {
    uri=$1
    ./h2load -n100000 -c10  --h1 $uri | grep -efinished -esucceeded
    ./h2load -n100000 -c100 --h1 $uri | grep -efinished -esucceeded
    ./h2load -n100000 -c10  -m10 $uri | grep -efinished -esucceeded
    ./h2load -n100000 -c100 -m10 $uri | grep -efinished -esucceeded
    ./h2load -n100000 -c10 -m100 $uri | grep -efinished -esucceeded
  }
  
  run https://127.0.0.1:1447/echo
  run https://127.0.0.1:1449/echo
  run https://127.0.0.1:1447/static
  run https://127.0.0.1:1449/static
  run https://127.0.0.1:1447/proxy
  run https://127.0.0.1:1449/proxy
  ```
