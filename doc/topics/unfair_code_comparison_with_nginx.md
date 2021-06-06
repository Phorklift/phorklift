Here we compare source code between nginx-1.14.0 and h2tpd.

# Lines of source code

We must declare that this comparison is very unfair, because:

- Nginx is much more complete and has more functions, but h2tpd is
  still under development.
  This is mainly reflected in modules.

- Nginx has been developed for many years, so there are many duplicated
  codes all around. While h2tpd is developed from the ground-up, so it's
  clear by now.

- Nginx supports several OS but h2tpd supports Linux only by now.
  This is mainly reflected in Nginx's src/event/.

So it's very reasonable that nginx has more code than h2tpd. But the
comparison still gives some information.

This table shows lines of source code of nginx and h2tpd for each part.

    ```
    ----------+-------------------------+----------------------------
              |            nginx-1.14.0 | h2tpd-git-xxxxxxxx
    ==========+=========================+============================
    main      |         src/http/ 24698 | 6804 src/
    ----------+-------------------------+----------------------------
    event     |        src/event/ 10749 | 837  src/libloop/
    ----------+-------------------------+----------------------------
    utilities |         src/core/ 20860 | 4165 src/libwuya/
    ----------+-------------------------+----------------------------
    modules   | src/http/modules/ 41396 | 2602 src/modules/
    ----------+-------------------------+----------------------------
    http2     |      src/http/v2/  8935 | 978  src/libhttp2/
              |                         | 5486 src/libhttp2/libhpack/
    ----------+-------------------------+----------------------------
    lua       |  lua-nginx-module 37259 | 544  src/luaapis/
    ----------+-------------------------+----------------------------
    TOTAL     |          106638 + 37259 | 21416
    -----------------------------------------------------------------
    ```


# Some better points than nginx

Nginx's source code is very good. And I was greatly influenced by it,
which you can see in h2tpd. But h2tpd still has some points
better than nginx in my opinion.

1. h2tpd organizes some code in independent libraries, including
   `libwuya`, `libloop`, `libhttp2` and `libhpack`. The main
   code calls these libraries by API only, but can not access their
   internal data. This makes the code clearer.
   Besides, because these libraries do not depend on any h2tpd structure
   or code, they can be used by other programs. In fact `libwuya` and
   `libloop` were used by other programs before h2tpd.

2. h2tpd tries to avoid mutable function pointer.
   There are some mutable function pointers in Nginx such as the handlers
   in `ngx_http_request_t`, `ngx_http_upstream_t`, and `ngx_event_t`. It's
   very hard to understand and follow them when first reading the code.

3. h2tpd tries to avoid too many flags in structure.
   There are many flags (in `unsigned xx:1` type) in Nginx, e.g.
   `ngx_http_request_t`. I think it's impossible to point out the meaning
   of each flag for most readers.

4. h2tpd tries to avoid too long functions.
   There are many functions longer than 100 lines in Nginx, but none in h2tpd.
