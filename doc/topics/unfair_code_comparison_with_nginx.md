Here we compare source code between nginx-1.14.0 and Phorklift.

# Lines of source code

We must declare that this comparison is very unfair, because:

- Nginx is much more complete and has more functions, but Phorklift is
  still under development.
  This is mainly reflected in modules.

- Nginx has been developed for many years, so many parts of the code may contain duplicates. As Phorklift has been developed from the ground up, it contains much less duplicated code.

- Nginx supports several Operating Systems, but Phorklift currently supports Linux only.
  This is mainly reflected in Nginx's src/event/.

So it's a very reasonable assumption that Nginx has more code than Phorklift, but the
comparison still gives some information.

This table shows lines of source code for Nginx and Phorklift grouped by purpose.

    ----------+-------------------------+----------------------------
              |            nginx-1.14.0 | phorklift-git-xxxxxxxx
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


# Some advantages over Nginx

Nginx's source code is very good and I was greatly influenced by it,
which you can see in Phorklift. But, Phorklift still has some advantages over Nginx in my opinion.

1. Phorklift organizes some code into independent libraries, including
   `libwuya`, `libloop`, `libhttp2` and `libhpack`. The main
   code calls these libraries by API only, but can not access their
   internal data, thus making the code clearer.
   Besides, because these libraries do not depend on any of Phorklift's structure
   or code, they can be used by other programs. In fact `libwuya` and
   `libloop` were used by other programs before Phorklift.

2. Phorklift tries to avoid using mutable function pointers.
   There are some mutable function pointers in Nginx such as the handlers
   in `ngx_http_request_t`, `ngx_http_upstream_t`, and `ngx_event_t`. It's
   very hard to understand and follow them when first reading the code.

3. Phorklift tries to avoid too many flags in structure.
   There are many flags (in `unsigned xx:1` type) in Nginx, e.g.
   `ngx_http_request_t`. I think it's impossible to point out the meaning
   of each flag for most readers.

4. Phorklift tries to avoid functions that are too long.
   There are many functions longer than 100 lines in Nginx, but none in Phorklift.
