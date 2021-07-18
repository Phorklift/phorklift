-- Static file service.
--
-- REQUEST: curl -v http://127.0.0.1:8080/01.hello_world.lua
-- EXPECT: hello, world!
--
-- REQUEST: curl http://127.0.0.1:8080/
-- EXPECT: 01.hello_world.lua
--
-- REQUEST: curl http://127.0.0.1:8080/modules/
-- EXPECT: static_service.lua
--
-- REQUEST: curl -v http://127.0.0.1:8080/01.hello_world.lua -H'Range: bytes=1-20'
-- EXPECT: 206 Partial Content
--
-- REQUEST: curl -v http://127.0.0.1:8080/01.hello_world.lua -H"If-Modified-Since: `curl -v http://127.0.0.1:8080/01.hello_world.lua 2>&1 | grep 'Last-Modified' | cut -d':' -f2- | sed 's/\r//' `"
-- EXPECT: 304 Not Modified
--
-- REQUEST: curl http://127.0.0.1:8081/
-- EXPECT: hello, HTTPS world!

Listen "8080" {
    static = { "good_confs/", enable_list_dir=true }
}
Listen "8081" {
    static = { "good_confs/", index="03.ssl.lua" }
}
