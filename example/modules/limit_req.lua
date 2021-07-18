-- Request frequency limit.
--
-- The client is identified by network address, unless `key` is set.
--
--
-- REQUEST: curl 127.0.0.1:8080/1
-- EXPECT: hello, world!
--
-- REQUEST: curl 127.0.0.1:8080/1
-- EXPECT: limited
--
-- REQUEST: sleep 2.1; curl 127.0.0.1:8080/1
-- EXPECT: hello, world!
--
--
-- REQUEST: curl 127.0.0.1:8080/burst2
-- EXPECT: hello, world!
--
-- REQUEST: curl 127.0.0.1:8080/burst2
-- EXPECT: hello, world!
--
-- REQUEST: curl 127.0.0.1:8080/burst2
-- EXPECT: limited
--
--
-- REQUEST: curl 127.0.0.1:8080/key?id=123
-- EXPECT: hello, world!
--
-- REQUEST: curl 127.0.0.1:8080/key?id=456
-- EXPECT: hello, world!
--
-- REQUEST: curl 127.0.0.1:8080/key?id=456
-- EXPECT: limited

Runtime {
    worker = 1
}

Listen "8080" {
    echo = "hello, world!\n",
    limit_req = { 1, page="limited!\n" }, -- 1 r/s, default for all Path()

    Path "/1" {
    },
    Path "/burst2" {
        limit_req = { burst = 2 }
    },
    Path "/key" {
        limit_req = { key = function() return phl.req.get_uri_query("id") end }
    },
}
