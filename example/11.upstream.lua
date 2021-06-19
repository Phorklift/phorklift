-- Upstream, healthcheck, loadbalance.
--
-- REQUEST: curl http://127.0.0.1:8080/down
-- EXPECT: hello, world!
--
-- REQUEST: curl -v http://127.0.0.1:8080/status503
-- EXPECT: 503 Service Unavailable
--
-- REQUEST: curl http://127.0.0.1:8080/retry_status503
-- EXPECT: hello, world!
--
-- REQUEST: curl http://127.0.0.1:8080/hash?id=1234
-- EXPECT: hello, world!
--
-- REQUEST: curl http://127.0.0.1:8080/hash?id=1234
-- EXPECT: hello, world!
--
-- REQUEST: curl http://127.0.0.1:8080/hash?id=1234
-- EXPECT: hello, world!

local down_upstream = {
    "127.0.0.1:8083", -- down
    "127.0.0.1:8081#0.01", -- live, weight=0.01
    max_retries = 1,
}
local status503_upstream = {
    "127.0.0.1:8082", -- return 503
    "127.0.0.1:8081#0.01", -- live, weight=0.01
    max_retries = 1,
}
local retry_status503_upstream = {
    "127.0.0.1:8082", -- return 503
    "127.0.0.1:8081#0.01", -- live, weight=0.01
    max_retries = 1,
    retry_status_codes = { 503 },
}
local hash_upstream = {
    "127.0.0.1:8081",
    "127.0.0.1:8082",
    "127.0.0.1:8083",
    hash = function() return phl.req.get_uri_query("id") end,
}

Listen "8080" {
    Path "/down" {
        proxy = { down_upstream },
    },
    Path "/status503" {
        proxy = { status503_upstream },
    },
    Path "/retry_status503" {
        proxy = { retry_status503_upstream },
    },
    Path "/hash" {
        proxy = { hash_upstream },
    },
}

-- backend
Listen "8081" {
    echo = "hello, world!\n",
}
Listen "8082" {
    echo = { "not avaiable now!\n",
        status_code = 503 },
}
