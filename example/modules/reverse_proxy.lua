-- Reverse Proxy.
--
-- REQUEST: curl http://127.0.0.1:8080/hi
-- EXPECT: hello, world!
--

local upstream = {
    "127.0.0.1:8081",
    "127.0.0.1:8082",
    "127.0.0.1:8083#0.01", -- weight=0.01
    max_retries = 2,
}

Listen "8080" {
    proxy = { upstream },
}

Listen "8083" {
    echo = "hello, world!\n",
}
