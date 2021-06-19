-- Multiple Hosts, AKA virtual servers.
--
-- Wildcard `*` can be used at the head or tail of hostname, but not both.
-- It must be right next to `.` if used. For example, "*.foo.com" if valid,
-- while "*x.foo.com" is invalid.
--
-- The string "*" is used to match everything.
--
-- For each request, Phorklift locates Host using longest match. Specifically
-- in the following order:
--
--   * exactly match (no `*`),
--   * the longest subfix match (leading `*` hostname, e.g. "*.foo.com"),
--   * the longest prefix match (tail `*` hostname, e.g. "www.foo.*"),
--   * the "*".
--
-- The order in which Host appears in Listen scope is irrelevant.
--
--
-- REQUEST: curl http://127.0.0.1:8080/hi -H'Host: www.example.com'
-- EXPECT: hello, www!
--
-- REQUEST: curl http://127.0.0.1:8080/hi -H'Host: static.example.com'
-- EXPECT: hello, static!
--
-- REQUEST: curl http://127.0.0.1:8080/hi -H'Host: hellooo.example.com'
-- EXPECT: hello, prefix-*!
--
-- REQUEST: curl http://127.0.0.1:8080/hi -H'Host: hellooo.step2.example.com'
-- EXPECT: hello, longer prefix-*!
--
-- REQUEST: curl http://127.0.0.1:8080/hi -H'Host: www.example.org'
-- EXPECT: hello, subfix-*!
--
-- REQUEST: curl http://127.0.0.1:8080/hi
-- EXPECT: hello, *!

Listen "8080" {
    Host "www.example.com" {
        echo = "hello, www!\n",
    },

    Host "img.example.com" "static.example.com" {
        echo = "hello, static!\n",
    },

    Host "*.example.com" {
        echo = "hello, prefix-*!\n",
    },
    Host "*.step2.example.com" {
        echo = "hello, longer prefix-*!\n",
    },

    Host "www.example.*" {
        echo = "hello, subfix-*!\n",
    },

    Host "*" {
        echo = "hello, *!\n",
    },
}

-- different SSL settings (certificate, session timeout, etc) can be set for Hosts
Listen "1443" {
    Host "www.example.com" {
        ssl = {
            certificate = "../misc/unsafe-test-only.crt",
            private_key = "../misc/unsafe-test-only.key",
        },
        echo = "hello, www!\n",
    },
    Host "img.example.com" {
        ssl = {
            certificate = "../misc/unsafe-test-only.crt",
            private_key = "../misc/unsafe-test-only.key",
        },
        echo = "hello, img!\n",
    },
}
