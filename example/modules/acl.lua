-- ACL, access control list
--
-- REQUEST: curl 127.0.0.1:8080/hi --interface 127.0.0.1 -v
-- EXPECT: 403 Forbidden
--
-- REQUEST: curl 127.0.0.1:8080/hi --interface 127.0.0.2 -v
-- EXPECT: hello, world!
--
-- REQUEST: curl 127.0.0.1:8080/hi --interface 127.0.0.3 -v
-- EXPECT: 403 Forbidden
--
--
-- REQUEST: curl 127.0.0.1:8081/hi --interface 127.0.0.1
-- EXPECT: 403 Forbidden
--
-- REQUEST: curl 127.0.0.1:8081/hi --interface 127.0.0.2
-- EXPECT: hello, world!

Listen "8080" {
    acl = {
        "!127.0.0.1/32", -- '!' means "deny"
        "127.0.0.2", -- the last rule is "allow", so the default rule is "deny"
    },
    echo = "hello, world!\n",
}

Listen "8081" {
    acl = {
        "!127.0.0.1", -- the last rule is "deny", so the default rule is "allow"
    },
    echo = "hello, world!\n",
}
