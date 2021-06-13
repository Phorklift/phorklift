-- Basic access authentication.
--
--
-- REQUEST: curl -v 127.0.0.1:8080/
-- EXPECT: 401 Unauthorized
--
-- REQUEST: curl 127.0.0.1:8080/ -uhello:auth
-- EXPECT: hello, world!

Listen "8080" {
    auth_basic = "hello:auth",
    echo = "hello, world!\n",
}
