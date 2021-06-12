-- Multiple Listens
--
-- REQUEST: curl http://127.0.0.1:8080/hi
-- EXPECT: hello, world!
--
-- REQUEST: curl -k https://127.0.0.1:1443/hi
-- EXPECT: hello, HTTPS world!

Listen "8080" {
    echo = "hello, world!\n",
}

Listen "1443" {
    ssl = {
        certificate = "../misc/unsafe-test-only.crt",
        private_key = "../misc/unsafe-test-only.key",
    },
    echo = "hello, HTTPS world!\n",
}
