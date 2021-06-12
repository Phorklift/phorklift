-- HTTPS service
--
-- REQUEST: curl -k https://127.0.0.1:1443/hi
-- EXPECT: hello, HTTPS world!

Listen "1443" {
    ssl = {
        certificate = "../misc/unsafe-test-only.crt",
        private_key = "../misc/unsafe-test-only.key",
    },
    echo = "hello, HTTPS world!\n",
}
