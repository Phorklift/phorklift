-- Listen on mulitple addresses
--
-- REQUEST: curl http://127.0.0.1:8080/hi
-- EXPECT: hello, world!
--
-- REQUEST: curl http://127.0.0.1:8081/hi
-- EXPECT: hello, world!
--
-- REQUEST: curl http://127.0.0.2:8081/hi
-- EXPECT: Connection refused

Listen "8080" "127.0.0.1:8081" {
    echo = "hello, world!\n",
}
