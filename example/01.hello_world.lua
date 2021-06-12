-- Response "hello, world!\n" to each request.
--
-- `echo` is one of content modules, which genenrate content.
--
-- REQUEST: curl http://127.0.0.1:8080/hi
-- EXPECT: hello, world!

Listen "8080" {
    echo = "hello, world!\n",
}
