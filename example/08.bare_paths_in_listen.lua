-- Bare Path in Listen directly.
--
-- REQUEST: curl http://127.0.0.1:8080/img/
-- EXPECT: hello, img!
--
-- REQUEST: curl http://127.0.0.1:8080/waka
-- EXPECT: hello, all!

Listen "8080" {
    Path "/img/" {
        echo = "hello, img!\n",
    },
    Path "/" {
        echo = "hello, all!\n",
    },
}
