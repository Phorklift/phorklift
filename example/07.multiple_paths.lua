-- Multiple Paths in Host
--
-- A pathname must starts with `/`, `=` or `~`, indicate prefix,
-- exactly, and Lua regex matching respectively.
--
-- For each requests, Phorklift locates Path by comparing the pathnames
-- one by one in the order that Path appears in Host.
-- This is different to locate Host in Listen.
--
-- Some pathname that obviously can not be matched is not allowed.
-- For example, "/img/big/" is not allowed to appear behind "/img/".
--
--
-- REQUEST: curl http://127.0.0.1:8080/img/
-- EXPECT: hello, exact match!
--
-- REQUEST: curl http://127.0.0.1:8080/img/abc/a.jpg
-- EXPECT: hello, prefix match!
--
-- REQUEST: curl http://127.0.0.1:8080/img/123/a.jpg
-- EXPECT: hello, regex match!
--
-- REQUEST: curl http://127.0.0.1:8080/waka
-- EXPECT: hello, all!

Listen "8080" {
    Host "*" { -- The Host level can be omitted
        Path "=/img/" {
            echo = "hello, exact match!\n",
        },
        Path "~/img/%d+/" {
            echo = "hello, regex match!\n",
        },
        Path "/img/" {
            echo = "hello, prefix match!\n",
        },
        Path "/" { -- accept all
            echo = "hello, all!\n",
        },
    },
}
