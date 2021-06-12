-- Share instance by inheriting or referring variable.
--
-- REQUEST: curl http://127.0.0.1:8080/hello -H'Host: test1.com'
-- EXPECT: hello
--
-- REQUEST: curl http://127.0.0.1:8080/world -H'Host: test1.com'
-- EXPECT: world
--
--
-- REQUEST: curl http://127.0.0.1:8080/hello -H'Host: test2.com'
-- EXPECT: hello
--
-- REQUEST: curl -v http://127.0.0.1:8080/world -H'Host: test2.com'
-- EXPECT: 503 Service Unavailable
--
--
-- REQUEST: curl http://127.0.0.1:8080/hello -H'Host: test3.com'
-- EXPECT: hello
--
-- REQUEST: curl -v http://127.0.0.1:8080/world -H'Host: test3.com'
-- EXPECT: 503 Service Unavailable

local mymeter = { 1 }

Listen "8080" {

    Host "test1.com" {
        -- The following 2 Paths have independent limit meter.
        -- In other words, a client-IP can request "/hello" 1 times
        -- and "/world" 1 times both in one second.
        Path "/hello" {
            limit_req = 1, -- 1 req/sec, identified by client-IP as default
            echo = "hello\n",
        },

        Path "/world" {
            limit_req = 1,
            echo = "world\n",
        },
    },

    Host "test2.com" {
        -- The following 2 Paths share this limit_req meter.
        -- In other words, a client-IP can request "/hello" and "/world"
        -- 1 times total in one second.
        limit_req = 1,

        Path "/hello" {
            echo = "hello\n",
        },
        Path "/world" {
            echo = "world\n",
        },
    },

    Host "test3.com" {
        -- This is same with "test2.com".
        Path "/hello" {
            limit_req = mymeter,
            echo = "hello\n",
        },
        Path "/world" {
            limit_req = mymeter,
            echo = "world\n",
        },
    },
}


-- Here is another example of sharing upstream
local origin_upstream = {
    "127.0.0.1:11180",
    "127.0.0.1:11181",
}
Listen "8081" {
    Host "*" {
        Path "=/stats" {
            stats = true,
        },
        Path "=/ping" {
            echo = "pong\n",
        },

        -- The following Paths share the upstream, so the share
        -- the healthcheck, connection pool, statistics, etc.
        Path "/img" {
            proxy = { origin_upstream,
                x_forwarded_for = false,
            },
        },
        Path "/" {
            proxy = { origin_upstream },
        },
    }
}
