-- Inherit from upper scope
--
-- REQUEST: curl http://127.0.0.1:8080/mypath
-- EXPECT: hello, mypath!
--
-- REQUEST: curl -v http://127.0.0.1:8080/notfound
-- EXPECT: 404 Not Found
--
-- REQUEST: curl http://127.0.0.1:8080/default
-- EXPECT: hello, host!

Listen "8080" {
    Host "*" {
        -- `echo` is a Path-level command. It works as default
        -- value for all Paths if set in Host() scope.
        echo = "hello, host!\n",

        Path "/mypath" {
            -- overwrite the default value
            echo = "hello, mypath!\n",
        },
        Path "/notfound" {
            -- inherit the echo string, but overwrite the status code 200
            echo = { status_code = 404 },
        },
        Path "/" {
            -- inherit the echo string and status code
        },
    },
}
