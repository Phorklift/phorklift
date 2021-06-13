-- Basic access authentication.
--
--
-- REQUEST: curl 127.0.0.1:8080/
-- EXPECT: hello, world!

Listen "8080" {
    Host "*" {
        Path "/auth" {
            echo = "TODO"
            --[[
            lua = function()
                local token = h2d.req.get_header("Token")
                if token == "twgdh" then
                    return
                else
                    return s
                end
            end,
            --]]
        },
        Path "/" {
            auth_request = "/auth",
            echo = "hello, world!\n",
        }
    }
}
