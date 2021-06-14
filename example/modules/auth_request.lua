-- Authentication by a subrequest.
--
--
-- REQUEST: curl 127.0.0.1:8080/ -H'Token: twgdh'
-- EXPECT: hello, world!
--
-- REQUEST: curl -v 127.0.0.1:8080/ -H'Token: invalid'
-- EXPECT: 401 Unauthorized

Listen "8080" {
    Path "/auth" {
        lua = function()
            local token = h2d.req.get_header("Token")
            if token == "twgdh" then
                return "yes"
            else
                return h2d.HTTP_401, "no"
            end
        end,
    },
    Path "/" {
        auth_request = "/auth",
        echo = "hello, world!\n",
    }
}
