-- Lua script, for filters and content.
--
-- REQUEST: curl -v 127.0.0.1:8080/hi?name=hacker
-- EXPECT: 403 Forbidden
--
-- REQUEST: curl -v 127.0.0.1:8080/hi?name=h2tpd
-- EXPECT: hello, h2tpd
--
-- REQUEST: curl -v 127.0.0.1:8080/hi?name=h2tpd
-- EXPECT: X-tag: haha

Listen "8080" {
    error_log = {level = "debug" },
    script = {
        -- process headers filter
        request_headers = function()
            local name = h2d.req.get_uri_query("name")
            if name == 'hacker' then
                return h2d.HTTP_403
            end
        end,

        -- content
        function()
            return "hello, " .. h2d.req.get_uri_query("name")
        end,

        -- reponse headers filter
        response_headers = function()
            h2d.resp.add_header("X-tag", "haha")
        end,
    }
}
