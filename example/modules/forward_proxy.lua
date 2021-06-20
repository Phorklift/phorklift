-- Forward Proxy.
--
--
-- REQUEST: curl -v http://127.0.0.1:8080/ -H'Host: www.baidu.com'
-- EXPECT: 200 OK
--
-- REQUEST: curl -v http://127.0.0.1:8081/ -H'Host: www.baidu.com'
-- EXPECT: 200 OK
--
-- REQUEST: curl -vk https://127.0.0.1:1443/ -H'Host: www.baidu.com'
-- EXPECT: 200

local forward_proxy_dynamic = {
    get_name = function() return phl.req.host end,
    get_conf = function(host) return { host } end,
}

-- plain forward proxy
Listen "8080" {
    proxy = { { -- 1. define the upstream internal
        default_port = 80,
        dynamic = forward_proxy_dynamic,
    } },
}

-- 2. define the upstream here, and be referred later
local forward_proxy_ssl_backend = {
    ssl = {},
    default_port = 443,
    dynamic = forward_proxy_dynamic,
}

-- SSL forward proxy
Listen "1443" {
    ssl = {
        certificate = "../misc/unsafe-test-only.crt",
        private_key = "../misc/unsafe-test-only.key",
    },
    proxy = { forward_proxy_ssl_backend },
}

-- plain downstream and SSL upstream
Listen "8081" {
    proxy = { forward_proxy_ssl_backend },
}
