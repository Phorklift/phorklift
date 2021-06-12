-- Forward Proxy.

local forward_proxy_dynamic = {
    get_name = function() return h2d.req.host end,
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
    ssl_enable = true,
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
