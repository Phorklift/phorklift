
Listen ("22345") {
	ssl = {
		certificate = "conf/cert.pem",
		private_key = "conf/key.pem",
	},
	Host ("www.baidu.com") {
		Path ("/1") {
			static = { "src/libwuya/" },
		}
	},
	Host ("www.taobal.com") {
		ssl = {
			--certificate = "taobao",
		},
		Path ("/2") {
			static = { "src/libwuya/" },
		}
	},
	network = {
		keepalive_timeout = 13,
	},
}
Listen ("443") {
	network = {
		keepalive_timeout = 1,
	},
	http2 = {
		keepalive_timeout = 2,
	},
	ssl = {
		certificate = "conf/cert.pem",
		private_key = "conf/key.pem",
	},
	Host("www.baidu.com", "baidu.com") {
		Path ("/3") {
			acl = {
				--"!1.2.3.4/24",
			},
			lua = {
				content = require "conf/content",
			},
		},
		Path ("/") {
			--static = { "libhttp2/examples/" },
			--proxy = { "127.0.0.1:2346" },
			--proxy = { "120.92.102.53:80" }, -- www.newsmth.net
			--proxy = { "95.211.80.227:80" }, -- nginx.org
			--proxy = {
				--upstream = { "180.101.49.12:443", ssl_enable=true, }
			--}, -- www.baidu.com
			lua = {
				--content = require "conf/content",
				content = function()
					h2d.sleep(3)
					return (require "conf/content")()
				end
			},
		},
	},
	Host("www.newsmth.net") {
		Path ("/") {
			proxy = { upstream = { "120.92.102.53:80" , recv_buffer_size = 1024*16 } }, -- www.newsmth.net
		},
	},
	Host("*") {
		Path ("/subreq") {
			test_subreq = { true },
			static = { "src/" },
		},
		Path ("/") {
			static = { "src/libhttp2/examples/" },
		},
	},
}
