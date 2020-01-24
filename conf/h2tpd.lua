
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
Listen "443" {
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
			lua = require "conf/content",
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
				function()
					h2d.sleep(3)
					return (require "conf/content")()
				end
			},
		},
	},
	Host "www.newsmth.net" {
		Path "/" {
			proxy = { "120.92.34.37:80", "120.92.102.53:80"; -- www.newsmth.net
				upstream = { recv_buffer_size = 1024*16 },
			},
		},
	},
	Host "tmpnet" {
		acl = {
			"!1.2.3.4/24",
		},
		static = "src/",
		--static = { "src" } ,
		Path "/libloop2/" {
			acl = {
				"!5.5.5.5/24",
				"!5.5.5.5/24",
			},
		},
		Path "/libloop/" {
			--[[
			upstream = {
				read_timeout = 10,
				load_balance = "roundrobin",
				load_balance = {
					"hash",
					size = 10
				},
			},
			proxy = {
				"1.2.3.4",
				"2.3.4.4",
				headers = {},
			},
			proxy = {
				"1.2.3.4",
				"2.3.4.4",
				headers = {},
				upstream = {
					read_timeout = 10,
					load_balance = "hash",
				},
			},
			proxy = { { "1.2.3.4", "2.3.4.4",
					read_timeout = 10,
					load_balance = "hash",
				},
				headers = {},
			},
			--]]
		},
		Path "/" {
			acl = {
				H2D_ARRAY_APPEND,
				"!5.5.5.5/24",
				"!5.5.5.5/24",
				"!5.5.5.5/24",
				"!5.5.5.5/24",
			},
			static = "src/libwuya",
		},
	},
	Host "*" {
		Path "/subreq" {
			lua = require "conf/content",
		},
		Path "/test_subreq" {
			test_subreq = true,
			static = "src/",
		},
		Path "/stats" {
			stats = true,
		},
	},
}
