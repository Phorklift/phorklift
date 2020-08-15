-- this could be used by other modules
general = {
	upstream = {
		_array_type = "string",
		load_balance = "rr",
		read_timeout = 10,
		write_timeout = 10,
		idle_timeout = 10,
		idle_max = 10,
		fails = 1,
		default_port = 80,
		resolve_interval = 10*60,
		send_buffer_size = 1024*16,
		recv_buffer_size = 1024*16,
		ssl_enable = false,

		hash = H2D_ZERO_FUNC,
	},
	mask = {
		_array_type = "number",
	},
	rewrite = {
		_array_type = "string",
		log = "",
	},
	headers = {
		_arbitrary_key = true,
	},
}

-- Listen() context
Listen () {

	_array_type = "table", -- Hosts

	network = {
		connections = 10000,
		send_timeout = 10,
		recv_timeout = 10,
		send_buffer_size = 16 * 1024,
	},

	http1 = {
		keepalive_timeout = 60,
	},
	http2 = {
		ping_interval = 45, -- not implement
		idle_timeout = 3*60,
	},

	--[[
	ssl_mask = {},

	proxy_protocol = {
		trust_from = {},
		mask = {},
	},
	--]]

	-- Host() context
	Host () {
		_array_type = "table", -- Paths

		ssl = {
			certificate = "",
			private_key = "",
			certificate2 = "",
			private_key2 = "",
			ticket_secret = "",
			ticket_timeout = 7 * 86400;
		},

		--[[
		rewrite = {
			"/(.*).hpp", "/%1.h";
			"/(.*)", "/mobile/%1";
		},
		rewrite = general.rewrite,
		--]]
	
		-- Path() context
		Path () {
		--[[
			headers = general.headers,

			error_page = { _arbitrary_key = true },

			body_filter = function () end, 

			jump_host = "",

			access_log = {
				dir = "logs/",
				file = "access.log",
				format = "",
				filter = function () end,
			},
			error_log = {
				dir = "logs/",
				file = "error.log",
				level = "error",
			},
		--]]
		},
	},
}
