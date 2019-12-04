Path () {
	acl = {
		--[[
		--examples:
		"1.2.3.0/24",  -- allow
		"!5.6.7.0/24", -- "!" means deny
		-- default policy is the reverse of last one
		--]]
		_array_type = "string",
		log = {
			file = "", -- empty means logging to error.log
			level = "info",
		},
	},
}
