local _M = {
	Null = {}, -- Null Bulk String, for non-existence value
}

local mt = { __index = _M }

function _M.connect(server)
	local c = h2d.ups.getc(server)
	if not c then
		return nil
	end

	return setmetatable({c = c}, mt)
end

local function parse_line(resp)
	local tail = string.find(resp, "\r\n", 2, true)
	if not tail then
		return nil, "not complete line"
	end

	local next_line = tail + 2
	tail = tail - 1

	local first = string.sub(resp, 1, 1)
	if first == '+' then -- Simple Strings
		return string.sub(resp, 2, tail), next_line
	end
	if first == '-' then -- Errors
		return nil, string.sub(resp, 2, tail)
	end
	if first == ':' then -- Integers
		return tonumber(string.sub(resp, 2, tail)), next_line
	end
	if first == '$' then -- Bulk Strings
		local len = tonumber(string.sub(resp, 2, tail))
		if len == -1 then
			return _M.Null, next_line
		end

		local ret = string.sub(resp, next_line, next_line + len - 1)
		if string.len(ret) < len then
			return nil, "TODO: not complete bulk string"
		end
		return ret, next_line + len + 2
	end
	if first == '*' then -- Arrays
		local total = next_line
		local array = {}
		resp = string.sub(resp, next_line)
		for i = 1, tonumber(string.sub(resp, 2, tail)) do
			local v, next_line = parse_line(resp)
			if not v then
				return nil, next_line
			end
			table.insert(array, v)
			total = total + next_line
			resp = string.sub(resp, next_line)
		end
		return array, total
	end

	return nil, "invalid type: " .. first
end

function _M.query(self, line)
	local ok = self.c:send(line .. '\r\n')
	if not ok then
		return nil, "send fail"
	end

	local resp = self.c:recv_size(1024)
	if not resp then
		return nil, "recv fail"
	end

	return parse_line(resp)
end

function _M.query_once(server, line)
	local c = h2d.ups.getc(server)
	if not c then
		return nil, "connect fail"
	end

	local ok = c:send(line .. '\r\n')
	if not ok then
		return nil, "send fail"
	end

	local resp = c:recv_size(1024)
	if not resp then
		return nil, "recv fail"
	end

	local ret, err = parse_line(resp)
	if ret then
		c:keepalive()
	else
		c:close()
	end

	return ret, err
end

return _M
