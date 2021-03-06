--[[ Load h2tpd configuration file.

Author: Wu Bingzheng
  Date: 2019-09-20

Runtime() and Listen() are accepted at top level.
Runtime() is simple.
Configuration rules for Listen():

+ Array members and key-value options are allowed;

+ There are 3 levels which are created by Listen(), Host() and Path();

+ Options defined in lower level can be set in higher level as default value.
  E.g. `ssl` is defined in level Host, while it can be set in level Listen,
  and used as default value of all Hosts under this Listen;

+ Options set in lower level override the default value set in higher level;

+ Array members set in lower level will clear the members set in higher
  level first.


Input arguments: Listen table, configuration file name
Return: Listen array, Runtime

--]]


-- constants
H2D_ARRAY_APPEND = {}
KiB = 1024
MiB = 1024*1024
GiB = 1024*1024*1024
Minute = 60
Hour = 3600
Day = 86400

-- input arguments
local h2d_listen_default, h2d_conf_file = ...

-- prepare the defaults
local h2d_host_default = h2d_listen_default[1]
local h2d_path_default = h2d_host_default[1]

h2d_listen_default._default_next = h2d_host_default
h2d_host_default._default_next = h2d_path_default
h2d_listen_default[1] = nil
h2d_host_default[1] = nil

-- build metatable
local function h2d_build_metatable(t)
	for k,v in pairs(t) do
		if type(v) == "table" and k ~= '__index' then
			h2d_build_metatable(v)
		end
	end
	t.__index = t
end

h2d_build_metatable(h2d_listen_default)

local function h2d_level_base(base, key, new)
	-- normal case
	if base[key] ~= nil then
		return base
	end

	-- lower level key-value option
	local value = new[key]
	while base[key] == nil do
		base = base._default_next
		new = new._default_next
		if not base then
			return nil -- the key does not exist
		end
	end

	new[key] = value -- set at lower level
	return base
end

local function h2d_iter_key(key, prefix)
	if type(key) == "number" then
		return false
	end
	if type(key) ~= "string" then
		error(prefix .. ": invalid key type: " .. key)
	end
	if string.sub(key, 1, 1) ~= "_" then
		return true
	end
	if key == "_default_next" or key == "_hostnames" or key == "_pathnames" or key == "_addresses" then
		return false
	end
	error(prefix .. ": internal option is not allowed: " .. key)
end

local function h2d_set_metatable(new, base, prefix)
	-- array members, handle H2D_ARRAY_APPEND
	if new[1] == H2D_ARRAY_APPEND then
		table.remove(new, 1)
		for i = 1,#base do
			table.insert(new, 1, base[i])
		end
	end

	-- key-value options, call h2d_set_metatable() recursively
	for k,v in pairs(new) do
		if h2d_iter_key(k, prefix) then

			-- target:=base, if this option is at this level; or
			-- target:=base._default_next, if the option is at lower level; or
			-- target:=nil, if the key does not exist in base.
			local target = h2d_level_base(base, k, new)
			if target and type(target[k]) == "table" then
				-- grammar suger
				if type(v) ~= "table" then
					new[k] = { v }
					v = new[k]
					h2d_level_base(base, k, new)
				end

				h2d_set_metatable(v, target[k], prefix..'>'..k)
			end
		end
	end

	setmetatable(new, base)
end

local h2d_conf_listens = {}

local function h2d_check_names(names, expect, prefix)
	if not names then
		error(prefix .. ": invalid level: only " .. expect .. " is allowed here")
	end
	if #names == 0 then
		error(prefix .. ": expect names")
	end
	for _,n in ipairs(names) do
		if type(n) ~= "string" then
			error(prefix .. ": names must be string but get " .. type(n))
		end
	end
end

function Listen(...)
	local addresses = {select(1, ...)}

	h2d_check_names(addresses, nil, "Listen()")

	local listen_prefix = string.format("Listen(%s)", addresses[1])

	return function(listen)
		listen._addresses = addresses

		listen._default_next = {} -- default host
		listen._default_next._default_next = {} -- default path

		h2d_set_metatable(listen, h2d_listen_default, listen_prefix)

		h2d_build_metatable(listen._default_next)
		setmetatable(listen._default_next, h2d_host_default)
		setmetatable(listen._default_next._default_next, h2d_path_default)

		for i,host in ipairs(listen) do
			h2d_check_names(host._hostnames, "Host()", listen_prefix)

			host._default_next = {} -- default path

			local host_prefix = listen_prefix .. string.format(">Host(%s)", host._hostnames[1])
			h2d_set_metatable(host, listen._default_next, host_prefix)

			h2d_build_metatable(host._default_next)
			setmetatable(host._default_next, listen._default_next._default_next)

			for j,path in ipairs(host) do
				h2d_check_names(path._pathnames, "Path()", host_prefix)

				local path_prefix = host_prefix .. string.format(">Path(%s)", path._pathnames[1])
				h2d_set_metatable(path, host._default_next, path_prefix)
			end
		end

		table.insert(h2d_conf_listens, listen)
	end
end

function Host(...)
	local names = {select(1, ...)}
	return function(opts)
		opts._hostnames = names
		return opts
	end
end
function Path(...)
	local names = {select(1, ...)}
	return function(opts)
		opts._pathnames = names
		return opts
	end
end


-- Runtime
local h2d_conf_runtime = {}
function Runtime(t)
	if next(h2d_conf_runtime) then
		error("duplicate Runtime")
	end
	h2d_conf_runtime = t
end


dofile(h2d_conf_file)
if #h2d_conf_listens == 0 then
	error("at least 1 Listen() is need")
end

-- clear globals
Listen = nil
Host = nil
Path = nil

-- debug
local function dump_table(t, indent)
	local instr = string.rep("    ", indent)
	if t._hostnames then
		print(instr .. "HOST: " .. table.concat(t._hostnames))
		--dump_table(opts, indent + 1)
		--return
	elseif t._pathnames then
		print(instr .. "PATH: " .. table.concat(t._pathnames))
		--dump_table(opts, indent + 1)
		--return
	end

	for k,v in pairs(t) do
		if k ~= '__index' then
		if type(v) == "table" then
			print(instr .. k .. " =")
			dump_table(v, indent + 1)
		else
			print(instr .. k .. " = " .. tostring(v))
		end
		end
	end
end
local function dumpall()
	for k,v in ipairs(h2d_conf_listens) do
		print ("== listen: ", k)
		dump_table(v, 1)
	end
end
--dumpall()

return h2d_conf_listens, h2d_conf_runtime
