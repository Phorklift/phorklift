-- Load h2tpd configuration file.
--
-- Author: Wu Bingzheng
--   Date: 2019-09-20
--
--
-- Configuration rules:
--
-- + Array members and key-value options are allowed;
--
-- + There are 3 levels which are created by Listen(), Host() and Path();
--
-- + Options defined in lower level can be set in higher level as default value.
--   E.g. `ssl` is defined in level Host, while it can be set in level Listen,
--   and used as default value of all Hosts under this Listen;
--
-- + Options set in lower level override the default value set in higher level;
--
-- + Array members set in lower level will clear the members set in higher
--   level first.
--
--
-- Load steps:
--
-- 1. Load core configuration definitions from @h2d_conf_definitions_dir/core.lua
--
-- 2. Load modules' configuration definitions from @h2d_conf_definitions_dir/mod_*.lua
--
-- 3. Merge user-defined default values from @h2d_conf_defaults_file
--
-- 4. Read the configuration file from @h2d_conf_file
--
--
-- Return 2 values:
--   The Listen array, H2D_ZERO_FUNC


-- zero value of function
H2D_ZERO_FUNC = function() end

-- input arguments
local h2d_conf_definitions_dir, h2d_conf_defaults_file, h2d_conf_file = ...


-- 1. Load core configuration definitions

local h2d_listen_default
local h2d_host_default
local h2d_path_default

function Listen()
	return function(opts) h2d_listen_default = opts end
end
function Host()
	return function(opts) h2d_host_default = opts end
end
function Path()
	return function(opts) h2d_path_default = opts end
end
dofile(h2d_conf_definitions_dir .. "/core.lua")


-- 2. Load module configuration definitions

local h2d_current_module = nil
local function h2d_conf_add(base, new)
	for k,v in pairs(new) do
		if base[k] ~= nil then
			error(string.format("duplicate key:%s when build module: %s", k, h2d_current_module))
		end
		base[k] = v
	end
end

function Listen()
	return function(opts) h2d_conf_add(h2d_listen_default, opts) end
end
function Host()
	return function(opts) h2d_conf_add(h2d_host_default, opts) end
end
function Path()
	return function(opts) h2d_conf_add(h2d_path_default, opts) end
end

local p = io.popen('ls -1 ' .. h2d_conf_definitions_dir .. '/mod_*.lua')
for f in p:lines() do
	h2d_current_module = f
	dofile(f)
end
p:close()


-- 3. Merge user-defined default values

local function h2d_value_type(base, key, new, value, prefix)
	-- normal case
	if base[key] ~= nil then
		return base, type(base[key])
	end

	-- arbitrary key
	if base._arbitrary_key then
		return base, base._arbitrary_key
	end

	-- lower level key-value option
	while base[key] == nil do
		base = base._default_next
		new = new._default_next
		if not base then
			error(prefix .. ": invalid option key: " .. key)
		end
	end

	new[key] = value -- set at lower level

	return base, type(base[key])
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

local function h2d_conf_merge_default(base, new, prefix, checkonly)

	-- array members
	if new[1] ~= nil then
		local array_type = base._array_type
		if not array_type then
			error(prefix .. ": array member is not allowed")
		end

		if not checkonly then
			-- clear original array members in base first
			for i in ipairs(base) do
				base[i] = nil
			end

			-- set new members
			for i,v in ipairs(new) do
				if type(v) ~= array_type then
					error(prefix .. string.format(": mismatch array member type, get %s while expect %s", type(v), array_type))
				end
				base[i] = v
				new[i] = nil
			end
		end
	end

	-- key-value options
	for k,v in pairs(new) do
		if h2d_iter_key(k, prefix) then

			-- target:=base, if this option is at this level; or
			-- target:=base._default_next, if the option is at lower level.
			local target, vtype = h2d_value_type(base, k, new, v, prefix)

			if type(v) ~= vtype then
				if vtype == "table" and target[k]._array_type == type(v) then
					new[k] = { v } -- grammar suger
					v = new[k]
				else
					error(prefix .. string.format(": mismatch type of key %s, get %s while expect %s", k, type(v), vtype))
				end
			end

			if type(v) == "table" then
				h2d_conf_merge_default(target[k], v, prefix..'>'..k, checkonly)
			elseif not checkonly then
				target[k] = v
			end
		end
	end

	if checkonly then
		setmetatable(new, base)
	end
end

function Listen()
	return function(opts) h2d_conf_merge_default(h2d_listen_default, opts, "Listen*") end
end
function Host()
	return function(opts) h2d_conf_merge_default(h2d_host_default, opts, "Host*") end
end
function Path()
	return function(opts) h2d_conf_merge_default(h2d_path_default, opts, "Path*") end
end

dofile(h2d_conf_defaults_file)

-- build metatable
function h2d_build_metatable(t)
	for k,v in pairs(t) do
		if type(v) == "table" then
			h2d_build_metatable(v)
		end
	end
	t.__index = t
end

h2d_listen_default._default_next = h2d_host_default
h2d_host_default._default_next = h2d_path_default
h2d_build_metatable(h2d_listen_default)


-- 4. Read the configuration file

local h2d_conf_listens = {}

local function h2d_check_names(names, prefix)
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

	h2d_check_names(addresses, "Listen()")

	local listen_prefix = string.format("Listen(%s)", addresses[1])

	return function(listen)
		listen._addresses = addresses

		listen._default_next = {} -- default host
		listen._default_next._default_next = {} -- default path

		h2d_conf_merge_default(h2d_listen_default, listen, listen_prefix, true)

		h2d_build_metatable(listen._default_next)
		setmetatable(listen._default_next, h2d_host_default)
		setmetatable(listen._default_next._default_next, h2d_path_default)

		for i,host in ipairs(listen) do
			h2d_check_names(host._hostnames, listen_prefix)

			host._default_next = {} -- default path

			local host_prefix = listen_prefix .. string.format(">Host(%s)", host._hostnames[1])
			h2d_conf_merge_default(listen._default_next, host, host_prefix, true)

			h2d_build_metatable(host._default_next)
			setmetatable(host._default_next, listen._default_next._default_next)

			for j,path in ipairs(host) do
				h2d_check_names(path._pathnames, host_prefix)

				local path_prefix = host_prefix .. string.format(">Path(%s)", path._pathnames[1])
				h2d_conf_merge_default(host._default_next, path, path_prefix, true)
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

dofile(h2d_conf_file)


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

return h2d_conf_listens, H2D_ZERO_FUNC
