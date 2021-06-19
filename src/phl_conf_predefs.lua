-- Runtime
phl_conf_runtime = {}
function Runtime(opts)
	if next(phl_conf_runtime) then
		error('duplicate Runtime')
	end
	phl_conf_runtime = opts
end

-- Listen, Host, and Path
phl_conf_listens = {}

-- accept one or more string arguments and a final table argument
local function make_accept_args(name, opt)
	local str_args = {}
	local function accept_args(arg)
		local t = type(arg)
		if t == 'string' then
			table.insert(str_args, arg)
			return accept_args
		elseif t == 'table' then
			if not next(str_args) then
				error('at least 1 string argument is need for '..name)
			end
			arg[opt] = str_args
			str_args = {}
			if name == 'Listen' then
				table.insert(phl_conf_listens, arg)
			else
				return arg
			end
		else
			error('invalid argument type for '..name)
		end
	end
	return accept_args
end

Listen = make_accept_args('Listen', '_addresses')
Host = make_accept_args('Host', '_hostnames')
Path = make_accept_args('Path', '_pathnames')
