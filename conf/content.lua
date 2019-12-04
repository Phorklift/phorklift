local content = function()
	local out = {}
	table.insert(out, 'URL: ' .. h2d.url())
	for k,v in pairs(h2d.headers()) do
		table.insert(out, k .. ': ' .. v)
	end
	return table.concat(out, '\n')
end

return content
