Path () {
	proxy = {
		_array_type = "string",
		upstream = general.upstream,
		x_forwarded_for = true,
		max_retries = 3,
		retry_status_codes = { _array_type="number", 500, 501, 502, 503, 504},
	},
}
