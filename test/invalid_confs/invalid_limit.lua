--ERROR: status_code out of range
Listen "8080" {
	echo = { "hello",
		status_code = 1,
	}
}
