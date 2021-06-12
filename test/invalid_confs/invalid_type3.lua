--ERROR: wrong type of status_code
Listen "8080" {
	echo = { "hello",
		status_code = "404",
	}
}
