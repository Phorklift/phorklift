--ERROR: duplicate Runtime
Runtime {
	worker = 1
}
Runtime {
	error_log = "error.log"
}

Listen "8080" {
	echo = "hello world"
}
