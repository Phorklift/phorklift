--ERROR: post handler fails
Listen "8080" {
	error_log = { level = "good" },
	static = "./",
}
