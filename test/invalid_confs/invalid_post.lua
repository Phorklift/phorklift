--ERROR: post handler fails
Listen "8080" {
	static = "notexist_path/",
}
