--ERROR: Host command can not in bare Path
Listen "8080" {
	Path "/" {
        ssl = {
            certificate = "../misc/unsafe-test-only.crt",
            private_key = "../misc/unsafe-test-only.key",
        },
		echo = "hello, world!\n"
	}
}
