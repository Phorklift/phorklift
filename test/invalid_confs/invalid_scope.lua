--ERROR: invalid command
Listen "8080" {
	Host "*" {
		Path "/" {
			network = { -- this should in Listen scope
				connections = 1
			},

			echo = "hello",
		}
	}
}
