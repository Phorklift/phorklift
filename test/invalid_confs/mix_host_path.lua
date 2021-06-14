--ERROR: can not mix Host and Path
Listen "8080" {
    Host "*" {
        echo = "host"
    },
	Path "/" {
		echo = "path"
	},
}
