--ERROR: Path() is allowed in Host() scope only, but not in Listen() scope
Listen "18080" {
	Path "/" {
		echo = "hello"
	}
}
