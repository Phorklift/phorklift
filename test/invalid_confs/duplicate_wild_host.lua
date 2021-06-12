-- ERROR: duplicate wildcard host
Listen "8080" {
    Host "*" {
        echo = "hello",
    },
    Host "*" {
        echo = "world",
    }
}
