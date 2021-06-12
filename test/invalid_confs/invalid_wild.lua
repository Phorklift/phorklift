-- ERROR: leading wildcast
Listen "8080" {
    Host "*h.exampl.com" {
        echo = "hello",
    },
}
