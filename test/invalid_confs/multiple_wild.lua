-- ERROR: at most 1 wildcast in hostname
Listen "8080" {
    Host "*.exampl.*" {
        echo = "hello",
    },
}
