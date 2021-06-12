-- ERROR: duplicate hostname
Listen "8080" {
    Host "www.example.com" {
        echo = "hello",
    },
    Host "www.example.com" {
        echo = "hello",
    },
}
