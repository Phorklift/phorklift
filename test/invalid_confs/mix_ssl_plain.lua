-- ERROR: can not mix SSL and plain amount Host() under one Listen()
Listen "8080" {
    Host "ww1.example.com" {
        echo = "plain"
    },
    Host "www.example.com" {
        ssl = {
            certificate = "../misc/unsafe-test-only.crt",
            private_key = "../misc/unsafe-test-only.key",
        },
        echo = "ssl"
    },
}
