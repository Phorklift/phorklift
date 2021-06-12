--ERROR: invalid empty host name
Listen "8080" {
    Host "" {
        echo = "hello"
    }
}
