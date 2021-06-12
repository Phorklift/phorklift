--ERROR: pathname must start with
Listen "8080" {
    Host "" {
        Path "+/asdf" {
            echo = "hello"
        }
    }
}
