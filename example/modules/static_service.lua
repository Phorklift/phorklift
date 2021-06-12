-- Static file service.
--
-- REQUEST: curl http://127.0.0.1:8080/01.hello_world.lua
-- EXPECT: hello, world!
--

Listen "8080" {
    static = "good_confs/"
}
