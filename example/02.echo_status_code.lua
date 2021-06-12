-- Response 404
--
-- In fact `echo` accepts Lua-table type value. Like in this example,
-- there are an array member "I'm sorry!\n" to indicate the response
-- body, and a key-value map member `status_code` to indicate the
-- status code.
--
-- In [last example](01.hello_world.lua), `echo` was set to a string value.
-- This is a h2tpd configuration's grammar sugur, which is
-- you can omit the table constructor and set a member directly, if
--
--   * the value table accepts array members (either single or multiple),
--   * the type of array member is NOT table again,
--   * you want to set only one array member,
--   * you do not want to set any key-value entry.
--
-- This feature is very ofter used in the following examples.
--
-- REQUEST: curl -v http://127.0.0.1:8080/hi
-- EXPECT: 404 Not Found

Listen "8080" {
    echo = { "I'm sorry!\n",
        status_code = 404,
    }
}
