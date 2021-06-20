Phorklift is an HTTP server and proxy daemon, with clear, powerful and dynamic configuration.


# Common Features

- High performance and low memory usage.

- Modular mechanism, similar to [Nginx](https://nginx.org).

- HTTP/1.x and HTTP/2 (except server-push)

- Reload configuration.

- Static file service, proxy, ACL, gzip, etc.

In short, Phorklift targets production-level.


# Key Features

## Feature: Configuration in Lua.

It's a very natural choice when [Lua](https://lua.org) is embed.

Lua is simple and powerful. Correspondingly, Phorklift's configuration is
always short and clear for most cases, while it can also provide powerful
description capabilities for some specific cases.

In order to highlight Phorklift configuration's feature, the examples in the
following sections mainly show the usage of Lua's function and look a bit
complex. However usually you may not need that, and then Lua behaves like
other configurations.
Here is a simple example:

  ```lua
  Listen "443" {
      ssl = {
          certificate = "certs/cert.pem",
          private_key = "certs/priv.pem",
      },
      network = {
          send_timeout = 10,
      },
      static = "html/",  -- provide static file service
  }
  ```

Here are a [tutorial](doc/3.conf_tutorial.md) and more [examples](example/).


## Feature: Lua Embed.

This is inspired by the [Lua-nginx module](https://github.com/openresty/lua-nginx-module)
from OpenResty, but we are more comprehensive. Lua is no longer just a module.

Here is a configuration example to log requests only status-code >= 400
or reacting slower than 1 second:

  ```lua
  access_log = {
      filter = function()
          return phl.resp.status_code >= 400 or phl.resp.react_ms > 1000
      end,
  }
  ```

where `phl` is a [built-in Lua package](doc/5.lua_api.md).

Another example on the request rate limit key. If the request is from a
login user then use the user-id as a key, or use the client IP.

  ```lua
  limit_req = {
      key = function()
          local user_id = phl.req.get_cookie("id")
          return user_id and user_id or phl.conn.client_ip
      end
  }
  ```

Going further, different weight can be set for each request:

  ```lua
  limit_req = {
      weight = function()
          local weight = 1 -- default value

          -- bigger `limit` argument means bigger weight
          local limit = phl.req.get_uri_query("limit")
          if limit then
              limit = tonumber(limit)
              weight = (limit > 100) and limit/100 or 1
          end

          -- higher VIP level has higher limit
          local user_id = phl.req.get_cookie("id")
          local vip = get_vip_level(user_id)
          if vip then
              weight = weight / vip
          end

          return weight
      end,
  }
  ```

Thanks to Lua's light-weight coroutine, the script can be written like
blocking mode. Let's see the `get_vip_level()` in last example:

  ```lua
  local function get_vip_level(user_id)
      local r = phl.subrequest("@get_user_info", {args={user_id=user_id}})
      if r.status_code ~= 200 then
          return nil
      end

      local info = cjson.decode(r.body)
      return tonumber(info.vip_level)
  end
  ```

`phl.subrequest()` creates a Phorklift sub-request, and returns after it
finishes. But Phorklift switches to process other events during this time.
So the script looks like blocking but the underlying is asynchronous.

If you are used to Lua-nginx module, you will feel familiar.

These are all very simple examples. However it is easy to write complex
applications.


## Feature: Dynamic Configration.

Dynamic configuration enables some components to be created/updated/deleted
during running.

This is Phorklift's killer!

By now, built-in Upstream and Path support dynamic configuration.
You can make any components in you module to support dynamic easily if necessary.

Let's take the forward proxy as example which uses upstream.
Usually one upstream defines a group of static hostname or IP addresses,
so it's suitable for _reverse_ proxy:

  ```lua
  local upstream_origin = {
      "origin1.example.com",
      "origin2.example.com",
  }
  ```

However for _forward_ proxy, the addresses are not static but decided by the
request's Host header. You can not write the addresses into configuration
file, but can only know them on receiving requests. So here is the dynamic:

  ```lua
  local upstream_hello_dynamic = {
      dynamic = {
          get_name = function() return phl.req.host end,
          get_conf = function(name) return { name } end,
      }
  }
  ```

There is no static addresses in this upstream, but a `dynamic` member which
contains 2 functions: `get_name()` returns a string as the name of sub-upstream
for this request; and `get_conf()` returns the configuration of the sub-upstream
according to the name.

For example, for a request with header "Host: xxx.example.com", `get_name()`
returns "xxx.example.com", and `get_conf()` returns `{"xxx.example.com"}`
which is a valid upstream configuration. Then Phorklift creates a new sub-upstream
with this configuration to serve this request, and also cache it for later use.
The following requests with same Host will hit the cache and need not to call
`get_conf()` again.

Forward proxy is realized! This seems nothing special, but more powerful
functions can be achieved through more complex `get_name()` and `get_conf()`.

Here is another example of dynamic upstream for service discovery:

  ```lua
  local upstream_service_discovery = {
      dynamic = {
          idle_timeout = 3600,
          check_interval = 60,

          get_name = function()
              return string.match(phl.req.uri_path, '/(%w+)/')
          end,

          get_conf = function(name)
              local redis = require "luapkgs/phl_redis"
              local conf = redis.query_once("127.0.0.1:6379", "get "..name)
              if not conf then  -- query failure
                  return phl.HTTP_500
              end

              if conf == redis.Null then  -- miss or deleted
                  return phl.HTTP_404
              end

              return phl.HTTP_200, conf
          end,
      }
  }
  ```

For example, for a request with URL "/img/big/123.jpg", `get_name()` returns
"img"; and `get_conf()` queries the upstream's configuration for "img" from
Redis, where should be an entry with key="img" and value is arbitrary valid
upstream configuration string.
The following requests with "/img/" prefix will use this sub-upstream
directly in 60 seconds (defined by `check_interval=60` above). After
60 seconds, Phorklift will query Redis again to check whether the configuration
is deleted or modified.
Then the administrator only need to create, delete and modify the
name-configuration entries in Redis to realize the service discovery.

Compared to last forward proxy example, `get_conf()` return one more value,
the status code, to indicate status. Besides, the returned `conf` is string
but not Lua table, and Phorklift will load the string into Lua table.

Here the Redis is just an example. You can query the configuration from
local file, another HTTP server, etc.

Dynamic Upstream handles upstream configuration only, while dynamic Path 
handles path configuration which includes most of Phorklift's commands, such as
the `limit_req` in the above example. It's much more powerful.


## Feature: Clean Code.

Probably all programers will think their codes are clean.
But I really try my best to keep Phorklift's code clean.

In addition, Phorklift is written from the ground-up so there is no "legacy code" by now.

Here is a [unfair comparison with Nignx](doc/topics/unfair_code_comparison_with_nginx.md).
You will find that it's much easier to develop with Phorklift than nginx.


## Feature: Detailed Statistics.

It meets most of the monitoring needs. No need to analyze logs anymore.

See `stats` command in [reference](doc/4.conf_reference.md) for more detail. [TODO]


# Disadvantages

- Lack of security and stability verification.

- Fewer functions and modules.

- Linux only.

All because of being young. Hope these problems will disappear as we grow.


# Licence

GPLv2.


# Status

Phorklift is still under development and not stable yet.

The main functions and frames have been realized. At least the functions
and configuration mentioned in this document have been realized.

I publish it now (June 2021) mainly to collect opinions and suggestions.
If you are interested, please try it and feedback. Thanks!


# Next Reading

[More ducuments](doc/).
