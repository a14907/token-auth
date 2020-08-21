# token-auth
这是一个kong插件，用于验证accesstoken，遵循协议：RFC 7662


# 环境变量

```
-e "KONG_LUA_PACKAGE_PATH=/custom/?.lua;;" 

-e "KONG_PLUGINS=bundled,token-auth" 

-v "/code/001_lua/kong_plugins:/custom/kong/plugins"
```

# 插件配置项

```
"redis_ip": "192.168.1.100",

"redis_db": "0",

"redis_port": "6379",

"introspect_url": "http://192.168.1.100:5000/connect/introspect",

"redis_password": null,

"gatewayapi_name": "gateway",

"gatewayapi_secret": "123456"
```
by wude
