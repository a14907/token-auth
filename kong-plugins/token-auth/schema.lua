local typedefs = require "kong.db.schema.typedefs"


return {
    name = "auth-token",
    fields = {
        {
            -- this plugin will only be applied to Services or Routes
            consumer = typedefs.no_consumer
        },
        {
            -- this plugin will only be executed on the first Kong node
            -- if a request comes from a service mesh (when acting as
            -- a non-service mesh gateway, the nodes are always considered
            -- to be "first".
            run_on = typedefs.run_on_first
        },
        {
            -- this plugin will only run within Nginx HTTP module
            protocols = typedefs.protocols_http
        },
        {
            config = {
                type = "record",
                fields = {
                    -- Describe your plugin's configuration's schema here.
                    {
                        redis_ip = {
                            type = "string",
                            required = true,
                            default="192.168.2.148"
                        },
                    },
                    {
                        redis_port = {
                            type = "string",
                            required = true,
                            default="6379"
                        },
                    },
                    {
                        redis_db = {
                            type = "string",
                            required = true,
                            default="2"
                        },
                    },
                    {
                        redis_password = {
                            type = "string",
                            required = false,
                            default=nil
                        },
                    },
                    {
                        introspect_url = {
                            type = "string",
                            required = true,
                            default="http://openplatformauthcenter.service.consul:8006/connect/introspect"
                        },
                    },
                    {
                        gatewayapi_name = {
                            type = "string",
                            required = true,
                            default="gateway"
                        },
                    },
                    {
                        gatewayapi_secret = {
                            type = "string",
                            required = true,
                            default="123456"
                        },
                    },
                },
            },
        },
    }
}
