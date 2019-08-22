local BasePlugin = require "kong.plugins.base_plugin"
local redis = require "resty.redis"
local cjson = require "cjson"
local http = require "resty.http"

local TokenAuthHandler = {}

TokenAuthHandler.VERSION = "1.0.0"
TokenAuthHandler.PRIORITY = 10

local function is_present(str)
    return str and str ~= "" and str ~= null
end

local function encodeBase64(source_str)
    local b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    local s64 = ""
    local str = source_str

    while #str > 0 do
        local bytes_num = 0
        local buf = 0

        for byte_cnt = 1, 3 do
            buf = (buf * 256)
            if #str > 0 then
                buf = buf + string.byte(str, 1, 1)
                str = string.sub(str, 2)
                bytes_num = bytes_num + 1
            end
        end

        for group_cnt = 1, (bytes_num + 1) do
            local b64char = math.fmod(math.floor(buf / 262144), 64) + 1
            s64 = s64 .. string.sub(b64chars, b64char, b64char)
            buf = buf * 64
        end

        for fill_cnt = 1, (3 - bytes_num) do
            s64 = s64 .. "="
        end
    end

    return s64
end

local function strsplit(input, delimiter)
    input = tostring(input)
    delimiter = tostring(delimiter)
    if (delimiter == "") then
        return false
    end
    local pos, arr = 0, {}
    for st, sp in function()
        return string.find(input, delimiter, pos, true)
    end do
        table.insert(arr, string.sub(input, pos, st - 1))
        pos = sp + 1
    end
    table.insert(arr, string.sub(input, pos))
    return arr
end

local function ToStringEx(value)
    if type(value) == "table" then
        return TableToStr(value)
    elseif type(value) == "string" then
        return "'" .. value .. "'"
    else
        return tostring(value)
    end
end

local function TableToStr(t)
    if t == nil then
        return ""
    end
    local retstr = "{"

    local i = 1
    for key, value in pairs(t) do
        local signal = ","
        if i == 1 then
            signal = ""
        end

        if key == i then
            retstr = retstr .. signal .. ToStringEx(value)
        else
            if type(key) == "number" or type(key) == "string" then
                retstr = retstr .. signal .. "[" .. ToStringEx(key) .. "]=" .. ToStringEx(value)
            else
                if type(key) == "userdata" then
                    retstr =
                        retstr .. signal .. "*s" .. TableToStr(getmetatable(key)) .. "*e" .. "=" .. ToStringEx(value)
                else
                    retstr = retstr .. signal .. key .. "=" .. ToStringEx(value)
                end
            end
        end

        i = i + 1
    end

    retstr = retstr .. "}"
    return retstr
end

local function rediskeepalive(red)
    local ok, err = red:set_keepalive(10000, 100)
    if not ok then
        kong.log.err("failed to set Redis keepalive: ", err)
        return nil, err
    end
end

function TokenAuthHandler:access(config)
    --创建redis
    kong.log.info("---begin create redis instance---")
    local red = redis:new()
    red:set_timeouts(1000, 1000, 1000)
    local ok, err = red:connect(config.redis_ip, config.redis_port)
    if not ok then
        kong.log.err("failed to connect to Redis: ", err)
        return kong.response.exit(401, "failed to connect to Redis  ")
    end

    local times, err = red:get_reused_times()
    if err then
        kong.log.err("failed to get connect reused times: ", err)
        return kong.response.exit(401, "failed to get connect reused times ")
    end
    if times == 0 then
        kong.log.info("---redis instance resuse time is " .. times .. "---")
        if is_present(config.redis_password) then
            local ok, err = red:auth(config.redis_password)
            if not ok then
                kong.log.err("failed to auth Redis: ", err)
                return kong.response.exit(401, "failed to auth Redis ")
            end
        end
        local ok, err = red:select(config.redis_db)
        if not ok then
            kong.log.err("failed to change Redis database: ", err)
            return kong.response.exit(401, "failed to change Redis database ")
        end
    end
    kong.log.info("---end create redis instance---")

    --获取请求头的token
    local rawHeader = kong.request.get_header("Authorization")
    if not rawHeader then
        rediskeepalive(red)
        return kong.response.exit(401, "must have Authorization header")
    end
    local splitHeader = strsplit(rawHeader, " ")
    if splitHeader[1] ~= "Bearer" then
        rediskeepalive(red)
        return kong.response.exit(401, "schema in Authorization header is not right")
    end
    if splitHeader[2] == nil or splitHeader[2] == "" then
        rediskeepalive(red)
        return kong.response.exit(401, "Authorization header is empty")
    end
    --判断缓存中是否有该token的验证结果
    local token = splitHeader[2]
    local cachekey = "accesstoken:" .. token
    local res, err = red:get(cachekey)
    local isCacheOk = false
    if res then
        if res == "valid" then
            isCacheOk = true
        else
            if res ~= ngx.null and res == "invalid" then
                rediskeepalive(red)
                return kong.response.exit(401, "token invalid ")
            end
        end
    end
    if not isCacheOk then
        -- 请求远程服务判断token的有效性
        kong.log.info("---begin get response from ids4---")
        local basicHeader = "Basic " .. encodeBase64(config.gatewayapi_name .. ":" .. config.gatewayapi_secret)
        local formBody = "token=" .. splitHeader[2]

        local httpc = http.new()
        local res, err =
            httpc:request_uri(
            config.introspect_url,
            {
                method = "POST",
                body = formBody,
                headers = {
                    ["Content-Type"] = "application/x-www-form-urlencoded",
                    ["Authorization"] = basicHeader
                }
                --   keepalive_timeout = 60,
                --   keepalive_pool = 10
            }
        )
        kong.log.info("---end get response from ids4---")
        if not res then
            rediskeepalive(red)
            kong.log.err("call introspect_url fail " .. config.introspect_url " err:" .. err)
            return kong.response.exit(401, "call introspect_url fail ")
        end

        local res = cjson.decode(res.body)
        if res.active then
            -- 有效 根据返回回来的过期时间计算需要缓存的时间进行缓存，判断nbf字段，只有在nbf之后才算生效，在exp之前
            local now = os.time()
            if res.nbf > now then
                rediskeepalive(red)
                return kong.response.exit(401, "token will valid after:" .. res.nbf .. " now:" .. now)
            end
            if now > res.exp then
                rediskeepalive(red)
                return kong.response.exit(401, "token is exp now:" .. now .. ", exp:" .. res.exp)
            end

            local expseconds = res.exp - now

            local ok, err = red:set(cachekey, "valid")
            if not ok then
                kong.log.err("failed to set " .. cachekey .. ": " .. "valid redis err:" .. err)
            end
            local ok, err = red:expire(cachekey, expseconds)
            if not ok then
                kong.log.err("failed to expire " .. cachekey .. ": 60s redis err:" .. err)
            end
        else
            -- 失效 缓存1分钟，避免短时间大量请求过来
            local ok, err = red:set(cachekey, "invalid")
            if not ok then
                kong.log.err("failed to set " .. cachekey .. ": " .. "invalid")
                rediskeepalive(red)
                return kong.response.exit(401, "token invalid")
            end

            local ok, err = red:expire(cachekey, 60)

            if not ok then
                kong.log.err("failed to expire " .. cachekey .. ": 60s")
                rediskeepalive(red)
                return kong.response.exit(401, "token invalid")
            end
            kong.log.err("token invalid " .. basicHeader)
            rediskeepalive(red)
            return kong.response.exit(401, "token invalid")
        end
    end
end

function TokenAuthHandler:header_filter(config)
end

return TokenAuthHandler
