local _M = {}

local model = require "tpupload.model"
local cjson = require "cjson"
local upload = require "resty.upload"

local re_find = ngx.re.find
local re_match = ngx.re.match
local sub = string.sub
local byte = string.byte
local str = require "resty.string"
local http_time = ngx.http_time
local tonumber = tonumber
local resp_header = ngx.header
local ngx_time = ngx.time
local ngx_var = ngx.var
local format = string.format
local unescape_uri = ngx.unescape_uri
local match_table = {}

local function gen_cache_control_headers(ts)
    resp_header["Last-Modified"] = http_time(tonumber(ts))
    resp_header["Cache-Control"] = "max-age=300"
end

function _M.download()
    local uri = ngx_var.uri

    ngx.log(ngx.ERR,uri);
    local m = re_match(uri, [[/(\w+)/([01-9a-fA-F]{6,64})]], 'jox', nil, match_table)
    if m then
        if #m[2] % 2 == 1 then
            resp_header["error"] = "invalid hex string length"
            return ngx.exit(400)
        end
        local p = model.get_file_id_hash(m[1],m[2])
        if p == nil then
            return ngx.exit(404)
        else
            resp_header["Cache-Control"] = "max-age=31536000, immutable"
            ngx.print(p.bin)
            return
        end
    end
    return ngx.exit(404)
end

function _M.upload()
    local uri = ngx_var.uri
    local m = re_match(uri, [[/(\w+)/([01-9a-fA-F]{64})$]], 'jox', nil, match_table)
    if m then
        local found = model.find_file(m[1],m[2])
        --print("JSON: ", cjson.encode(found))
        if(found) then
            --ngx.print("File exists");
            resp_header["error"] = "file exists"
            return ngx.exit(409);
        end

        local upload = require "resty.upload"
        local chunk_size = 8192
        local filename = m[1] .. "-" .. m[2]
        local uploadpath = "client_body_temp/"
        local file_name = uploadpath..filename
        filename = nil
        local file

        local form = upload:new(chunk_size)
        if form then
            file = io.open(file_name, "w+")
            if not file then
                   resp_header["error"] = cjson.encode({code=2,message="file save failed"})
                   return ngx.exit(500);
            end
            while true do
                local typ, res, err = form:read()
               if not typ then
                       resp_header["error"] = cjson.encode({code=1,message="nofile upload"})
                       return ngx.exit(500);
                end

                if typ == "body" then
                    if file then
                        assert(file:write(res))
                    end

                elseif typ == "part_end" then
                    assert(file:close())
                    file = nil
                    file = io.open(file_name, "rb")
                    local data = file:read("*all")
                    assert(file:close())
                    assert(os.remove(file_name))
                    file_name = nil
                    local resty_sha256 = require "resty.sha256"
                    local sha256 = resty_sha256:new()
                    assert(sha256:update(data))
                    local digest = str.to_hex(sha256:final())
                    if(digest==m[2]) then
                        res = model.put_file_to_bucket(m[1],digest,data)
                        ngx.say(cjson.encode(res))
                        return
                    else
                        --ngx.say("File hash mismatch");
                        resp_header["error"] = "hash mismatch"
                        return ngx.exit(400)
                    end
                elseif typ == "eof" then
                    break
                else
                    -- do nothing
                end
            end
        else
            ngx.say(cjson.encode({code=1,message="nofile upload"}))
            return
        end
    end
    return ngx.exit(404)
end

--not used
function _M.run()
    local uri = ngx_var.uri
    --if uri == "/test1" then
    --    resp_header["Cache-Control"] = "max-age=3600"
    --    ngx.print("preved")
    --    return
    --end

    local m = re_match(uri, [[^/data/(\w+)/([01-9a-fA-F]{6,64})$]], 'jox', nil, match_table)
    --ngx.log(ngx.ERR,uri);
    if m then
        if #m[2] % 2 == 1 then
            return ngx.exit(400)
        end
        resp_header["Cache-Control"] = "max-age=7200"
        local p = model.get_file_id_hash(m[1],m[2])
        if p == nil then
            return ngx.exit(404)
        else
            --print("JSON: ", cjson.encode(p))
            ngx.print(p.bin)
            return
        end
    end

    local m = re_match(uri, [[^/upload/(\w+)/([01-9a-fA-F]{64})$]], 'jox', nil, match_table)
    if m then
        local found = model.find_file(m[1],m[2])
        --print("JSON: ", cjson.encode(found))
        if(found) then
            --ngx.print("File exists");
            resp_header["error"] = "file exists"
            return ngx.exit(409);
        end

        local upload = require "resty.upload"
        local chunk_size = 8192
        local filename = m[1] .. "-" .. m[2]
        local uploadpath = "client_body_temp/"
        local file_name = uploadpath..filename
        filename = nil
        local file

        local form = upload:new(chunk_size)
        if form then
            file = io.open(file_name, "w+")
            if not file then
                ngx.say(cjson.encode({code=2,message="file save failed"}))
                return
            end
            while true do
                local typ, res, err = form:read()
                if not typ then
                    ngx.say(cjson.encode({code=1,message="nofile upload"}))
                    return
                end

                if typ == "body" then
                    if file then
                        assert(file:write(res))
                    end

                elseif typ == "part_end" then
                    assert(file:close())
                    file = nil
                    file = io.open(file_name, "rb")
                    local data = file:read("*all")
                    assert(file:close())
                    assert(os.remove(file_name))
                    file_name = nil
                    local resty_sha256 = require "resty.sha256"
                    local sha256 = resty_sha256:new()
                    assert(sha256:update(data))
                    local digest = str.to_hex(sha256:final())
                    if(digest==m[2]) then
                        res = model.put_file_to_bucket(m[1],digest,data)
                        ngx.say(cjson.encode(res))
                        return
                    else
                        --ngx.say("File hash mismatch");
                        resp_header["error"] = "hash mismatch"
                        return ngx.exit(400)
                    end
                elseif typ == "eof" then
                    break
                else
                    -- do nothing
                end
    end
else
    ngx.say(cjson.encode({code=1,message="nofile upload"}))
    return
end
    end

--    local m = re_match(uri, [[^/test2/(\w+)$]], 'jox', nil, match_table)
--    ngx.log(ngx.ERR,uri);
--    if m then
--        resp_header["Cache-Control"] = "max-age=3600"
--        local p = model.get_i(m[1])
--        print("JSON: ", cjson.encode(p))
--        ngx.print(p)
--        return
--    end

--    if uri == "/" then
--        resp_header["Cache-Control"] = "max-age=3600"
--        return ngx.redirect("/test1/", 302)
--    end
--
--    if (re_find(uri, [[ ^ / (?: [a-z]{2} ) $ ]], 'jox')) then
--        resp_header["Cache-Control"] = "max-age=3600"
--        return ngx.redirect(uri .. "/", 301)
--    end

    return ngx.exit(404)
end

return _M
