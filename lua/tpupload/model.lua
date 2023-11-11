local _M = {}

-- TODO: we need to employ some kind of data caching here to avoid hitting
-- the database all the times.

local pgmoon = require "pgmoon"
local cjson = require "cjson"
local str = require "resty.string"
local quote_sql_str = ndk.set_var.set_quote_pgsql_str

local db_spec = {
    host = os.getenv("TPUPLOAD_DB_HOST"),
    port = os.getenv("TPUPLOAD_DB_PORT"),
    database = os.getenv("TPUPLOAD_DB_NAME"),
    user = os.getenv("TPUPLOAD_DB_USERNAME"),
    password = os.getenv("TPUPLOAD_DB_PASSWORD"),
    ssl = true,
    ssl_version = "tlsv1_2",
}

local function query_db(query)
    local pg = pgmoon.new(db_spec)

    --print("sql query: ", query)

    local ok, err

    for i = 1, 3 do
        ok, err = pg:connect()
        if not ok then
            ngx.log(ngx.ERR, "failed to connect to database: ", err)
            ngx.sleep(0.1)
        else
            break
        end
    end

    if not ok then
        ngx.log(ngx.ERR, "fatal response due to query failures")
        return ngx.exit(500)
    end

    -- the caller should ensure that the query has no side effects
    local res
    for i = 1, 2 do
        res, err = pg:query(query)
        if not res then
            ngx.log(ngx.ERR, "failed to send query: ", err)

            ngx.sleep(0.1)

            ok, err = pg:connect()
            if not ok then
                ngx.log(ngx.ERR, "failed to connect to database: ", err)
                break
            end
        else
            break
        end
    end

    if not res then
        ngx.log(ngx.ERR, "fatal response due to query failures")
        return ngx.exit(500)
    end

    local ok, err = pg:keepalive(0, 5)
    if not ok then
        ngx.log(ngx.ERR, "failed to keep alive: ", err)
    end

    return res
end

function _M.find_file(i,hash_hex)
    local pg = pgmoon.new(db_spec)
    
    local ret = "id as bucket_id,encode(hash,'hex') as hash,len as size"
    local sql_get = "select " .. ret .. " from files where id=" .. i .. " and hash=decode('" .. hash_hex .. "','hex')"
    local resg = query_db(sql_get)
    if #resg == 0 then
        return nil;
    end
    return resg[1]
end

function _M.put_file_to_bucket(i,hash_hex,bin)
    local pg = pgmoon.new(db_spec)
    
    local ret = "id as bucket_id,encode(hash,'hex') as hash,len as size"

    local hex = str.to_hex(bin)
    local sql_query = "insert into files (id,bin) values (" .. i .. ",decode('".. hex .. "','hex')) returning " .. ret .. ";"
    local res = query_db(sql_query)

    --print("JSON: ", cjson.encode(res))
    if #res == 0 then
        ngx.log(ngx.ERR, "Cannot store")
        return nil
    end
    return res[1]
end

function _M.get_file_id_hash(i,hash)
    local pg = pgmoon.new(db_spec)
    --ngx.log(ngx.ERR, cjson.encode(i))
    --ngx.log(ngx.ERR, cjson.encode(hash))
    --local sql_fragment = pgmoon.Postgres.escape_literal("preved")
    local len = (#hash) / 2;
    local sql_query = "select bin from files where id=" .. i .. " and substring(hash,1," .. len .. ") = ('\\x" .. hash .."')"
    --print("JSON: ", sql_query)
    local res = query_db(sql_query)

    --print("JSON: ", cjson.encode(res))
    if #res == 0 then
        ngx.log(ngx.ERR, "file not found")
        return nil
    end
    return res[1]
end


function _M.get_i(i)
    local res = query_db("select bin from files where id=" .. i .. ";")

    --print("JSON: ", cjson.encode(res))
    if #res == 0 then
        ngx.log(ngx.ERR, "no main menu found")
        return ''
    end
    return res[1].bin
end

return _M
