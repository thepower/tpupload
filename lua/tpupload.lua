local _M = {}

local controller = require "tpupload.controller"

function _M.download()
    controller.download()
end

function _M.upload()
    controller.upload()
end

function _M.go()
    controller.run()
end

return _M
