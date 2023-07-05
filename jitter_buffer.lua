local _jitter_buffer = {}

local function _comparator(l, r)
    if math.abs(l.key - r.key) >= 1000 then
        return l.key > r.key
    end
    return l.key < r.key
end

function _jitter_buffer:init(sz, logger)
    self._buf = {}
    self._sz = sz or 50
    self._comparator = _comparator
    self._logger = logger or nil
end

function _jitter_buffer:push(seq, data)
    for _, kv in ipairs(self._buf) do
        if kv.key == seq then
            -- debug
            if self._logger then
                self._logger("duplicated " .. seq .. ", ignore\n")
            end
            return
        end
    end

    table.insert(self._buf, {key = seq, value = data})
    table.sort(self._buf, self._comparator)

    if #self._buf > self._sz then
        local front = self._buf[1]
        table.remove(self._buf, 1)
        -- debug
        if self._logger then
            self._logger("pop " .. front.key .. "\n")
        end
        return front.key, front.value
    end
end

function _jitter_buffer:pop()
    if #self._buf > 0 then
        local front = self._buf[1]
        table.remove(self._buf, 1)
        -- debug
        if self._logger then
            self._logger("pop " .. front.key .. "\n")
        end
        return front.key, front.value
    end
end

function _jitter_buffer:size()
    return #self._buf
end

function _jitter_buffer:clear()
    self._buf = {}
end

function _jitter_buffer.new(sz, logger)
    local inst = {}
    setmetatable(inst, {__index = _jitter_buffer})
    inst:init(sz, logger)
    return inst
end

return _jitter_buffer
