local _RTP_SEQ_MOD = 65536
local _MAX_MISORDER = 3000

local _jitter_buffer = {}

local function _comparator(l, r)
    return l.key < r.key
end

function _jitter_buffer:init(sz, logger)
    self._buf = {}
    self._sz = sz or 50
    self._first = 1
    self._latest = 0
    self._cycle = 0
    self._comparator = _comparator
    self._logger = logger or nil
end

function _jitter_buffer:push(seq, data)
    local delta = 0
    if seq >= self._latest then
        delta = seq - self._latest
    else
        delta = _RTP_SEQ_MOD - self._latest + seq
    end

    if self._first ~= 0 then
        self._first = 0
        self._latest = seq
    elseif delta < _MAX_MISORDER then
        if seq < self._latest then
            self._cycle = self._cycle + _RTP_SEQ_MOD
        end
        self._latest = seq
    elseif delta > _RTP_SEQ_MOD - _MAX_MISORDER then
        -- duplicate or reordered packet
    else
        -- a new stream?
        self._latest = seq
        self._cycle = self._cycle + _RTP_SEQ_MOD
    end

    local ext_seq = self._cycle + seq
    for _, kv in ipairs(self._buf) do
        if kv.key == ext_seq then
            -- debug
            if self._logger then
                self._logger("duplicated: seq=" .. seq .. ", ext_seq=".. ext_seq)
            end
            return
        end
    end

    table.insert(self._buf, {key = ext_seq, value = {seq, data}})
    table.sort(self._buf, self._comparator)

    if #self._buf > self._sz then
        local front = self._buf[1]
        table.remove(self._buf, 1)
        -- debug
        if self._logger then
            self._logger("pop " .. front.value[1] .. "\n")
        end
        return front.value[1], front.value[2]
    end
end

function _jitter_buffer:pop()
    if #self._buf > 0 then
        local front = self._buf[1]
        table.remove(self._buf, 1)
        -- debug
        if self._logger then
            self._logger("pop " .. front.value[1] .. "\n")
        end
        return front.value[1], front.value[2]
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
