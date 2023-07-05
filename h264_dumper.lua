package.prepend_path("/Applications/Wireshark.app/Contents/Resources/share/wireshark/rtp_dumper")

jitterBuffer = require("jitter_buffer")

h264Dumper = {}

function h264Dumper:init(fd, logger)
    self._fd = fd
    self._logger = logger
    self._fu_ongoing = false
    self._fu_payload = {}
end

function h264Dumper:on_h264_data(seq, data)
    local nal_unit_type = bit.band(string.byte(data, 1), 0x1f)
    if nal_unit_type > 0 and nal_unit_type < 24 then
        -- Single NAL unit
        if self._logger then
            self._logger(string.format("[%d] Single NAL unit, len=%d\n", seq, data:len()))
        end
        if self._fd then
            self._fd:write("\000\000\000\001")
            self._fd:write(data)
        end
    elseif nal_unit_type == 24 then
        -- Single-time aggregation packet A
        if self._logger then
            self._logger(string.format("[%d] Single-time aggregation packet A, len=%d\n", seq, data:len()))
        end
        if self._fd then
            local offset = 2 -- skip NAL unit header of STAP-A (1 byte)
            repeat
                local size = string.byte(data, offset)
                size = size * 256 + string.byte(data, offset + 1)
                offset = offset + 2
                if self._logger then
                    self._logger(string.format(" - writing STAP-A unit, size %d\n", size))
                end
                self._fd:write("\000\000\000\001")
                self._fd:write(string.sub(data, offset, offset + size - 1))
                offset = offset + size
            until offset > data:len()
        end
    elseif nal_unit_type == 28 then
        -- Fragmentation unit A (FU-A)
        if self._logger then
            self._logger(string.format("[%d] Fragmentation unit A (FU-A), len=%d\n", seq, data:len()))
        end
        local fu_header = string.byte(data, 2)
        if bit.band(fu_header, 0x80) ~= 0 then
            -- the first packet of FU-A picture
            if self._logger then
                self._logger(" - FU-A start\n")
                if self._fu_ongoing then
                    self._logger(" - XXX discard previous FU-A payload\n")
                end
            end
            self._fu_ongoing = true
            self._fu_payload = {}
            table.insert(self._fu_payload, string.sub(data, 3))
        elseif bit.band(fu_header, 0x40) ~= 0 then
            -- the last packet of FU-A picture
            if self._logger then
                self._logger(" - FU-A end\n")
            end
            if self._fu_ongoing then
                table.insert(self._fu_payload, string.sub(data, 3))
                if self._fd then
                    local fu_identifier = string.byte(data, 1)
                    local nal_unit_header = bit.bor(bit.band(fu_identifier, 0xe0), bit.band(fu_header, 0x1f))
                    self._fd:write("\000\000\000\001")
                    self._fd:write(string.char(nal_unit_header))
                    for i, p in ipairs(self._fu_payload) do
                        self._fd:write(p)
                    end
                end
            else
                if self._logger then
                    self:log(" - XXX FU-A not started, discard")
                end
            end
            self._fu_ongoing = false
            self._fu_payload = {}
        else
            if self._fu_ongoing then
                table.insert(self._fu_payload, string.sub(data, 3))
            else
                if self._logger then
                    self:log(" - XXX FU-A not started, discard")
                end
            end
        end
    else
        -- unsupported NAL Unit Type
        if self._logger then
            self._logger(string.format("[%d] XXX unsupported NAL Unit Type %d, len=%d\n", seq, nal_unit_type, data:len()))
        end
    end
end

function h264Dumper:reset()
    self._fu_ongoing = false
    self._fu_payload = {}
end

function h264Dumper.new(fd, logger)
    local inst = {}
    setmetatable(inst, {__index = h264Dumper})
    inst:init(fd, logger)
    return inst
end

-- Define the menu entry's callback
do
    -- fields
    local rtp_seq_f = Field.new("rtp.seq")
    local rtp_payload_f = Field.new("rtp.payload")

    local function h264_dumper()

        local function dialog_func(user_filter)
            -- previous seq num
            local prev_seq = 0

            -- Declare the window we will use
            local tw = TextWindow.new("H.264 Dumper")

            -- Declare our log function
            local function twlog(msg)
                tw:append(msg)
            end

            -- this is our tap
            local tap = Listener.new("rtp", user_filter)

            -- RTP jitter buffer
            local jbuf = jitterBuffer.new(50, twlog)

            -- Creates a file to dump rtp payloads.
            local fd = io.open(os.getenv("HOME") .. "/dump.h264", "wb")

            -- H.264 dumper
            local dumper = h264Dumper.new(fd, twlog)

            local function remove()
                -- close output file
                fd:close()
                -- this way we remove the listener that otherwise will remain running indefinitely
                tap:remove()
            end

            -- we tell the window to call the remove() function when closed
            tw:set_atclose(remove)

            -- print welcome message
            twlog("User Filter:\n" .. user_filter .. "\n\n========================================\n\n")

            -- this function will be called once for each packet
            function tap.packet()
                local field_rtp_seq = rtp_seq_f()
                local field_rtp_payload = rtp_payload_f()
                if field_rtp_seq then
                    local rtp_seq = field_rtp_seq.value
                    local rtp_payload = nil
                    if field_rtp_payload then
                        rtp_payload = field_rtp_payload.value:raw()
                    end

                    -- push to jitter buffer
                    local seq, ordered_data = jbuf:push(rtp_seq, rtp_payload)
                    if seq then
                        if seq ~= (prev_seq + 1) % 65536 then
                            twlog("XXX Unordered seq num " .. prev_seq .. " -> " .. seq .. "\n")
                        end
                        prev_seq = seq

                        if ordered_data then
                            dumper:on_h264_data(seq, ordered_data)
                        end
                    end
                end
            end

            -- this function will be called whenever a reset is needed
            -- e.g. when reloading the capture file
            function tap.reset()
                jbuf:clear()
                dumper:reset()
            end

            -- Ensure that all existing packets are processed.
            retap_packets()

            while jbuf:size() > 0 do
                local seq, ordered_data = jbuf:pop()
                if seq then
                    if seq ~= (prev_seq + 1) % 65536 then
                        twlog("XXX Unordered seq num " .. prev_seq .. " -> " .. seq .. "\n")
                    end
                    prev_seq = seq

                    if ordered_data then
                        dumper:on_h264_data(seq, ordered_data)
                    end
                end
            end

            fd:flush()

            twlog("\nDone\n")
        end

        new_dialog("H.264 Dumper", dialog_func, "User Filter: ")
    end

    -- Create the menu entry
    register_menu("H.264 Dumper", h264_dumper, MENU_TOOLS_UNSORTED)
end
