jitterBuffer = require("jitter_buffer")

-- Define the menu entry's callback
do
    -- fields
    local rtp_marker_f = Field.new("rtp.marker")
    local rtp_seq_f = Field.new("rtp.seq")
    local rtp_ts_f = Field.new("rtp.timestamp")
    local rtp_payload_f = Field.new("rtp.payload")

    local function payload_dumper_tlv()

        local function dialog_func(user_filter)
            -- previous seq num
            local prev_seq = 0

            -- Declare the window we will use
            local tw = TextWindow.new("RTP Payload Dumper")

            -- Declare our log function
            local function twlog(msg)
                tw:append(msg)
            end

            -- this is our tap
            local tap = Listener.new("rtp", user_filter)

            -- RTP jitter buffer
            local jbuf = jitterBuffer.new(50, twlog)

            -- Creates a file to dump rtp payloads.
            local fd = io.open(os.getenv("HOME") .. "/dump.tlv", "wb")

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
            function tap.packet(pinfo)
                local field_rtp_marker = rtp_marker_f()
                local field_rtp_seq = rtp_seq_f()
                local field_rtp_ts = rtp_ts_f()
                local field_rtp_payload = rtp_payload_f()
                if field_rtp_marker and field_rtp_seq and field_rtp_ts and field_rtp_payload then
                    local rtp_marker = field_rtp_marker.value
                    local rtp_seq = field_rtp_seq.value
                    local rtp_ts = field_rtp_ts.value
                    local captuer_ts = math.floor(pinfo.abs_ts * 1000)
                    local rtp_payload = field_rtp_payload.value:raw()
                    local total_len = rtp_payload:len() + 17

                    local tlv = ''
                    -- length (little endian)
                    tlv = tlv .. string.pack("<I2", total_len)
                    -- Marker
                    tlv = tlv .. string.char(rtp_marker and 1 or 0)
                    -- seq (little endian)
                    tlv = tlv .. string.pack("<I2", rtp_seq)
                    -- timestamp (little endian)
                    tlv = tlv .. string.pack("<I4", rtp_ts)
                    -- timestamp_ms (little endian)
                    tlv = tlv .. string.pack("<I8", captuer_ts)
                    -- body
                    tlv = tlv .. rtp_payload

                    -- push to jitter buffer
                    local seq, ordered_data = jbuf:push(rtp_seq, tlv)
                    if seq then
                        if seq ~= (prev_seq + 1) % 65536 then
                            twlog("XXX Unordered seq num " .. prev_seq .. " -> " .. seq .. "\n")
                        end
                        prev_seq = seq

                        if ordered_data then
                            fd:write(ordered_data)
                        end
                    end
                end
            end

            -- this function will be called whenever a reset is needed
            -- e.g. when reloading the capture file
            function tap.reset()
                jbuf:clear()
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
                        fd:write(ordered_data)
                    end
                end
            end

            fd:flush()

            twlog("\nDone\n")
        end

        new_dialog("RTP Payload Dumper (TLV)", dialog_func, "User Filter: ")
    end

    -- Create the menu entry
    register_menu("RTP Payload Dumper (TLV)", payload_dumper_tlv, MENU_TOOLS_UNSORTED)
end
