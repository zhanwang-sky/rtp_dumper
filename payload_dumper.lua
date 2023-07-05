package.prepend_path("/Applications/Wireshark.app/Contents/Resources/share/wireshark/rtp_dumper")

jitterBuffer = require("jitter_buffer")

-- Define the menu entry's callback
do
    -- fields
    local rtp_seq_f = Field.new("rtp.seq")
    local rtp_payload_f = Field.new("rtp.payload")

    local function payload_dumper()

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
            local fd = io.open(os.getenv("HOME") .. "/dump.raw", "wb")

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

        new_dialog("RTP Payload Dumper", dialog_func, "User Filter: ")
    end

    -- Create the menu entry
    register_menu("RTP Payload Dumper", payload_dumper, MENU_TOOLS_UNSORTED)
end
