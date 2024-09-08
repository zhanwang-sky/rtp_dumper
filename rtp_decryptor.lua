jitterBuffer = require("jitter_buffer")

-- Define the menu entry's callback
do
    -- fields
    local rtp_seq_f = Field.new("rtp.seq")
    local rtp_ssrc_f = Field.new("rtp.ssrc")
    local rtp_payload_f = Field.new("rtp.payload")

    local function rtp_decryptor()

        local function dialog_func(user_filter)
            -- previous seq num
            local prev_seq = 0

            -- Declare the window we will use
            local tw = TextWindow.new("RTP Decryptor")

            -- Declare our log function
            local function twlog(msg)
                tw:append(msg)
            end

            -- this is our tap
            local tap = Listener.new("rtp", user_filter)

            -- RTP jitter buffer
            local jbuf = jitterBuffer.new(50, twlog)

            -- Creates a pcap file to dump decrypted packets.
            local dumper = Dumper.new(os.getenv("HOME") .. "/dump.pcap",
                                      wtap_name_to_file_type_subtype("pcap"))

            local function remove()
                -- close pcap file
                dumper:close()
                -- this way we remove the listener that otherwise will remain running indefinitely
                tap:remove()
            end

            -- we tell the window to call the remove() function when closed
            tw:set_atclose(remove)

            -- print welcome message
            twlog("User Filter:\n" .. user_filter .. "\n\n========================================\n\n")

            -- this function will be called once for each packet
            function tap.packet(pinfo, tvb)
                local field_rtp_seq = rtp_seq_f()
                local field_rtp_ssrc = rtp_ssrc_f()
                local field_rtp_payload = rtp_payload_f()
                if pinfo and tvb and field_rtp_seq and field_rtp_ssrc and field_rtp_payload then
                    local rtp_seq = field_rtp_seq.value
                    local rtp_ssrc = field_rtp_ssrc.value

                    local raw_pkt = tvb:bytes()
                    local raw_key = ByteArray.new(string.format("%08x", rtp_ssrc))

                    local pkt_len = raw_pkt:len()
                    local payload_len = field_rtp_payload.value:raw():len()
                    local offset = pkt_len - payload_len
                    local pos = 0

                    while pos < payload_len do
                        local val = raw_pkt:get_index(offset + pos)
                        val = bit.bxor(val, raw_key:get_index(pos % 4))
                        raw_pkt:set_index(offset + pos, val)
                        pos = pos + 1
                    end

                    raw_pkt = raw_pkt:subset(2, pkt_len - 2)

                    -- push to jitter buffer
                    local seq, ordered_data = jbuf:push(rtp_seq, {ts = pinfo.abs_ts, data = raw_pkt})
                    if seq then
                        if seq ~= (prev_seq + 1) % 65536 then
                            twlog("XXX Unordered seq num " .. prev_seq .. " -> " .. seq .. "\n")
                        end
                        prev_seq = seq

                        if ordered_data then
                            dumper:dump(ordered_data.ts, PseudoHeader.none(), ordered_data.data)
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
                        dumper:dump(ordered_data.ts, PseudoHeader.none(), ordered_data.data)
                    end
                end
            end

            dumper:flush()

            twlog("\nDone\n")
        end

        new_dialog("RTP Decryptor", dialog_func, "User Filter: ")
    end

    -- Create the menu entry
    register_menu("RTP Decryptor", rtp_decryptor, MENU_TOOLS_UNSORTED)
end
