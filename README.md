# rtp_dumper
A wireshark plugin, extracts H.264 NALU or RAW RTP payloads from pcap file.

## Usage

**Step 1. Install**

```
cd /Applications/Wireshark.app/Contents/Resources/share/wireshark

git clone https://github.com/zhanwang-sky/rtp_dumper.git

echo 'dofile(DATA_DIR.."rtp_dumper/h264_dumper.lua")' >> init.lua
echo 'dofile(DATA_DIR.."rtp_dumper/payload_dumper.lua")' >> init.lua
```

**Step 2. Enjoy**

<img width="605" alt="image" src="https://github.com/zhanwang-sky/rtp_dumper/assets/6380117/d2b540c6-df16-4b1d-91dd-db392c5efa16">
