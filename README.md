# Automatically Extract and Recover Video from Network Packet Captures

## Overview

This tool automatically analyzes **PCAP files** (network packet captures) and extracts video streams from them. It detects and recovers multiple video formats without requiring prior knowledge of the stream type.

---

## Supported Formats

- **MJPEG** – Motion JPEG (individual JPEG frames)
- **MP4** – HTTP video streams
- **FLV** – Flash Video
- **RTP** – Real-Time Transport Protocol
- **H.264 / H.265** – Raw video codecs

---

## Quick Start

### 1. Install Dependencies

#### Kali Linux / Debian / Ubuntu
```bash
sudo apt update
sudo apt install python3-scapy ffmpeg
```

#### Other Linux Distributions
```bash
pip3 install scapy
sudo apt install ffmpeg
```

---

### 2. Download the Script
```bash
wget https://raw.githubusercontent.com/lucasmilhomem11/pcap-video-recovery/main/universal_Video_Recovery.py
chmod +x universal_extract.py
```

---

### 3. Run the Script
```bash
python3 universal_extract.py your_capture.pcap
```

The script will:
1. Analyze the PCAP file
2. Detect the video format automatically
3. Extract the video stream
4. Save the output as `recovered_video.mp4`

---

## Usage Examples

### Basic Usage
```bash
python3 universal_extract.py capture.pcap
```

### Specify Frame Rate (FPS)
```bash
python3 universal_extract.py capture.pcap 30
```

### Custom Output Filename
```bash
python3 universal_extract.py capture.pcap 25 my_video.mp4
```

---

## How It Works

### Extraction Flow

```
PCAP File
   │
   ▼
Auto-Detect Video Type
   │
   ▼
Extract Stream or Frames
   │
   ▼
Rebuild Video
   │
   ▼
recovered_video.mp4
```

---

### Detection Logic

| Format | Detection Clue | Description |
|-------|----------------|-------------|
| **MJPEG** | `multipart/x-mixed-replace` | HTTP JPEG stream |
| **MP4** | `Content-Type: video/mp4` | HTTP video transfer |
| **FLV** | `FLV` magic bytes | Flash video |
| **RTP** | RTP v2 headers | Real-time streams |
| **H.264** | `00 00 00 01` | Raw NAL units |

---

## Example Output

```text
============================================================
Universal Video Recovery from PCAP
Automatically detects: MJPEG, MP4, FLV, RTP, H.264
============================================================

[*] Reading PCAP file: camera_capture.pcap
[*] Total packets: 5432
[*] Analyzing stream type...
[+] Detected stream type: MJPEG
[*] Confidence scores:
    mjpeg: 50
    http_mp4: 0
    rtp: 3
    raw_h264: 2

============================================================
Extracting MJPEG stream
============================================================

[*] Extracted 245 JPEG frames
[*] Converting frames at 25 FPS...
[+] Video saved: recovered_video.mp4
[+] Duration: 9.80 seconds
```

---

## Advanced Options

### Common Frame Rates

| FPS | Use Case |
|-----|----------|
| 15  | Security cameras |
| 25  | PAL standard (default) |
| 30  | NTSC / smoother motion |
| 60  | High-speed video |

---

### Manual FPS Adjustment
```bash
python3 universal_extract.py capture.pcap 15
python3 universal_extract.py capture.pcap 30
```

---

## Troubleshooting

### No Video Stream Detected
Inspect the capture in Wireshark:
```bash
wireshark capture.pcap
```

Look for:
- `Content-Type: video/*`
- `image/jpeg`
- RTP (UDP traffic)
- Large continuous TCP streams

---

### ffmpeg Not Found
```bash
sudo apt install ffmpeg
```

---

### Video Speed Incorrect
Adjust FPS:
```bash
python3 universal_extract.py capture.pcap 30
```

---

### Frames Extracted but No Video
Manually convert frames:
```bash
ffmpeg -framerate 25 -i frames/frame_%05d.jpg -c:v libx264 -pix_fmt yuv420p output.mp4
```

---

## File Structure

```
project/
├── capture.pcap
├── universal_extract.py
├── frames/
│   ├── frame_00001.jpg
│   └── ...
├── recovered_video.mp4
└── extracted_video.mp4
```

---

## Common Use Cases

- Security camera forensic analysis
- Network traffic inspection
- IoT device monitoring

---

## Tips & Best Practices

1. Capture complete streams (start before and stop after the video)
2. Filter traffic before saving:
   ```
   tcp.port == 80 or udp
   ```
3. Small PCAPs may not contain full video
4. Adjust FPS for smooth playback

---

## Known Limitations

- Encrypted streams (HTTPS / SRTP) cannot be recovered
- Fragmented captures may produce incomplete videos
- Proprietary camera protocols may require custom parsers
- Very large PCAP files may require significant RAM

---

## Technical Reference

### Supported Protocols

| Protocol | Port(s) | Transport |
|----------|---------|-----------|
| HTTP/MJPEG | 80, 8080 | TCP |
| RTSP | 554 | TCP/UDP |
| RTP | Various | UDP |
| HTTP/MP4 | 80, 443 | TCP |

---

### Magic Bytes

| Format | Hex |
|--------|-----|
| JPEG | FF D8 FF E0 |
| MP4 | 66 74 79 70 |
| FLV | 46 4C 56 |
| H.264 | 00 00 00 01 |

---

## Quick Reference

```bash
# Install
sudo apt install python3-scapy ffmpeg

# Run
python3 universal_extract.py capture.pcap

# Custom FPS
python3 universal_extract.py capture.pcap 30

# Custom output
python3 universal_extract.py capture.pcap 25 output.mp4
```

---

⭐ If this tool helped you, please star the repository.

_Last updated: January 2026_
