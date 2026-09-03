# Pcap Data Validation

Desktop dashboard for PCAP/PCAPNG validation and protocol analysis using Wireshark/TShark dissectors.

## Features

- Overview and protocol distribution
- Upload behavior and session analysis
- DNS, TLS, HTTP content, files, and images
- STUN transaction details
- RADIUS analysis and CSID/ECI correlation
- SS7/GSM MAP/GSM SMS subscriber and signaling extraction
- VoIP SIP/RTP inspection
- CCTV/RTSP/RTP best-effort media extraction
- Satellite/iDirect PCAPNG custom-block telemetry extraction
- Raw packet/detail exports

## Requirements

- Python 3.10 or newer: https://www.python.org/downloads/
- Wireshark with TShark, mergecap, and capinfos: https://www.wireshark.org/download.html
- Optional FFmpeg for RTP audio/video conversion: https://ffmpeg.org/download.html

## Quick Start

```bat
run_dashboard.bat
```

Or:

```bat
python pcap_dashboard.py
```

## Setup Check

```bat
check_setup.bat
```

## Offline Setup

See `README_OFFLINE_SETUP.md` for full offline installation and dependency instructions.

## Notes

The dashboard relies on Wireshark/TShark dissectors for protocol decoding. Encrypted traffic such as TLS, QUIC, ESP, WireGuard, OpenVPN, and SRTP cannot be decoded into readable content without the required keys.

