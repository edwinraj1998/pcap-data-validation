# Pcap Data Validation - Offline Team Package

This package contains the current `pcap_dashboard.py` dashboard script and reference scripts used while adding RADIUS and RTP/CCTV support.

## 1. What is included

- `pcap_dashboard.py` - main dashboard application.
- `run_dashboard.bat` - double-click launcher for Windows.
- `check_setup.bat` - checks Python, TShark, mergecap, capinfos, FFmpeg, and Python modules.
- `requirements_offline.txt` - Python packages used by optional dashboard features.
- `reference_scripts/` - helper/reference scripts for RADIUS and RTP work.

## 2. Required software

Install these before running the dashboard:

- Python 3.10 or newer
  - Official download page: https://www.python.org/downloads/
  - During install, tick `Add python.exe to PATH`.
- Wireshark with TShark
  - Official download page: https://www.wireshark.org/download.html
  - TShark is normally installed at `C:\Program Files\Wireshark\tshark.exe`.
  - The dashboard also uses `mergecap.exe` for merging and `capinfos.exe` for capture info.

Optional but recommended:

- FFmpeg
  - Official download page: https://ffmpeg.org/download.html
  - Windows builds page linked by FFmpeg: https://www.gyan.dev/ffmpeg/builds/
  - Add the FFmpeg `bin` folder to PATH if you want RTP audio/video conversion features.

## 3. Python package setup

If the offline machine has internet:

```bat
cd /d "%~dp0"
python -m pip install --upgrade pip
python -m pip install -r requirements_offline.txt
```

If the offline machine has no internet, prepare the packages on an internet machine first:

```bat
mkdir wheelhouse
python -m pip download -r requirements_offline.txt -d wheelhouse
```

Copy this whole folder, including `wheelhouse`, to the offline machine, then install:

```bat
cd /d "%~dp0"
python -m pip install --no-index --find-links=wheelhouse -r requirements_offline.txt
```

Note: the dashboard can still open without `matplotlib` and `Pillow`, but graph/image preview features may be limited.

## 4. Run the dashboard

Double-click:

```bat
run_dashboard.bat
```

Or run from Command Prompt / PowerShell:

```bat
cd /d "C:\Path\To\Pcap_Data_Validation_offline_package_20260830_135500"
python pcap_dashboard.py
```

## 5. Check setup

Run:

```bat
check_setup.bat
```

Expected important results:

- Python found
- TShark found
- mergecap found
- capinfos found

FFmpeg is optional. If it is missing, normal PCAP analysis still works, but RTP audio/video conversion may not.

## 6. Supported capture inputs

The dashboard supports files that Wireshark/TShark can read, including:

- `.pcap`
- `.pcapng`
- `.done` files that contain PCAP/PCAPNG data
- merged captures created by `mergecap`

For SharePoint/OneDrive shared URLs, download permission is required. If the URL returns HTTP 403 Forbidden, open the link in a browser, sign in, download the capture locally, then browse to the local file in the dashboard.

## 7. Main dashboard areas

- Overview
- Protocols
- Upload Behavior
- DNS
- TLS
- Sessions
- HTTP Content
- Files & Images
- STUN
- RADIUS
- SS7
- Subscriber Leaks
- VoIP SIP/RTP
- CCTV
- Satellite
- Raw Data

## 8. Important notes

- The dashboard uses Wireshark/TShark dissectors to decode protocol fields.
- Encrypted traffic such as TLS, QUIC, ESP, WireGuard, OpenVPN, and SRTP cannot be decoded into content unless the required decryption keys are available.
- For SRTP audio/video, payload extraction alone is not enough. You need the SRTP keying material from SDP/DTLS/key logs/endpoints.
- Very large captures can take time. Quick mode gives faster session summaries; detailed mode gives better upload behavior analysis.

## 9. Quick troubleshooting

If `TShark not found` appears:

1. Install Wireshark.
2. Open the dashboard.
3. Go to `Settings > Configure TShark Path`.
4. Select `C:\Program Files\Wireshark\tshark.exe`.

If merging is not working:

- Confirm `mergecap.exe` exists in the same folder as `tshark.exe`.
- Ensure source files are readable by Wireshark.
- The dashboard does not modify original capture files.

If RTP/H.264/VLC does not play:

- It may be SRTP encrypted.
- It may be audio mislabeled as video.
- The stream may be missing SDP codec mapping, SPS/PPS, or start codes.
- Install FFmpeg and retry export/conversion.

