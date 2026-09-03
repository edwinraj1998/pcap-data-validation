import sys
import os
from scapy.all import rdpcap, UDP
import subprocess

def extract_rtp_payload(pcap_file, udp_port, output_raw):
    print(f"Reading PCAP: {pcap_file}")
    packets = rdpcap(pcap_file)
    payloads = []
    
    for pkt in packets:
        if UDP in pkt and pkt[UDP].dport == udp_port:
            raw_data = bytes(pkt[UDP].payload)
            if len(raw_data) > 12:  # Basic RTP header is 12 bytes
                rtp_payload = raw_data[12:]  # Strip RTP header
                payloads.append(rtp_payload)
    
    if not payloads:
        print(f"No RTP packets found on UDP port {udp_port}.")
        return

    print(f"Writing {len(payloads)} payloads to {output_raw}")
    with open(output_raw, 'wb') as f:
        for p in payloads:
            f.write(p)

def convert_with_ffmpeg(input_raw, output_file, codec='h264'):
    print(f"Converting {input_raw} to {output_file} using FFmpeg...")
    cmd = [
        'ffmpeg',
        '-f', codec,
        '-i', input_raw,
        '-c:v', 'copy',
        output_file
    ]
    try:
        subprocess.run(cmd, check=True)
        print(f"Conversion complete. Output saved to {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"FFmpeg error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python extract_rtp_pipeline.py <input.pcap> <udp_port>")
        sys.exit(1)

    pcap_path = sys.argv[1]
    udp_port = int(sys.argv[2])
    raw_output = "rtp_payload.raw"
    final_output = "cctv_output.mp4"  # or .aac depending on codec

    extract_rtp_payload(pcap_path, udp_port, raw_output)
    convert_with_ffmpeg(raw_output, final_output, codec='h264')  # change codec to 'aac' if needed
