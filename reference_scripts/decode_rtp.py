#!/usr/bin/env python3
import subprocess, argparse, os, sys

def decode_with_rtpdec(pcap_file, udp_port, payload_type, sample_rate, output_file):
    """
    Uses the rtpdec CLI tool to decode RTP packets from a pcap into a raw stream.
    Requires: rtpdec installed and in your PATH.
    """
    cmd = [
        'rtpdec',
        '-p', str(payload_type),
        '-s', str(sample_rate),
        '-f', 'pcap',
        pcap_file,
        str(udp_port)
    ]
    print('Running:', ' '.join(cmd))
    with open(output_file, 'wb') as out:
        subprocess.run(cmd, stdout=out, check=True)
    print(f"Output written to {output_file}")

def decode_with_pylivestream(pcap_file, udp_port, output_dir):
    """
    Uses pylivestream to read RTP stream from pcap and write an HLS playlist.
    Requires: pylivestream installed (pip install pylivestream).
    """
    from pylivestream import RtpDumpSource, HLSStream, StreamWriter

    source = RtpDumpSource(pcap_file, udp_port=udp_port)
    stream = HLSStream(source, fragment_duration=2)  # 2s segments
    writer = StreamWriter(stream, output_dir)
    writer.start()

def main():
    parser = argparse.ArgumentParser(description='Decode RTP from PCAP')
    parser.add_argument('pcap', help='Path to the PCAP file')
    parser.add_argument('udp_port', type=int, help='UDP port where RTP is streaming')
    parser.add_argument('--mode', choices=['rtpdec', 'pylivestream'], default='rtpdec',
                        help='Which tool to use (default: rtpdec)')
    parser.add_argument('--payload', type=int, default=96,
                        help='RTP payload type (for rtpdec, default: 96)')
    parser.add_argument('--rate', type=int, default=90000,
                        help='Sample rate in Hz (for rtpdec, default: 90000)')
    parser.add_argument('--output', default='output.raw',
                        help='Output file or directory (default: output.raw)')
    args = parser.parse_args()

    if not os.path.exists(args.pcap):
        print(f"Error: PCAP file {args.pcap} not found.")
        sys.exit(1)

    if args.mode == 'rtpdec':
        decode_with_rtpdec(args.pcap, args.udp_port, args.payload, args.rate, args.output)
    else:
        # For pylivestream we interpret --output as a directory for HLS files
        decode_with_pylivestream(args.pcap, args.udp_port, args.output)

if __name__ == '__main__':
    main()
