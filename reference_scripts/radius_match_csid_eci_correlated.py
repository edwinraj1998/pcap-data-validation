#!/usr/bin/env python3
r"""
Match Calling-Station-Id (RADIUS attr 31) and ECI (gtpv2.ecgi_eci) across PCAP/PCAPNG files,
with options to:
  * Require the tuple to be present in ALL files (--require-in-all), or at least N files (--min-files)
  * Correlate CSID and ECI even when they appear in DIFFERENT FRAMES using a chosen key:
      --correlate-by imsi | msisdn | time
    and optional --time-window-seconds (default: 0, i.e., no time constraint)

This script uses PyShark/TShark to read dissector fields.
It writes a CSV summary listing matched (CSID, ECI) tuples and the frames that produced them.

Default input directory:
  C:\\Users\\edwin.rajan\\OneDrive - ClearTrail\\Desktop\\Mobily_test_PCAP

Prerequisites:
  - Wireshark/TShark installed and in PATH (tshark.exe)
  - pip install pyshark

Usage examples (PowerShell):
  # Minimal: match CSID & ECI per file
  python .\\radius_match_csid_eci_correlated.py --min-files 1 --verbose

  # Correlate by IMSI, allow pairs when IMSI matches (no time constraint)
  python .\\radius_match_csid_eci_correlated.py --correlate-by imsi --min-files 1 --verbose

  # Correlate by MSISDN within 30s window
  python .\\radius_match_csid_eci_correlated.py --correlate-by msisdn --time-window-seconds 30 --min-files 1 --verbose

  # Require the (CSID, ECI) tuple to be present in ALL files
  python .\\radius_match_csid_eci_correlated.py --require-in-all --correlate-by imsi --time-window-seconds 30 --verbose
"""

import argparse
import os
import sys
from collections import defaultdict
from datetime import datetime

DEFAULT_PCAP_DIR = r"C:\\Users\\edwin.rajan\\OneDrive - ClearTrail\\Desktop\\Mobily_test_PCAP"

# ---------------------------
# Utilities
# ---------------------------

def list_pcap_files(root_dir):
    exts = {".pcap", ".pcapng"}
    try:
        items = os.listdir(root_dir)
    except Exception as e:
        print(f"[ERROR] Unable to list directory: {root_dir} -> {e}")
        sys.exit(2)
    files = []
    for n in items:
        p = os.path.join(root_dir, n)
        if os.path.isfile(p) and os.path.splitext(n)[1].lower() in exts:
            files.append(p)
    return sorted(files)


def pyshark_available():
    try:
        import pyshark  # noqa: F401
        return True
    except Exception:
        return False


def normalize_digits(s):
    if not s:
        return None
    return "".join(ch for ch in str(s) if ch.isdigit()) or None

# ---------------------------
# Extraction using PyShark/TShark
# ---------------------------

def extract_radius_rows(pcap_path, ports):
    """Extract RADIUS frames providing CSID and potential correlation hints (User-Name).
    Returns: list of dicts with keys: file, packet_index, time_epoch, csid, src_ip, dst_ip,
             radius_code, radius_id, username_digits (optional)
    """
    import pyshark
    port_clause = " || ".join([f"udp.port=={p}" for p in ports])
    disp_filter = f"({port_clause}) && radius"

    cap = pyshark.FileCapture(
        pcap_path,
        display_filter=disp_filter,
        keep_packets=False,
        use_json=True,
    )

    rows = []
    try:
        for pkt in cap:
            try:
                # Frame/time
                frame_time_epoch = None
                pkt_index = None
                if hasattr(pkt, "frame"):
                    fr = pkt.frame
                    if hasattr(fr, "frame_time_epoch"):
                        try:
                            frame_time_epoch = float(fr.frame_time_epoch)
                        except Exception:
                            frame_time_epoch = None
                    if hasattr(fr, "frame_number"):
                        try:
                            pkt_index = int(fr.frame_number)
                        except Exception:
                            pkt_index = None

                # IPs
                src_ip = dst_ip = None
                if hasattr(pkt, "ip"):
                    src_ip = getattr(pkt.ip, "src", None)
                    dst_ip = getattr(pkt.ip, "dst", None)
                elif hasattr(pkt, "ipv6"):
                    src_ip = getattr(pkt.ipv6, "src", None)
                    dst_ip = getattr(pkt.ipv6, "dst", None)

                # RADIUS
                radius_layer = getattr(pkt, "radius", None)
                csid = None
                rcode = None
                rid = None
                username = None
                if radius_layer is not None:
                    csid = getattr(radius_layer, "calling_station_id", None) or getattr(radius_layer, "Calling_Station_Id", None)
                    rcode = getattr(radius_layer, "code", None)
                    rid = getattr(radius_layer, "id", None)
                    username = getattr(radius_layer, "user_name", None) or getattr(radius_layer, "User_Name", None)

                # Candidate correlation digits from CSID or User-Name
                username_digits = normalize_digits(username)

                if not csid:
                    continue

                rows.append({
                    "file": pcap_path,
                    "packet_index": pkt_index,
                    "time_epoch": frame_time_epoch,
                    "csid": csid,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "radius_code": rcode,
                    "radius_id": rid,
                    "username_digits": username_digits,
                })
            except Exception:
                continue
    finally:
        cap.close()

    return rows


def extract_gtpv2_rows(pcap_path):
    """Extract GTPv2 frames providing ECI and correlation keys (IMSI/MSISDN/TEID).
    Returns: list of dicts with keys: file, packet_index, time_epoch, eci, imsi, msisdn, teid, src_ip, dst_ip
    """
    import pyshark
    # We want control-plane GTPv2, and extract ECGI/ECI if present, but also correlation keys even when ECI is absent
    disp_filter = "gtpv2"

    cap = pyshark.FileCapture(
        pcap_path,
        display_filter=disp_filter,
        keep_packets=False,
        use_json=True,
    )

    rows = []
    try:
        for pkt in cap:
            try:
                # Frame/time
                frame_time_epoch = None
                pkt_index = None
                if hasattr(pkt, "frame"):
                    fr = pkt.frame
                    if hasattr(fr, "frame_time_epoch"):
                        try:
                            frame_time_epoch = float(fr.frame_time_epoch)
                        except Exception:
                            frame_time_epoch = None
                    if hasattr(fr, "frame_number"):
                        try:
                            pkt_index = int(fr.frame_number)
                        except Exception:
                            pkt_index = None

                # IPs
                src_ip = dst_ip = None
                if hasattr(pkt, "ip"):
                    src_ip = getattr(pkt.ip, "src", None)
                    dst_ip = getattr(pkt.ip, "dst", None)
                elif hasattr(pkt, "ipv6"):
                    src_ip = getattr(pkt.ipv6, "src", None)
                    dst_ip = getattr(pkt.ipv6, "dst", None)

                # GTPv2 fields
                gtpv2 = getattr(pkt, "gtpv2", None)
                eci = None
                imsi = None
                msisdn = None
                teid = None
                if gtpv2 is not None:
                    # ECI candidates
                    for candidate in ("ecgi_eci", "ecgi_eci_field", "ecgi_eci_value", "ecgi_eci_"):
                        eci = getattr(gtpv2, candidate, None)
                        if eci:
                            break
                    if not eci:
                        for fld in ("gtpv2.ecgi_eci", "gtpv2.ecgi.eci"):
                            try:
                                eci = pkt.get_field_value(fld)
                                if eci:
                                    break
                            except Exception:
                                pass
                    # IMSI candidates
                    imsi = (getattr(gtpv2, "imsi", None) or
                            getattr(pkt, "e212", None) and getattr(pkt.e212, "imsi", None) or
                            getattr(pkt, "nas_eps", None) and getattr(pkt.nas_eps, "imsi", None))
                    # MSISDN candidates
                    msisdn = (getattr(gtpv2, "msisdn", None) or
                              getattr(pkt, "e212", None) and getattr(pkt.e212, "msisdn", None))
                    # TEID candidates (varies by IE and version)
                    teid = (getattr(gtpv2, "teid", None) or
                            getattr(pkt, "gtp", None) and getattr(pkt.gtp, "teid", None))

                rows.append({
                    "file": pcap_path,
                    "packet_index": pkt_index,
                    "time_epoch": frame_time_epoch,
                    "eci": eci,
                    "imsi": normalize_digits(imsi),
                    "msisdn": normalize_digits(msisdn),
                    "teid": normalize_digits(teid),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                })
            except Exception:
                continue
    finally:
        cap.close()

    return rows

# ---------------------------
# Correlation logic (per file)
# ---------------------------

def correlate_per_file(radius_rows, gtp_rows, correlate_by, time_window_sec):
    """Return a list of correlated tuples within one file.
    Each item: { 'file', 'csid', 'eci', 'radius_packet_index', 'gtp_packet_index', 'timestamp_radius', 'timestamp_gtp' }

    Strategy:
      - If correlate_by == 'imsi': match radius username_digits with gtp IMSI; if time_window_sec>0, require |t1-t2|<=window
      - If correlate_by == 'msisdn': match radius username_digits or csid digits with gtp MSISDN; time window optional
      - If correlate_by == 'time': pair nearest-in-time events (no key) within window; if window==0, pair by identical timestamp only

    Note: RADIUS seldom carries TEID; thus 'teid' is not supported here.
    """
    results = []
    # Build indexes
    if correlate_by == 'imsi':
        # map IMSI -> list of gtp rows
        gtp_by_imsi = defaultdict(list)
        for g in gtp_rows:
            if g.get('imsi'):
                gtp_by_imsi[g['imsi']].append(g)
        for r in radius_rows:
            imsi_candidate = r.get('username_digits')  # often IMSI in User-Name for mobile RADIUS
            if not imsi_candidate:
                continue
            if imsi_candidate in gtp_by_imsi:
                for g in gtp_by_imsi[imsi_candidate]:
                    t1 = r.get('time_epoch')
                    t2 = g.get('time_epoch')
                    if time_window_sec and (t1 is None or t2 is None or abs(t1 - t2) > time_window_sec):
                        continue
                    results.append({
                        'file': r['file'],
                        'csid': r['csid'],
                        'eci': g.get('eci'),
                        'radius_packet_index': r.get('packet_index'),
                        'gtp_packet_index': g.get('packet_index'),
                        'timestamp_radius': t1,
                        'timestamp_gtp': t2,
                    })
    elif correlate_by == 'msisdn':
        gtp_by_msisdn = defaultdict(list)
        for g in gtp_rows:
            if g.get('msisdn'):
                gtp_by_msisdn[g['msisdn']].append(g)
        for r in radius_rows:
            # Calling-Station-Id often carries MSISDN; else try User-Name digits
            msisdn_candidate = normalize_digits(r.get('csid')) or r.get('username_digits')
            if not msisdn_candidate:
                continue
            if msisdn_candidate in gtp_by_msisdn:
                for g in gtp_by_msisdn[msisdn_candidate]:
                    t1 = r.get('time_epoch')
                    t2 = g.get('time_epoch')
                    if time_window_sec and (t1 is None or t2 is None or abs(t1 - t2) > time_window_sec):
                        continue
                    results.append({
                        'file': r['file'],
                        'csid': r['csid'],
                        'eci': g.get('eci'),
                        'radius_packet_index': r.get('packet_index'),
                        'gtp_packet_index': g.get('packet_index'),
                        'timestamp_radius': t1,
                        'timestamp_gtp': t2,
                    })
    else:  # time-only correlation
        if time_window_sec == 0:
            # pair frames with identical epoch (rare but deterministic)
            gtp_by_time = defaultdict(list)
            for g in gtp_rows:
                t = g.get('time_epoch')
                if t is not None:
                    gtp_by_time[t].append(g)
            for r in radius_rows:
                t = r.get('time_epoch')
                if t is None:
                    continue
                if t in gtp_by_time:
                    for g in gtp_by_time[t]:
                        results.append({
                            'file': r['file'], 'csid': r['csid'], 'eci': g.get('eci'),
                            'radius_packet_index': r.get('packet_index'), 'gtp_packet_index': g.get('packet_index'),
                            'timestamp_radius': t, 'timestamp_gtp': t,
                        })
        else:
            # sliding window pairing: for each radius row, pair any gtp rows within +/- window
            # (could produce multiple pairs per row)
            gtp_sorted = sorted([g for g in gtp_rows if g.get('time_epoch') is not None], key=lambda x: x['time_epoch'])
            for r in radius_rows:
                t1 = r.get('time_epoch')
                if t1 is None:
                    continue
                for g in gtp_sorted:
                    t2 = g.get('time_epoch')
                    if t2 is None:
                        continue
                    if abs(t1 - t2) <= time_window_sec:
                        results.append({
                            'file': r['file'], 'csid': r['csid'], 'eci': g.get('eci'),
                            'radius_packet_index': r.get('packet_index'), 'gtp_packet_index': g.get('packet_index'),
                            'timestamp_radius': t1, 'timestamp_gtp': t2,
                        })
    # Filter out pairs missing ECI
    results = [x for x in results if x.get('eci')]
    return results

# ---------------------------
# Aggregation across files
# ---------------------------

def main():
    parser = argparse.ArgumentParser(description="Correlate CSID (RADIUS) and ECI (GTPv2) across files; support require-in-all and correlation keys.")
    parser.add_argument("--pcap-dir", default=DEFAULT_PCAP_DIR, help="Directory with .pcap/.pcapng files")
    parser.add_argument("--out-csv", default=None, help="Output CSV path (default: <pcap-dir>\\csid_eci_correlated.csv)")
    parser.add_argument("--min-files", type=int, default=1, help="Tuple must appear in >= this many DISTINCT files (default: 1)")
    parser.add_argument("--require-in-all", action="store_true", help="Require tuple to be present in ALL files (overrides --min-files)")
    parser.add_argument("--ports", nargs="*", type=int, default=[1812, 1813, 1645, 1646], help="UDP ports considered for RADIUS")
    parser.add_argument("--correlate-by", choices=["imsi", "msisdn", "time"], default="time", help="Key used to correlate CSID & ECI between frames")
    parser.add_argument("--time-window-seconds", type=int, default=0, help="Window for time-based or key+time correlation (default: 0)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    pcap_dir = args.pcap_dir
    out_csv = args.out_csv or os.path.join(pcap_dir, "csid_eci_correlated.csv")

    if not pyshark_available():
        print("[ERROR] PyShark is required. Install via: pip install pyshark")
        print("Also ensure Tshark (Wireshark) is installed and in PATH.")
        sys.exit(1)

    files = list_pcap_files(pcap_dir)
    if not files:
        print(f"[ERROR] No .pcap/.pcapng files found in: {pcap_dir}")
        sys.exit(3)

    if args.verbose:
        print(f"[INFO] Scanning {len(files)} file(s) under: {pcap_dir}")

    # Collect correlations per file
    per_file_correlated = defaultdict(list)

    for f in files:
        if args.verbose:
            print(f"[INFO] Extracting RADIUS rows from {f}")
        radius_rows = extract_radius_rows(f, set(args.ports))
        if args.verbose:
            print(f"[INFO] Extracting GTPv2 rows from {f}")
        gtp_rows = extract_gtpv2_rows(f)
        if args.verbose:
            print(f"[INFO] Correlating in {f}: {len(radius_rows)} RADIUS rows, {len(gtp_rows)} GTPv2 rows")
        correlated = correlate_per_file(radius_rows, gtp_rows, args.correlate_by, args.time_window_seconds)
        per_file_correlated[f] = correlated
        if args.verbose:
            print(f"[INFO] Found {len(correlated)} CSID-ECI pairs in {f}")

    # Build buckets by key across files: key = (csid, eci)
    buckets = defaultdict(list)
    for f, rows in per_file_correlated.items():
        for r in rows:
            key = (r['csid'], r['eci'])
            buckets[key].append(r)

    # Determine which keys qualify
    matched_keys = []
    if args.require_in_all:
        file_set = set(files)
        for k, rs in buckets.items():
            files_with_key = {r['file'] for r in rs}
            if files_with_key == file_set:
                matched_keys.append(k)
    else:
        for k, rs in buckets.items():
            distinct_files = {r['file'] for r in rs}
            if len(distinct_files) >= args.min_files:
                matched_keys.append(k)

    # Write CSV
    import csv
    try:
        with open(out_csv, "w", newline="", encoding="utf-8") as fw:
            w = csv.writer(fw)
            w.writerow(["file", "radius_packet_index", "gtp_packet_index", "timestamp_radius", "timestamp_gtp", "calling_station_id", "eci", "src_ip_radius", "dst_ip_radius", "radius_code", "radius_id"])
            if matched_keys:
                matched_set = set(matched_keys)
                for k, rs in buckets.items():
                    if k not in matched_set:
                        continue
                    for r in rs:
                        ts_r = r.get('timestamp_radius')
                        ts_g = r.get('timestamp_gtp')
                        ts_r_iso = ''
                        ts_g_iso = ''
                        if ts_r is not None:
                            try:
                                ts_r_iso = datetime.utcfromtimestamp(ts_r).isoformat() + 'Z'
                            except Exception:
                                ts_r_iso = str(ts_r)
                        if ts_g is not None:
                            try:
                                ts_g_iso = datetime.utcfromtimestamp(ts_g).isoformat() + 'Z'
                            except Exception:
                                ts_g_iso = str(ts_g)
                        w.writerow([
                            r['file'], r.get('radius_packet_index', ''), r.get('gtp_packet_index', ''), ts_r_iso, ts_g_iso,
                            r['csid'], r['eci'], '', '', '', ''  # src/dst & radius code/id could be added with more plumbing
                        ])
    except Exception as e:
        print(f"[WARN] Could not write CSV {out_csv}: {e}")
        sys.exit(4)

    if matched_keys:
        print(f"[DONE] Wrote {len(matched_keys)} unique (CSID, ECI) tuple(s) to: {out_csv}")
    else:
        print("[INFO] No (CSID, ECI) tuples across the requested file criteria.")
        print(f"[INFO] Wrote CSV header: {out_csv}")
        print("[HINT] Try relaxing criteria, e.g., --min-files 1 or using --correlate-by msisdn and setting --time-window-seconds 30")

if __name__ == "__main__":
    main()
