import os
import csv
import sys
import shutil
from pathlib import Path
from typing import Optional
import argparse

# pyshark nutzt tshark im Hintergrund
try:
    import pyshark
except ImportError:
    print("ERROR: pyshark fehlt. Bitte zuerst installieren: pip install pyshark==0.6")
    sys.exit(1)

def ensure_tshark():
    exe = shutil.which("tshark") or shutil.which("tshark.exe")
    if not exe:
        print("ERROR: tshark nicht gefunden. Bitte Wireshark/Tshark installieren.")
        sys.exit(1)
    return exe

def safe_get(pkt, *path, default=""):
    """Robuste Feldabfrage in pyshark (gibt '' zurück, wenn Feld fehlt)."""
    cur = pkt
    try:
        for p in path:
            cur = getattr(cur, p)
        return str(cur)
    except Exception:
        return default

def bool_flag(pkt, layer, field):
    try:
        v = getattr(getattr(pkt, layer), field)
        s = str(v).lower()
        return s in ("1","true","yes")
    except Exception:
        return False

def extract_range(input_pcap: Path, start_no: int, end_no: int,
                  csv_packets: Path, csv_anoms: Path,
                  slice_out: Optional[Path]=None):
    # only_summaries=False, wir brauchen Layer-Felder
    cap = pyshark.FileCapture(
        str(input_pcap),
        use_json=True, include_raw=False,
        # Performance: nur TCP+OPCUA relevant
        display_filter="tcp || opcua"
    )

    # Vorbereitung CSVs
    pkt_fields = [
        "frame_no","rel_time","src","dst","srcport","dstport","proto","length",
        "tcp_stream","seq","ack","win","flags",
        "is_retx","is_ooo","is_ka","is_zerowin",
        "opcua_type","opcua_service","opcua_reqid","opcua_seq","opcua_chunk"
    ]
    anom_fields = [
        "frame_no","rel_time","tcp_stream","src","dst","anomaly"
    ]

    with csv_packets.open("w", newline="", encoding="utf-8") as f_pkt, \
         csv_anoms.open("w", newline="", encoding="utf-8") as f_anom:

        w_pkt = csv.DictWriter(f_pkt, fieldnames=pkt_fields)
        w_an  = csv.DictWriter(f_anom, fieldnames=anom_fields)
        w_pkt.writeheader()
        w_an.writeheader()

        for i, pkt in enumerate(cap, start=1):
            # Nur gewünschte Paketnummern übernehmen
            if i < start_no:
                continue
            if i > end_no:
                break

            # Basisfelder
            frame_no   = i
            rel_time   = safe_get(pkt, "sniff_time")  # exakte Zeit; alternativ frame_info.time_relative
            ip_src     = safe_get(pkt, "ip", "src") or safe_get(pkt, "ipv6", "src")
            ip_dst     = safe_get(pkt, "ip", "dst") or safe_get(pkt, "ipv6", "dst")
            srcport    = safe_get(pkt, "tcp", "srcport")
            dstport    = safe_get(pkt, "tcp", "dstport")
            length     = safe_get(pkt, "length")
            proto      = "TCP" if hasattr(pkt, "tcp") else ("OPCUA" if hasattr(pkt, "opcua") else safe_get(pkt, "highest_layer"))

            # TCP-Details
            tcp_stream = safe_get(pkt, "tcp", "stream")
            seq        = safe_get(pkt, "tcp", "seq")
            ack        = safe_get(pkt, "tcp", "ack")
            win        = safe_get(pkt, "tcp", "window_size_value") or safe_get(pkt, "tcp", "window_size")
            flags = "".join([
                "S" if bool_flag(pkt,"tcp","flags_syn") else "",
                "F" if bool_flag(pkt,"tcp","flags_fin") else "",
                "R" if bool_flag(pkt,"tcp","flags_reset") else "",
                "P" if bool_flag(pkt,"tcp","flags_push") else "",
                "A" if bool_flag(pkt,"tcp","flags_ack") else "",
                "U" if bool_flag(pkt,"tcp","flags_urg") else ""
            ])

            # Anomalie-Flags (Wireshark-Calculated Fields)
            is_retx    = safe_get(pkt, "tcp", "analysis_retransmission") != ""
            is_ooo     = safe_get(pkt, "tcp", "analysis_out_of_order") != ""
            is_ka      = safe_get(pkt, "tcp", "analysis_keep_alive") != ""
            is_zerowin = safe_get(pkt, "tcp", "analysis_zero_window") != ""

            # OPC UA-Felder (nur wenn OPC UA vorhanden)
            opcua_type    = ""
            opcua_service = ""
            opcua_reqid   = ""
            opcua_seq     = ""
            opcua_chunk   = ""

            if hasattr(pkt, "opcua"):
                opcua_type    = safe_get(pkt, "opcua", "messagetype") or safe_get(pkt,"opcua","msgtype")
                opcua_service = safe_get(pkt, "opcua", "servicename")
                opcua_reqid   = safe_get(pkt, "opcua", "requesthandle") or safe_get(pkt, "opcua", "requestid")
                opcua_seq     = safe_get(pkt, "opcua", "sequencenumber")
                opcua_chunk   = safe_get(pkt, "opcua", "chunktype")  # F, C, A

            w_pkt.writerow({
                "frame_no": frame_no,
                "rel_time": rel_time,
                "src": ip_src, "dst": ip_dst,
                "srcport": srcport, "dstport": dstport,
                "proto": proto, "length": length,
                "tcp_stream": tcp_stream, "seq": seq, "ack": ack, "win": win, "flags": flags,
                "is_retx": int(bool(is_retx)), "is_ooo": int(bool(is_ooo)),
                "is_ka": int(bool(is_ka)), "is_zerowin": int(bool(is_zerowin)),
                "opcua_type": opcua_type, "opcua_service": opcua_service,
                "opcua_reqid": opcua_reqid, "opcua_seq": opcua_seq, "opcua_chunk": opcua_chunk
            })

            # Separate Anomalie-Tabelle
            if is_retx:
                w_an.writerow({"frame_no": frame_no, "rel_time": rel_time, "tcp_stream": tcp_stream,
                               "src": ip_src, "dst": ip_dst, "anomaly": "tcp.retransmission"})
            if is_ooo:
                w_an.writerow({"frame_no": frame_no, "rel_time": rel_time, "tcp_stream": tcp_stream,
                               "src": ip_src, "dst": ip_dst, "anomaly": "tcp.out_of_order"})
            if is_zerowin:
                w_an.writerow({"frame_no": frame_no, "rel_time": rel_time, "tcp_stream": tcp_stream,
                               "src": ip_src, "dst": ip_dst, "anomaly": "tcp.zero_window"})
            if is_ka:
                w_an.writerow({"frame_no": frame_no, "rel_time": rel_time, "tcp_stream": tcp_stream,
                               "src": ip_src, "dst": ip_dst, "anomaly": "tcp.keep_alive"})

    # Optional: echten PCAP-Slice via editcap/tshark erzeugen (nur diesen Paketbereich)
    if slice_out:
        # Wir nutzen tshark mit Display-Filter auf frame.number
        tshark = ensure_tshark()
        # Hinweis: frame.number ist ein String-Vergleich in älteren Versionen – wir hacken das als Bereichsliste
        # und filtern dann nochmal, um exakt den Range zu bekommen.
        # Einfacher: exportiere alles und schneide im Nachgang mit frame.number check – aber hier direkt:
        print("Erzeuge PCAP-Slice, bitte warten ...")
        # -Y 'frame.number >= start && frame.number <= end'
        import subprocess
        df = f"frame.number >= {start_no} && frame.number <= {end_no}"
        cmd = [tshark, "-r", str(input_pcap), "-Y", df, "-w", str(slice_out)]
        subprocess.run(cmd, check=True)

def main():
    parser = argparse.ArgumentParser(description="Bereite OPC UA PCAP-Range als CSVs auf.")
    parser.add_argument("pcap", type=str, help="Pfad zur .pcapng-Datei")
    parser.add_argument("--start", type=int, default=0, help="Start-Paketnummer (inkl.)")
    parser.add_argument("--end", type=int, default=1024, help="End-Paketnummer (inkl.)")
    parser.add_argument("--outdir", type=str, default="opcua_export", help="Ausgabeverzeichnis")
    parser.add_argument("--slice", action="store_true", help="Zusätzlich einen PCAP-Slice schreiben")
    args = parser.parse_args()

    # If the path is not absolute, resolve it relative to the script's directory
    pcap_arg = Path(args.pcap).expanduser()
    if not pcap_arg.is_absolute():
        script_dir = Path(__file__).parent.resolve()
        pcap = (script_dir / pcap_arg).resolve()
    else:
        pcap = pcap_arg.resolve()
    # Ensure output directory is within the script's directory
    outdir_arg = Path(args.outdir)
    script_dir = Path(__file__).parent.resolve()
    if not outdir_arg.is_absolute():
        outdir = (script_dir / outdir_arg).resolve()
    else:
        outdir = outdir_arg.resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    csv_packets = outdir / f"opcua_packets_{args.start}_{args.end}.csv"
    csv_anoms   = outdir / f"tcp_anomalies_{args.start}_{args.end}.csv"
    slice_out   = (outdir / f"slice_{args.start}_{args.end}.pcapng") if args.slice else None

    extract_range(pcap, args.start, args.end, csv_packets, csv_anoms, slice_out)
    print("\nFertig!")
    print(f"- Pakete:   {csv_packets}")
    print(f"- Anomalien:{csv_anoms}")
    if slice_out:
        print(f"- Slice:    {slice_out}")

if __name__ == "__main__":
    main()
