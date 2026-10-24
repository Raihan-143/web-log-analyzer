"""
main.py
CLI entry point for the Automated Web Log Forensic & Threat Analyzer.
"""

import argparse
import json
import sys
from pathlib import Path
from core.parser import LogParser
from core.detector import ThreatDetector
from utils.logger import ConsoleLogger


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Automated Web Log Forensic & Threat Analyzer"
    )
    parser.add_argument(
        "-f", "--file",
        dest="log_file",
        required=True,
        help="Path to Nginx/Apache access.log file"
    )
    parser.add_argument(
        "-t", "--threshold",
        dest="threshold",
        type=int,
        default=5,
        help="Brute force failed attempts threshold (Default: 5)"
    )
    parser.add_argument(
        "-o", "--output",
        dest="output_file",
        default=None,
        help="Optional path to export findings as JSON report"
    )

    args = parser.parse_args()
    log_path = Path(args.log_file).resolve()

    if not log_path.exists():
        ConsoleLogger.failure(f"Log file not found: {log_path}")
        sys.exit(1)

    ConsoleLogger.header("Web Log Forensic & Threat Analyzer Engine")
    ConsoleLogger.info(f"Target Log File : {log_path}")
    ConsoleLogger.info(f"Brute Force Limit: {args.threshold} attempts")

    detector = ThreatDetector(brute_force_threshold=args.threshold)
    total_lines = 0
    parsed_lines = 0
    all_threats = []

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            total_lines += 1
            entry = LogParser.parse_line(line)
            if entry:
                parsed_lines += 1
                threats = detector.evaluate_entry(entry)
                for threat in threats:
                    all_threats.append(threat)
                    ConsoleLogger.failure(
                        f"[{threat['attack_type']}] Attacker IP: {threat['target_ip']} | "
                        f"Status: {threat['status']} | URI: {threat['url']}"
                    )

    # Brute force evaluation
    brute_force_events = detector.get_brute_force_alerts()
    for bf in brute_force_events:
        all_threats.append(bf)
        ConsoleLogger.failure(
            f"[{bf['attack_type']}] Attacker IP: {bf['target_ip']} | "
            f"Failures: {bf['failure_count']} | Endpoint: {bf['endpoint']}"
        )

    # Forensic Summary telemetry
    print()
    ConsoleLogger.info("Forensic Analysis Summary:")
    ConsoleLogger.info(f"Total Lines Processed : {total_lines}")
    ConsoleLogger.info(f"Successfully Parsed   : {parsed_lines}")
    
    if all_threats:
        ConsoleLogger.warning(f"Total Threat Incidents Flagged: {len(all_threats)}")
    else:
        ConsoleLogger.success("Zero Threat Signatures Detected. Clean Baseline Log.")

    # Export structured JSON report
    if args.output_file:
        report = {
            "logfile": str(log_path),
            "total_lines": total_lines,
            "threats_count": len(all_threats),
            "incidents": all_threats
        }
        try:
            with open(args.output_file, "w", encoding="utf-8") as out:
                json.dump(report, out, indent=4)
            ConsoleLogger.success(f"Forensic report written to: {args.output_file}")
        except OSError as err:
            ConsoleLogger.failure(f"Failed to export report: {err}")


if __name__ == "__main__":
    main()