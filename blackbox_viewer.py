import argparse
import configparser
import getpass
from pathlib import Path

from chain_of_custody import decrypt_logs_to_text, program_data_root


def main() -> None:
    parser = argparse.ArgumentParser(description="Black Box chain of custody viewer")
    parser.add_argument("--decrypt", action="store_true", help="Decrypt logs to plain text")
    parser.add_argument("--output", type=str, default=str(program_data_root() / "logs" / "report.txt"))
    args = parser.parse_args()
    if not args.decrypt:
        parser.error("Specify --decrypt")
    cfg_path = program_data_root() / "config.ini"
    cfg = configparser.ConfigParser()
    cfg.read([str(cfg_path)], encoding="utf-8")
    wrap = cfg.get("ChainOfCustody", "static_wrap_password", fallback="BlackBoxSupervisor2026!")
    pw = getpass.getpass("Master password: ")
    decrypt_logs_to_text(pw, wrap, Path(args.output))
    print(f"Wrote decrypted chronological log to: {args.output}")


if __name__ == "__main__":
    main()
