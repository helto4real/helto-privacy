"""Command-line administration for the Helto privacy keystore."""

from __future__ import annotations

import argparse
import getpass
import sys

from . import keystore
from .keystore import PrivacyKeystoreError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="helto-privacy")
    commands = parser.add_subparsers(dest="command", required=True)
    yubikey = commands.add_parser("yubikey", help="Manage YubiKey FIDO2 unlock")
    yubikey_commands = yubikey.add_subparsers(dest="yubikey_command", required=True)
    enroll = yubikey_commands.add_parser(
        "enroll",
        help="Create or convert a keystore using a protected FIDO2 credential",
    )
    enroll.add_argument(
        "--device",
        help="Select a non-secret FIDO HID device path such as /dev/hidraw2",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "yubikey" and args.yubikey_command == "enroll":
        return _enroll_yubikey(args.device)
    return 2


def _enroll_yubikey(device_path: str | None) -> int:
    try:
        method = keystore.keystore_unlock_method()
        if method == keystore.AUTH_YUBIKEY_FIDO2:
            raise PrivacyKeystoreError(
                f"{keystore.ERROR_AUTH_METHOD_INVALID}: Privacy keystore already uses a YubiKey."
            )
        current_password = None
        if method == keystore.AUTH_PASSWORD:
            current_password = getpass.getpass("Current privacy password: ")
        pin = getpass.getpass("YubiKey FIDO2 PIN: ")
        print("Touch the YubiKey when it flashes; enrollment requires two touches.")
        result = keystore.enroll_yubikey_keystore(
            pin=pin,
            current_password=current_password,
            device_path=device_path,
        )
    except (PrivacyKeystoreError, KeyboardInterrupt, EOFError) as exc:
        if isinstance(exc, KeyboardInterrupt):
            print("Enrollment cancelled.", file=sys.stderr)
        elif isinstance(exc, EOFError):
            print("Enrollment cancelled: no credential input was available.", file=sys.stderr)
        else:
            print(str(exc), file=sys.stderr)
        return 1

    print(
        "YubiKey FIDO2 enrollment complete."
    )
    print("The privacy password is no longer an unlock method for this keystore.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
