"""Shows, side by side, what a log contains and what the model sees of it.

Demonstration aid: illustrates that internal identifiers (hosts, accounts, private IPs)
are replaced by stable pseudonyms before any send to the model, and that the mapping
stays in the platform to rehydrate the report. No network call.

    .venv/bin/python scripts/demo_tokenization.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from middleware.config import Settings  # noqa: E402
from middleware.minimization import mask_row  # noqa: E402
from middleware.tokenization import TokenVault  # noqa: E402

_ROWS = [
    {
        "Computer": "PAR-FS-03.corp.internal",
        "Account": "svc-backup",
        "ProcessCommandLine": (
            'wmic /node:PAR-DC-01.corp.internal process call create "cmd /c netstat -ano"'
        ),
        "RemoteIP": "10.42.8.11",
    },
    {
        "Computer": "PAR-FS-03.corp.internal",
        "Account": "svc-backup",
        "ProcessCommandLine": "netsh interface portproxy add v4tov4 connectaddress=45.155.12.7",
        "RemoteIP": "10.42.8.11",
    },
]


def main() -> None:
    settings = Settings(_env_file=None, internal_hostname_suffixes="corp.internal")
    vault = TokenVault(internal_suffixes=settings.internal_hostname_suffixes)

    print("Tokenization of internal identifiers before sending to the model\n")
    print("Each row: first the real log, then what the model receives.\n")

    for index, row in enumerate(_ROWS, start=1):
        masked = mask_row(row, settings.masking, tokenization=settings.tokenization, vault=vault)
        print(f"--- Row {index} " + "-" * 52)
        for key in row:
            real = str(row[key])
            seen = str(masked.get(key, "(field removed)"))
            mark = "" if real == seen else "   <= tokenized"
            print(f"  {key}")
            print(f"    real log    : {real}")
            print(f"    model sees  : {seen}{mark}")
        print()

    print("Mapping kept in the platform (used to rehydrate the report):")
    for token, value in sorted(vault._by_token.items()):
        print(f"  {token:12} -> {value}")
    print("\nThe public IP 45.155.12.7 is not tokenized: it is an IOC, the model needs it.")
    print("Internal identifiers, however, never leave the platform.")


if __name__ == "__main__":
    main()
