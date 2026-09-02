"""Creates or updates a local platform account.

Used to bootstrap the first admin account; afterwards, accounts are managed from the
Configuration screen. The password is prompted at the keyboard, never passed as an argument
(it would end up in the shell history).

Usage:
    .venv/bin/python scripts/create_account.py j.doe --roles analyst,admin
    .venv/bin/python scripts/create_account.py j.doe --update   # new password
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from api.accounts import ALLOWED_ROLES, MIN_PASSWORD_LENGTH, AccountRepository  # noqa: E402
from middleware.config import Settings  # noqa: E402
from storage.repository import Database  # noqa: E402


def _ask_password() -> str:
    password = getpass.getpass("Password: ")
    if len(password) < MIN_PASSWORD_LENGTH:
        sys.exit(f"The password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if getpass.getpass("Confirmation: ") != password:
        sys.exit("The two entries do not match.")
    return password


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("username", help="account identifier (e.g. firstname.lastname)")
    parser.add_argument(
        "--roles",
        default="analyst",
        help="comma-separated roles: analyst, reader, admin",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="update the password of an existing account",
    )
    args = parser.parse_args()

    roles = [role.strip() for role in args.roles.split(",") if role.strip()]
    unknown = set(roles) - ALLOWED_ROLES
    if unknown:
        sys.exit(f"Unknown roles: {', '.join(sorted(unknown))}")

    settings = Settings()
    database = Database(settings.database_url)
    await database.create_all()
    accounts = AccountRepository(database)

    password = _ask_password()
    if args.update:
        if not await accounts.set_password(args.username, password):
            sys.exit(f"The account {args.username} does not exist.")
        print(f"Password updated for {args.username}.")
    else:
        try:
            await accounts.create(
                username=args.username,
                password=password,
                roles=roles,
                created_by="script:create_account",
            )
        except ValueError as error:
            sys.exit(f"{error} Use --update to change the password.")
        print(f"Account {args.username} created with roles: {', '.join(sorted(roles))}.")

    await database.dispose()


if __name__ == "__main__":
    asyncio.run(main())
