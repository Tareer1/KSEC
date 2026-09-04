"""CLI: ``ksec env`` — environment fingerprint."""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit
from ksec.kali.environment import fingerprint_environment


def cmd_env(ctx: KsecContext, args) -> int:
    emit(fingerprint_environment().to_dict(), args.json, args.quiet)
    return 0