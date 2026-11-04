"""recovery.notify_on_change: tell the account owner about security changes (via Mailpit)."""
from . import mailer
from .security import flags


def security_change(email: str, what: str) -> None:
    if not flags.enabled("recovery.notify_on_change"):
        return
    mailer.send(
        email,
        f"Account Lab security notice: {what}",
        f"{what} on your Account Lab account.\n\n"
        "If this wasn't you, your account may be compromised. (This is a lab notification.)\n",
    )
