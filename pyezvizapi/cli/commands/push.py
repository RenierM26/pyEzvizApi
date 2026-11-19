# Runtime hook context is explicit; immutable value types come from dependency leaves.
# ruff: noqa: SLF001
"push command handlers; cli.main passes the retained runtime hooks explicitly."

from __future__ import annotations

from types import ModuleType as _ModuleType
from typing import TYPE_CHECKING, Any

from pyezvizapi.cloud.login import verification_code

if TYPE_CHECKING:
    import pyezvizapi._typing.cli as _owner_types


def _handle_mqtt(
    args: _owner_types.argparse.Namespace, client: _owner_types.EzvizClient, *, _owner: _ModuleType
) -> int:
    """Migrate the login and listen with durable channel-99 token storage."""
    login_options: dict[str, Any] = {}
    if channel := getattr(args, "mfa_channel", None):
        login_options["mfa_channel"] = 1 if channel == "sms" else 3
    if account := getattr(args, "mfa_account", None):
        login_options["mfa_account"] = account
    try:
        client.enable_channel99(**login_options)
    except _owner.EzvizAuthVerificationCode as error:
        if error.code == 6002 and not error.code_sent:
            raise _owner.PyEzvizError(
                "No MFA code requested; select a bound --mfa-channel/--mfa-account "
                "or complete security verification in the EZVIZ app."
            ) from None
        code = input("MFA code required, please input MFA code.\n")
        sms_code = verification_code(code)
        client.enable_channel99(sms_code=sms_code, **login_options)
    mqtt = client.get_mqtt_client(on_message_callback=_owner._write_json)
    mqtt.connect()
    try:
        while True:
            mqtt.raise_if_failed()
            _owner.time.sleep(1)
    except KeyboardInterrupt:
        return 0
    finally:
        try:
            mqtt.stop()
        except TimeoutError as error:
            raise _owner.PyEzvizError(
                "Push shutdown timed out; cancellation remains signalled"
            ) from error
