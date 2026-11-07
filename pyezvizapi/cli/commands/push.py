# Runtime hooks deliberately resolve through their legacy owner.
# ruff: noqa: SLF001

"""push command handlers; legacy hooks resolve through cli.main."""
from __future__ import annotations

import pyezvizapi.cli.main as _owner


def _handle_mqtt(args: _owner.argparse.Namespace, client: _owner.EzvizClient) -> int:
    """Migrate the login and listen with durable channel-99 token storage."""
    try:
        client.enable_channel99()
    except _owner.EzvizAuthVerificationCode:
        code = input('MFA code required, please input MFA code.\n')
        try:
            sms_code = int(code.strip())
        except ValueError as err:
            raise _owner.PyEzvizError('MFA code must be numeric') from err
        client.enable_channel99(sms_code=sms_code)
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
            raise _owner.PyEzvizError('Push shutdown timed out; cancellation remains signalled') from error
