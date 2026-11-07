"""Compatibility alias. Implementation: :mod:`pyezvizapi.cli.mqtt_listener`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.cli import mqtt_listener as _implementation

if TYPE_CHECKING:
    from pyezvizapi.cli.mqtt_listener import (
    Any as Any,
    EzvizAuthVerificationCode as EzvizAuthVerificationCode,
    EzvizClient as EzvizClient,
    LOG_FILE as LOG_FILE,
    Path as Path,
    PyEzvizError as PyEzvizError,
    _LOGGER as _LOGGER,
    _load_token_file as _load_token_file,
    _parse_args as _parse_args,
    _save_token_file as _save_token_file,
    annotations as annotations,
    argparse as argparse,
    cast as cast,
    getpass as getpass,
    json as json,
    logging as logging,
    main as main,
    message_handler as message_handler,
    save_private_token as save_private_token,
    sys as sys,
    time as time,
    )

if __name__ == "__main__":
    sys.exit(_implementation.main())
else:
    sys.modules[__name__] = _implementation
