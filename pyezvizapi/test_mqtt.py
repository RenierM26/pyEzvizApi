# Compatibility export assignments include retained private attributes.
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.cli.mqtt_listener`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.cli import mqtt_listener as _implementation

if TYPE_CHECKING:
    import pyezvizapi.cli.mqtt_listener as _compat_module_0
    _LOGGER = _compat_module_0._LOGGER
    LOG_FILE = _compat_module_0.LOG_FILE
    Any = _compat_module_0.Any
    EzvizAuthVerificationCode = _compat_module_0.EzvizAuthVerificationCode
    EzvizClient = _compat_module_0.EzvizClient
    Path = _compat_module_0.Path
    PyEzvizError = _compat_module_0.PyEzvizError
    _load_token_file = _compat_module_0._load_token_file
    _parse_args = _compat_module_0._parse_args
    _save_token_file = _compat_module_0._save_token_file
    annotations = _compat_module_0.annotations
    argparse = _compat_module_0.argparse
    cast = _compat_module_0.cast
    getpass = _compat_module_0.getpass
    json = _compat_module_0.json
    logging = _compat_module_0.logging
    main = _compat_module_0.main
    message_handler = _compat_module_0.message_handler
    save_private_token = _compat_module_0.save_private_token
    sys = _compat_module_0.sys
    time = _compat_module_0.time

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        _LOGGER,
        LOG_FILE,
        Any,
        EzvizAuthVerificationCode,
        EzvizClient,
        Path,
        PyEzvizError,
        _load_token_file,
        _parse_args,
        _save_token_file,
        annotations,
        argparse,
        cast,
        getpass,
        json,
        logging,
        main,
        message_handler,
        save_private_token,
        sys,
        time,
    )

if __name__ == "__main__":
    sys.exit(_implementation.main())
else:
    sys.modules[__name__] = _implementation
