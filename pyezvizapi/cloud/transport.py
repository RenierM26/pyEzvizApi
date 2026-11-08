"""Copy request state while borrowing caller-owned transport adapters."""

from collections import OrderedDict
from copy import copy, deepcopy

import requests
from requests.structures import CaseInsensitiveDict


def isolated_session(source: requests.Session) -> requests.Session:
    """Copy request state, borrowing transport adapters owned by the caller.

    No transport pools are created here. Do not close this copy: adapter/pool
    lifetime remains with the supplied session, including custom TLS adapters.
    """
    session = copy(source)
    session.headers = CaseInsensitiveDict(source.headers)
    session.cookies = source.cookies.copy()
    session.params = deepcopy(source.params)
    session.proxies = dict(source.proxies)
    session.hooks = {name: list(hooks) for name, hooks in source.hooks.items()}
    session.adapters = OrderedDict(source.adapters)
    return session
