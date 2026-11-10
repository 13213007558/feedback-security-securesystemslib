"""Isolated dispatch registry for Signer and Key implementations"""

from __future__ import annotations

import contextvars
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from securesystemslib.signer._key import Key
    from securesystemslib.signer._signer import SecretsHandler, Signer

CURRENT_REGISTRY: contextvars.ContextVar[SignerRegistry | None] = (
    contextvars.ContextVar("securesystemslib_signer_registry", default=None)
)
"""Ambient registry for nested Signer/Key dispatch.

While ``Signer.from_priv_key_uri()`` or ``Key.from_dict()`` dispatches into an
implementation via a ``SignerRegistry``, the registry is stored here so that
nested dispatch calls made by the implementation (without an explicit
``registry`` argument) resolve against the same registry.
"""


class SignerRegistry:
    """Isolated dispatch context for Signer and Key implementations.

    A registry holds its own copies of the default dispatch tables
    (``SIGNER_FOR_URI_SCHEME`` and ``KEY_FOR_TYPE_AND_SCHEME``), snapshotted
    at construction time: later changes to the global tables do not affect
    existing registries, and registrations on a registry affect neither the
    global tables nor other registries. This allows multiple applications
    (or tenants) in the same process to use conflicting custom
    implementations -- even for the same URI scheme or key type/scheme.

    Registrations are additive by default: registering an already registered
    URI scheme or key type/scheme (including the built-in defaults) raises
    ``ValueError``. Pass ``replace=True`` to explicitly override an existing
    registration.

    Migrating from global registration::

        # Before: process-wide global dispatch tables
        SIGNER_FOR_URI_SCHEME[MySigner.SCHEME] = MySigner
        KEY_FOR_TYPE_AND_SCHEME[(MyKey.KEYTYPE, MyKey.SCHEME)] = MyKey
        signer = Signer.from_priv_key_uri(uri, public_key)
        key = Key.from_dict(keyid, key_dict)

        # After: per-registry isolation
        registry = SignerRegistry()
        registry.register_signer(MySigner.SCHEME, MySigner)
        registry.register_key(MyKey.KEYTYPE, MyKey.SCHEME, MyKey)
        signer = registry.signer_from_priv_key_uri(uri, public_key)
        key = registry.key_from_dict(keyid, key_dict)

    The registry is also propagated through nested dispatch: while a signer
    or key is constructed via a registry, any ``Signer.from_priv_key_uri()``
    or ``Key.from_dict()`` call the implementation makes internally resolves
    against the same registry, no explicit passing needed.

    Alternatively, the registry can be passed explicitly::

        signer = Signer.from_priv_key_uri(uri, public_key, registry=registry)
        key = Key.from_dict(keyid, key_dict, registry=registry)
    """

    def __init__(self) -> None:
        # NOTE: Local imports to avoid a circular import: _signer and _key
        # use this module for the ambient registry context variable.
        from securesystemslib.signer._key import KEY_FOR_TYPE_AND_SCHEME
        from securesystemslib.signer._signer import SIGNER_FOR_URI_SCHEME

        self._signer_for_uri_scheme: dict[str, type] = dict(SIGNER_FOR_URI_SCHEME)
        self._key_for_type_and_scheme: dict[tuple[str, str], type] = dict(
            KEY_FOR_TYPE_AND_SCHEME
        )

    def register_signer(
        self, scheme: str, signer: type[Signer], *, replace: bool = False
    ) -> None:
        """Register a Signer implementation for a private key URI scheme.

        Args:
            scheme: Private key URI scheme, e.g. ``file2``.
            signer: Signer implementation class for the scheme.
            replace: Must be True to replace an existing registration
                (including built-in defaults).

        Raises:
            ValueError: Scheme is already registered and replace is False.
        """
        if not replace and scheme in self._signer_for_uri_scheme:
            raise ValueError(
                f"Signer already registered for URI scheme '{scheme}': "
                "pass replace=True to override"
            )
        self._signer_for_uri_scheme[scheme] = signer

    def register_key(
        self, keytype: str, scheme: str, key: type[Key], *, replace: bool = False
    ) -> None:
        """Register a Key implementation for a keytype and scheme pair.

        Args:
            keytype: Key type, e.g. ``KEY_TYPE_ED25519``.
            scheme: Signature scheme, e.g. ``ED25519``.
            key: Key implementation class for the keytype/scheme pair.
            replace: Must be True to replace an existing registration
                (including built-in defaults).

        Raises:
            ValueError: Keytype/scheme pair is already registered and
                replace is False.
        """
        if not replace and (keytype, scheme) in self._key_for_type_and_scheme:
            raise ValueError(
                f"Key already registered for keytype/scheme '{keytype}/{scheme}': "
                "pass replace=True to override"
            )
        self._key_for_type_and_scheme[(keytype, scheme)] = key

    def signer_from_priv_key_uri(
        self,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: SecretsHandler | None = None,
    ) -> Signer:
        """Dispatch to a Signer implementation registered in this registry.

        Equivalent to ``Signer.from_priv_key_uri(..., registry=self)``.
        """
        from securesystemslib.signer._signer import Signer

        return Signer.from_priv_key_uri(
            priv_key_uri, public_key, secrets_handler, registry=self
        )

    def key_from_dict(self, keyid: str, key_dict: dict[str, Any]) -> Key:
        """Dispatch to a Key implementation registered in this registry.

        Equivalent to ``Key.from_dict(..., registry=self)``.
        """
        from securesystemslib.signer._key import Key

        return Key.from_dict(keyid, key_dict, registry=self)
