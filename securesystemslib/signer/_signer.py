"""Signer interface"""

from __future__ import annotations

import logging
from abc import ABCMeta, abstractmethod
from collections.abc import Callable
from typing import TYPE_CHECKING

from securesystemslib.signer._key import Key
from securesystemslib.signer._registry import CURRENT_REGISTRY
from securesystemslib.signer._signature import Signature

if TYPE_CHECKING:
    from securesystemslib.signer._registry import SignerRegistry

logger = logging.getLogger(__name__)

# NOTE Signer dispatch table is defined here so it's usable by Signer,
# but is populated in __init__.py (and can be appended by users).
SIGNER_FOR_URI_SCHEME: dict[str, type] = {}
"""Signer dispatch table for ``Signer.from_priv_key()``

See ``securesystemslib.signer.SIGNER_FOR_URI_SCHEME`` for default URI schemes,
and how to register custom implementations.
"""

# SecretsHandler is a function the calling code can provide to Signer:
# SecretsHandler will be called if Signer needs additional secrets.
# The argument is the name of the secret ("PIN", "passphrase", etc).
# Return value is the secret string.
SecretsHandler = Callable[[str], str]


class Signer(metaclass=ABCMeta):
    """Signer interface that supports multiple signing implementations.

    Usage example::

        signer = Signer.from_priv_key_uri(uri, pub_key)
        sig = signer.sign(b"data")

    Note that signer implementations may raise errors (during both
    ``Signer.from_priv_key_uri()`` and ``Signer.sign()``) that are not
    documented here: examples could include network errors or file read errors.
    Applications should use generic try-except here if unexpected raises are
    not an option.

    See ``SIGNER_FOR_URI_SCHEME`` for supported private key URI schemes.

    Interactive applications may also define a secrets handler that allows
    asking for user secrets if they are needed::

        from getpass import getpass

        def sec_handler(secret_name:str) -> str:
            return getpass(f"Enter {secret_name}: ")

        signer = Signer.from_priv_key_uri(uri, pub_key, sec_handler)

    Applications can provide their own Signer and Key implementations::

        from securesystemslib.signer import Signer, SIGNER_FOR_URI_SCHEME
        from mylib import MySigner

        SIGNER_FOR_URI_SCHEME[MySigner.MY_SCHEME] = MySigner

    This way the application code using signer API continues to work with
    default signers but now also uses the custom signer when the proper URI is
    used.

    To keep custom implementations isolated from other users of this library
    in the same process, register them on a ``SignerRegistry`` instance
    instead of the global dispatch table, and pass the registry here::

        from securesystemslib.signer import SignerRegistry

        registry = SignerRegistry()
        registry.register_signer(MySigner.MY_SCHEME, MySigner)

        signer = Signer.from_priv_key_uri(uri, pub_key, registry=registry)
    """

    @abstractmethod
    def sign(self, payload: bytes) -> Signature:
        """Signs a given payload by the key assigned to the Signer instance.

        Arguments:
            payload: The bytes to be signed.

        Returns:
            Returns a "Signature" class instance.
        """
        raise NotImplementedError  # pragma: no cover

    @classmethod
    @abstractmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: SecretsHandler | None = None,
        registry: SignerRegistry | None = None,
    ) -> Signer:
        """Factory constructor for a given private key URI

        Returns a specific Signer instance based on the private key URI and the
        supported uri schemes listed in ``SIGNER_FOR_URI_SCHEME``.

        Args:
            priv_key_uri: URI that identifies the private key
            public_key: Key that is the public portion of this private key
            secrets_handler: Optional function that may be called if the
                signer needs additional secrets (like a PIN or passphrase).
                secrets_handler should return the requested secret string.
            registry: Optional ``SignerRegistry`` to dispatch with, instead
                of the global ``SIGNER_FOR_URI_SCHEME`` table. The registry
                is also used for nested dispatch calls made by the signer
                implementation.

        Raises:
            ValueError: Incorrect arguments
            Other Signer-specific errors: These could include OSErrors for
                reading files or network errors for connecting to a KMS.
        """

        scheme, _, _ = priv_key_uri.partition(":")

        if registry is None:
            registry = CURRENT_REGISTRY.get()

        if registry is None:
            dispatch_table = SIGNER_FOR_URI_SCHEME
        else:
            dispatch_table = registry._signer_for_uri_scheme

        if scheme not in dispatch_table:
            raise ValueError(f"Unsupported private key scheme {scheme}")

        signer = dispatch_table[scheme]

        if registry is None:
            return signer.from_priv_key_uri(priv_key_uri, public_key, secrets_handler)  # type: ignore

        # Make the registry ambient so that nested dispatch calls made by
        # the signer implementation resolve against the same registry.
        token = CURRENT_REGISTRY.set(registry)
        try:
            return signer.from_priv_key_uri(priv_key_uri, public_key, secrets_handler)  # type: ignore
        finally:
            CURRENT_REGISTRY.reset(token)

    @property
    @abstractmethod
    def public_key(self) -> Key:
        """
        Returns:
            Public key the signer is based off.
        """
        raise NotImplementedError
