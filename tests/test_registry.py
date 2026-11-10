"""Tests for isolated Signer/Key dispatch with SignerRegistry.

Two fake signing "businesses" (A and B) register conflicting
implementations for the same URI scheme and key type/scheme in the same
process, each on its own SignerRegistry.
"""

import copy
import unittest
from typing import Any

from securesystemslib.exceptions import (
    UnsupportedLibraryError,
    UnverifiedSignatureError,
)
from securesystemslib.signer import (
    KEY_FOR_TYPE_AND_SCHEME,
    SIGNER_FOR_URI_SCHEME,
    Key,
    Signature,
    Signer,
    SignerRegistry,
)


class FakeKey(Key):
    """Key implementation shared by both fake businesses."""

    KEYTYPE = "fake-keytype"

    @classmethod
    def from_dict(cls, keyid: str, key_dict: dict[str, Any]) -> "FakeKey":
        keytype, scheme, keyval = cls._from_dict(key_dict)
        return cls(keyid, keytype, scheme, keyval, key_dict)

    def to_dict(self) -> dict[str, Any]:
        return self._to_dict()

    def verify_signature(self, signature: Signature, data: bytes) -> None:
        # "signature" is tag + payload, hex-encoded
        expected = (self.keyval["tag"].encode() + data).hex()
        if signature.keyid != self.keyid or signature.signature != expected:
            raise UnverifiedSignatureError("fake verification failed")


class FakeSignerA(Signer):
    """Signer for business A: nests a Key.from_dict() during construction."""

    SCHEME = "fake"
    NESTED_SCHEME = "fake-nested-a"

    def __init__(self, public_key: FakeKey, nested_key: Key):
        self._public_key = public_key
        self.nested_key = nested_key

    @property
    def public_key(self) -> FakeKey:
        return self._public_key

    @classmethod
    def from_priv_key_uri(
        cls, priv_key_uri, public_key, secrets_handler=None
    ) -> "FakeSignerA":
        if not priv_key_uri.startswith(f"{cls.SCHEME}:"):
            raise ValueError(f"FakeSignerA does not support {priv_key_uri}")
        # Nested construction: resolves against the ambient registry,
        # which must be the registry this signer is constructed with.
        nested_key = Key.from_dict(
            "nested-a",
            {
                "keytype": FakeKey.KEYTYPE,
                "scheme": cls.NESTED_SCHEME,
                "keyval": {"tag": "nested-a"},
            },
        )
        return cls(public_key, nested_key)

    def sign(self, payload: bytes) -> Signature:
        return Signature(self.public_key.keyid, (b"tag-a" + payload).hex())


class NestedHelperSignerB(Signer):
    """Helper signer only business B knows about, constructed nested."""

    SCHEME = "fake-helper-b"

    def __init__(self, public_key: Key):
        self._public_key = public_key

    @property
    def public_key(self) -> Key:
        return self._public_key

    @classmethod
    def from_priv_key_uri(
        cls, priv_key_uri, public_key, secrets_handler=None
    ) -> "NestedHelperSignerB":
        return cls(public_key)

    def sign(self, payload: bytes) -> Signature:
        return Signature(self.public_key.keyid, (b"helper-b" + payload).hex())


class FakeSignerB(Signer):
    """Signer for business B: nests a Signer.from_priv_key_uri() call."""

    SCHEME = "fake"

    def __init__(self, public_key: FakeKey, helper: Signer):
        self._public_key = public_key
        self.helper = helper

    @property
    def public_key(self) -> FakeKey:
        return self._public_key

    @classmethod
    def from_priv_key_uri(
        cls, priv_key_uri, public_key, secrets_handler=None
    ) -> "FakeSignerB":
        if not priv_key_uri.startswith(f"{cls.SCHEME}:"):
            raise ValueError(f"FakeSignerB does not support {priv_key_uri}")
        # Nested construction: must dispatch within the ambient registry.
        helper = Signer.from_priv_key_uri(
            f"{NestedHelperSignerB.SCHEME}:inner", public_key
        )
        return cls(public_key, helper)

    def sign(self, payload: bytes) -> Signature:
        return Signature(self.public_key.keyid, (b"tag-b" + payload).hex())


class FakeCloudSigner(Signer):
    """Signer with a missing optional dependency, like the KMS signers."""

    SCHEME = "fake-cloud"
    IMPORT_ERROR = "'fake-cloud-sdk' library required"

    @property
    def public_key(self) -> Key:
        raise NotImplementedError

    @classmethod
    def from_priv_key_uri(
        cls, priv_key_uri, public_key, secrets_handler=None
    ) -> "FakeCloudSigner":
        raise UnsupportedLibraryError(cls.IMPORT_ERROR)

    def sign(self, payload: bytes) -> Signature:
        raise NotImplementedError


def _key(keyid: str, scheme: str, tag: str) -> FakeKey:
    return FakeKey(keyid, FakeKey.KEYTYPE, scheme, {"tag": tag})


class TestSignerRegistry(unittest.TestCase):
    """Registry isolation tests."""

    def setUp(self):
        self.registry_a = SignerRegistry()
        self.registry_a.register_signer(FakeSignerA.SCHEME, FakeSignerA)
        self.registry_a.register_key(FakeKey.KEYTYPE, "fake-scheme-a", FakeKey)
        self.registry_a.register_key(
            FakeKey.KEYTYPE, FakeSignerA.NESTED_SCHEME, FakeKey
        )

        self.registry_b = SignerRegistry()
        self.registry_b.register_signer(FakeSignerB.SCHEME, FakeSignerB)
        self.registry_b.register_signer(NestedHelperSignerB.SCHEME, NestedHelperSignerB)
        self.registry_b.register_key(FakeKey.KEYTYPE, "fake-scheme-b", FakeKey)

    def test_interleaved_businesses_same_scheme(self):
        """Same URI scheme, different implementations, interleaved use."""
        key_a = _key("key-a", "fake-scheme-a", "tag-a")
        key_b = _key("key-b", "fake-scheme-b", "tag-b")

        signer_a = self.registry_a.signer_from_priv_key_uri("fake:a/1", key_a)
        signer_b = self.registry_b.signer_from_priv_key_uri("fake:b/1", key_b)

        self.assertIsInstance(signer_a, FakeSignerA)
        self.assertIsInstance(signer_b, FakeSignerB)

        # Interleaved signing and verification stays on the right side
        for i in range(3):
            data = f"data-{i}".encode()
            sig_a = signer_a.sign(data)
            sig_b = signer_b.sign(data)
            self.assertEqual(sig_a.signature, (b"tag-a" + data).hex())
            self.assertEqual(sig_b.signature, (b"tag-b" + data).hex())
            key_a.verify_signature(sig_a, data)
            key_b.verify_signature(sig_b, data)
            # Cross-verification must fail: no leakage between businesses
            with self.assertRaises(UnverifiedSignatureError):
                key_a.verify_signature(sig_b, data)

    def test_nested_construction_uses_ambient_registry(self):
        """Plugins construct nested keys/signers within their registry."""
        key_a = _key("key-a", "fake-scheme-a", "tag-a")
        key_b = _key("key-b", "fake-scheme-b", "tag-b")

        signer_a = self.registry_a.signer_from_priv_key_uri("fake:a/1", key_a)
        signer_b = self.registry_b.signer_from_priv_key_uri("fake:b/1", key_b)

        # A nested Key.from_dict() resolved registry A's private registration
        self.assertIsInstance(signer_a.nested_key, FakeKey)
        self.assertEqual(signer_a.nested_key.scheme, FakeSignerA.NESTED_SCHEME)

        # B nested Signer.from_priv_key_uri() resolved registry B's helper
        self.assertIsInstance(signer_b.helper, NestedHelperSignerB)
        sig = signer_b.helper.sign(b"x")
        self.assertEqual(sig.signature, (b"helper-b" + b"x").hex())

        # The nested schemes are not visible to the other registry
        with self.assertRaises(ValueError):
            self.registry_b.key_from_dict(
                "nested-a",
                {
                    "keytype": FakeKey.KEYTYPE,
                    "scheme": FakeSignerA.NESTED_SCHEME,
                    "keyval": {"tag": "nested-a"},
                },
            )
        with self.assertRaises(ValueError):
            self.registry_a.signer_from_priv_key_uri(
                f"{NestedHelperSignerB.SCHEME}:inner", key_a
            )

    def test_ambient_registry_does_not_leak(self):
        """After dispatch returns, nested-style calls use the global table."""
        key_a = _key("key-a", "fake-scheme-a", "tag-a")
        self.registry_a.signer_from_priv_key_uri("fake:a/1", key_a)

        # Outside of dispatch, the ambient registry is gone again
        with self.assertRaises(ValueError):
            Key.from_dict(
                "nested-a",
                {
                    "keytype": FakeKey.KEYTYPE,
                    "scheme": FakeSignerA.NESTED_SCHEME,
                    "keyval": {"tag": "nested-a"},
                },
            )

    def test_explicit_registry_argument(self):
        """Registry can be passed to Signer/Key dispatch directly."""
        key_dict = {
            "keytype": FakeKey.KEYTYPE,
            "scheme": "fake-scheme-a",
            "keyval": {"tag": "tag-a"},
        }
        key = Key.from_dict("key-a", copy.deepcopy(key_dict), registry=self.registry_a)
        self.assertIsInstance(key, FakeKey)
        self.assertEqual(key.to_dict(), key_dict)

        signer = Signer.from_priv_key_uri("fake:a/1", key, registry=self.registry_a)
        self.assertIsInstance(signer, FakeSignerA)

    def test_duplicate_registration_fails_unless_replace(self):
        """Re-registering a name errors; replace must be explicit."""
        # Custom scheme registered on this registry
        with self.assertRaises(ValueError):
            self.registry_a.register_signer(FakeSignerA.SCHEME, FakeSignerB)
        with self.assertRaises(ValueError):
            self.registry_a.register_key(FakeKey.KEYTYPE, "fake-scheme-a", FakeKey)

        # Built-in defaults are protected as well
        with self.assertRaises(ValueError):
            self.registry_a.register_signer("file2", FakeSignerA)

        # Explicit replace works and only affects this registry
        self.registry_a.register_signer(FakeSignerA.SCHEME, FakeSignerB, replace=True)
        # FakeSignerB nests a helper signer: register it here too
        self.registry_a.register_signer(NestedHelperSignerB.SCHEME, NestedHelperSignerB)
        signer = self.registry_a.signer_from_priv_key_uri(
            "fake:a/1", _key("key-a", "fake-scheme-a", "tag-a")
        )
        self.assertIsInstance(signer, FakeSignerB)
        with self.assertRaises(ValueError):
            self.registry_b.register_signer(NestedHelperSignerB.SCHEME, FakeSignerA)

    def test_unknown_scheme(self):
        """Unknown URI schemes and key type/schemes fail with ValueError."""
        key_a = _key("key-a", "fake-scheme-a", "tag-a")

        with self.assertRaises(ValueError):
            self.registry_a.signer_from_priv_key_uri("unknown-scheme:x", key_a)
        with self.assertRaises(ValueError):
            self.registry_a.key_from_dict(
                "keyid",
                {
                    "keytype": "unknown-keytype",
                    "scheme": "unknown-scheme",
                    "keyval": {},
                },
            )

        # Registry registrations did not leak into the global tables:
        # the same calls without a registry still fail
        with self.assertRaises(ValueError):
            Signer.from_priv_key_uri("fake:a/1", key_a)
        with self.assertRaises(ValueError):
            Key.from_dict(
                "keyid",
                {
                    "keytype": FakeKey.KEYTYPE,
                    "scheme": "fake-scheme-a",
                    "keyval": {"tag": "tag-a"},
                },
            )

    def test_missing_optional_dependency(self):
        """A registry-local signer may fail on missing optional deps."""
        self.registry_a.register_signer(FakeCloudSigner.SCHEME, FakeCloudSigner)
        key_a = _key("key-a", "fake-scheme-a", "tag-a")

        with self.assertRaises(UnsupportedLibraryError) as ctx:
            self.registry_a.signer_from_priv_key_uri("fake-cloud:x", key_a)
        self.assertIn("fake-cloud-sdk", str(ctx.exception))

        # The failure is contained: business B and the global table are fine
        self.assertNotIn(FakeCloudSigner.SCHEME, SIGNER_FOR_URI_SCHEME)
        signer_b = self.registry_b.signer_from_priv_key_uri(
            "fake:b/1", _key("key-b", "fake-scheme-b", "tag-b")
        )
        self.assertIsInstance(signer_b, FakeSignerB)

    def test_registry_snapshots_global_tables(self):
        """Later changes to the global tables do not affect registries."""
        sentinel = object()
        SIGNER_FOR_URI_SCHEME["late-scheme"] = sentinel
        KEY_FOR_TYPE_AND_SCHEME[("late-keytype", "late-scheme")] = sentinel
        self.addCleanup(SIGNER_FOR_URI_SCHEME.pop, "late-scheme", None)
        self.addCleanup(
            KEY_FOR_TYPE_AND_SCHEME.pop, ("late-keytype", "late-scheme"), None
        )

        # Registries created before the mutation don't see it
        with self.assertRaises(ValueError):
            self.registry_a.signer_from_priv_key_uri("late-scheme:x", None)
        with self.assertRaises(ValueError):
            self.registry_a.key_from_dict(
                "keyid",
                {
                    "keytype": "late-keytype",
                    "scheme": "late-scheme",
                    "keyval": {},
                },
            )

        # Registry registrations never pollute the global tables
        self.assertNotIn(FakeSignerA.SCHEME, SIGNER_FOR_URI_SCHEME)
        self.assertNotIn((FakeKey.KEYTYPE, "fake-scheme-a"), KEY_FOR_TYPE_AND_SCHEME)

    def test_default_behavior_unchanged(self):
        """Built-in tables work as before, with and without a registry."""
        key_dict = {
            "keytype": "ed25519",
            "scheme": "ed25519",
            "keyval": {"public": "ab" * 32},
        }
        # Global dispatch
        key = Key.from_dict("keyid", copy.deepcopy(key_dict))
        self.assertEqual(key.keytype, "ed25519")
        # Registry dispatch includes the built-in defaults
        key = self.registry_a.key_from_dict("keyid", copy.deepcopy(key_dict))
        self.assertEqual(key.keytype, "ed25519")


if __name__ == "__main__":
    unittest.main()
