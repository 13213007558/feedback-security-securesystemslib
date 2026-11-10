"""Algorithm-confusion regression tests.

These tests try to get a signature accepted with the *wrong* key
configuration. Each matrix row deliberately mismatches one of:

* the declared ``keytype`` / ``scheme`` (the metadata claim),
* the actual public key material (curve, algorithm family, encoding),
* the signature format / padding / digest it is verified against,
* the payload that was signed (incl. the DSSE pre-auth-encoding).

For every negative row the matrix states the stage at which the mismatch
must be rejected:

* ``import`` - ``Key.from_dict`` dispatch / ``SSlibKey`` construction,
* ``signer`` - ``CryptoSigner`` construction (private vs. public key),
* ``verify`` - ``SSlibKey.verify_signature`` / ``Envelope.verify``.

Positive control rows use the project's current pyca/cryptography backend to
produce real signatures over fixed data. Signature bytes are generated at run
time, so the tests do not depend on randomised (e.g. PSS/ECDSA) signatures
being byte-identical across runs. Optional remote signers (KMS, HSM, vault,
sigstore, tkey, gpg) are intentionally out of scope.

The matrix is short on purpose and every row carries a stable ``case_id``;
a single row can be re-run, e.g.::

    python -m pytest tests/test_algorithm_confusion.py -k p384_material_under_p256
    python -m unittest tests.test_algorithm_confusion.TestAlgorithmConfusion.\
test_verify_stage_rejects_confused_material
"""

from __future__ import annotations

import copy
import unittest
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.hashes import SHA256, SHA384
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
)

from securesystemslib.dsse import Envelope
from securesystemslib.exceptions import (
    UnverifiedSignatureError,
    VerificationError,
)
from securesystemslib.signer import (
    ECDSA_SHA2_NISTP256,
    ECDSA_SHA2_NISTP384,
    ECDSA_SHA2_NISTP521,
    ED25519,
    KEY_FOR_TYPE_AND_SCHEME,
    KEY_TYPE_ECDSA,
    KEY_TYPE_ED25519,
    KEY_TYPE_MLDSA,
    KEY_TYPE_RSA,
    MLDSA_65_1,
    RSA_PKCS1V15_SHA256,
    RSASSA_PSS_SHA256,
    CryptoSigner,
    Key,
    Signature,
    SSlibKey,
)
from securesystemslib.signer._key import MLDSA_IMPORT_ERROR

PEMS_DIR = Path(__file__).parent / "data" / "pems"
PAYLOAD = b"DATA"
OTHER_PAYLOAD = b"NOT DATA"
PAYLOAD_TYPE = "application/vnd.securesystemslib.confusion+json"

# Rejection stages (kept as strings so they read well in the matrix / output).
STAGE_IMPORT = "import"
STAGE_SIGNER = "signer"
STAGE_VERIFY = "verify"


@dataclass
class ConfusionCase:
    case_id: str
    description: str
    stage: str
    keytype: str
    scheme: str
    material: str  # key into the `publics` mapping
    expect: type[Exception]


# Stage 1: import / dispatch. These must never produce a usable Key object.
IMPORT_CASES = [
    ConfusionCase(
        "import_unknown_pair_ecdsa_alias_scheme_cross",
        "legacy alias keytype p384 paired with p256 scheme is not registered",
        STAGE_IMPORT,
        ECDSA_SHA2_NISTP384,
        ECDSA_SHA2_NISTP256,
        "ec256",
        ValueError,
    ),
    ConfusionCase(
        "import_unknown_pair_rsa_keytype_ed_scheme",
        "rsa keytype can never carry the ed25519 scheme",
        STAGE_IMPORT,
        KEY_TYPE_RSA,
        ED25519,
        "ed25519",
        ValueError,
    ),
    ConfusionCase(
        "import_unknown_pair_ed_keytype_rsa_scheme",
        "ed25519 keytype can never carry an rsa scheme",
        STAGE_IMPORT,
        KEY_TYPE_ED25519,
        RSASSA_PSS_SHA256,
        "rsa",
        ValueError,
    ),
    ConfusionCase(
        "import_unknown_pair_ecdsa_keytype_ed_scheme",
        "ecdsa keytype can never carry the ed25519 scheme",
        STAGE_IMPORT,
        KEY_TYPE_ECDSA,
        ED25519,
        "ed25519",
        ValueError,
    ),
    ConfusionCase(
        "import_unknown_pair_mldsa_keytype_ed_scheme",
        "ml-dsa keytype can never carry the ed25519 scheme",
        STAGE_IMPORT,
        KEY_TYPE_MLDSA,
        ED25519,
        "ed25519",
        ValueError,
    ),
    ConfusionCase(
        "import_missing_public_keyval",
        "SSlibKey requires a string 'public' keyval",
        STAGE_IMPORT,
        KEY_TYPE_ED25519,
        ED25519,
        "",
        ValueError,
    ),
]

# Stage 3: verify. These pairs import fine but must fail verification and must
# never accept a foreign / malformed signature.
VERIFY_CASES = [
    ConfusionCase(
        "ecdsa_curve_mismatch_p384_material_under_p256_scheme",
        "p384 public key material claimed as nistp256",
        STAGE_VERIFY,
        KEY_TYPE_ECDSA,
        ECDSA_SHA2_NISTP256,
        "ec384",
        VerificationError,
    ),
    ConfusionCase(
        "ecdsa_curve_mismatch_p256_material_under_p384_scheme",
        "p256 public key material claimed as nistp384",
        STAGE_VERIFY,
        KEY_TYPE_ECDSA,
        ECDSA_SHA2_NISTP384,
        "ec256",
        VerificationError,
    ),
    ConfusionCase(
        "ecdsa_curve_mismatch_p256_material_under_p521_scheme",
        "p256 public key material claimed as nistp521",
        STAGE_VERIFY,
        KEY_TYPE_ECDSA,
        ECDSA_SHA2_NISTP521,
        "ec256",
        VerificationError,
    ),
    ConfusionCase(
        "rsa_material_under_ecdsa_scheme",
        "rsa SPKI material loaded through the ecdsa verification branch",
        STAGE_VERIFY,
        KEY_TYPE_ECDSA,
        ECDSA_SHA2_NISTP256,
        "rsa",
        VerificationError,
    ),
    ConfusionCase(
        "ecdsa_material_under_rsa_scheme",
        "ecdsa SPKI material loaded through the rsa verification branch",
        STAGE_VERIFY,
        KEY_TYPE_RSA,
        RSASSA_PSS_SHA256,
        "ec256",
        VerificationError,
    ),
    ConfusionCase(
        "ed25519_raw_material_under_rsa_scheme",
        "raw ed25519 bytes are not an RSA PEM subject-public-key-info",
        STAGE_VERIFY,
        KEY_TYPE_RSA,
        RSASSA_PSS_SHA256,
        "ed25519",
        VerificationError,
    ),
    ConfusionCase(
        "mldsa_material_under_ed25519_scheme",
        "ml-dsa SPKI material cannot be read as an ed25519 raw key",
        STAGE_VERIFY,
        KEY_TYPE_ED25519,
        ED25519,
        "mldsa65",
        VerificationError,
    ),
]


class TestAlgorithmConfusion(unittest.TestCase):
    """Table-driven algorithm-confusion regression suite.

    Private keys come from the bundled PEM fixtures; signatures are generated
    with the current pyca/cryptography backend over the fixed ``PAYLOAD``.
    """

    @classmethod
    def setUpClass(cls) -> None:
        names = ["rsa", "ecdsa", "ecdsa_secp384r1", "ecdsa_secp521r1", "ed25519"]
        if MLDSA_IMPORT_ERROR is None:
            names.append("mldsa65")

        cls.private: dict[str, Any] = {}
        for name in names:
            cls.private[name] = load_pem_private_key(
                (PEMS_DIR / f"{name}_private.pem").read_bytes(), None
            )

        cls.keys = {
            "rsa": cls.private["rsa"],
            "ec256": cls.private["ecdsa"],
            "ec384": cls.private["ecdsa_secp384r1"],
            "ec521": cls.private["ecdsa_secp521r1"],
            "ed25519": cls.private["ed25519"],
        }
        cls.publics = {
            "rsa": cls._pem(cls.keys["rsa"].public_key()),
            "ec256": cls._pem(cls.keys["ec256"].public_key()),
            "ec384": cls._pem(cls.keys["ec384"].public_key()),
            "ec521": cls._pem(cls.keys["ec521"].public_key()),
            "ed25519": cls.keys["ed25519"]
            .public_key()
            .public_bytes(Encoding.Raw, PublicFormat.Raw)
            .hex(),
        }
        if MLDSA_IMPORT_ERROR is None:
            cls.keys["mldsa65"] = cls.private["mldsa65"]
            cls.publics["mldsa65"] = cls._pem(cls.keys["mldsa65"].public_key())

    @staticmethod
    def _pem(public_key: Any) -> str:
        return public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode()

    # -- Stage 1: import ----------------------------------------------------
    def test_import_stage_rejects(self) -> None:
        for case in IMPORT_CASES:
            with self.subTest(case_id=case.case_id):
                if case.material == "":
                    key_dict: dict[str, Any] = {
                        "keytype": case.keytype,
                        "scheme": case.scheme,
                        "keyval": {},
                    }
                else:
                    key_dict = {
                        "keytype": case.keytype,
                        "scheme": case.scheme,
                        "keyval": {"public": self.publics[case.material]},
                    }

                with self.assertRaises(case.expect):
                    Key.from_dict("confused-keyid", key_dict)

                # Unknown pairs stay out of the dispatch table. The
                # missing-keyval row uses a registered pair and is rejected by
                # the SSlibKey constructor, so it is exempt from this check.
                if case.material != "":
                    self.assertNotIn(
                        (case.keytype, case.scheme), KEY_FOR_TYPE_AND_SCHEME
                    )

    # -- Stage 3: verify ----------------------------------------------------
    def test_verify_stage_rejects_confused_material(self) -> None:
        for case in VERIFY_CASES:
            with self.subTest(case_id=case.case_id):
                key = SSlibKey(
                    "confused-keyid",
                    case.keytype,
                    case.scheme,
                    {"public": self.publics[case.material]},
                )
                # An unrelated, syntactically valid blob is enough: a confused
                # key must fail the type/curve checks before any crypto compare.
                signature = Signature("confused-keyid", b"\x00\x00".hex())
                with self.assertRaises(case.expect):
                    key.verify_signature(signature, PAYLOAD)

                # Rejected objects stay safe: they still round-trip and keep
                # rejecting rather than accepting.
                self.assertEqual(key.to_dict()["keytype"], case.keytype)
                with self.assertRaises(UnverifiedSignatureError):
                    key.verify_signature(signature, PAYLOAD)

    def test_rsa_cross_padding(self) -> None:
        """A PSS signature must not verify under a pkcs1v15 claim (and back)."""
        pss_sig = self.keys["rsa"].sign(
            PAYLOAD,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(SHA256()), salt_length=SHA256.digest_size
            ),
            SHA256(),
        )
        v15_sig = self.keys["rsa"].sign(
            PAYLOAD, asym_padding.PKCS1v15(), SHA256()
        )

        pkcs_key = SSlibKey(
            "rsa", KEY_TYPE_RSA, RSA_PKCS1V15_SHA256,
            {"public": self.publics["rsa"]},
        )
        pss_key = SSlibKey(
            "rsa", KEY_TYPE_RSA, RSASSA_PSS_SHA256,
            {"public": self.publics["rsa"]},
        )

        with self.assertRaises(UnverifiedSignatureError):
            pkcs_key.verify_signature(Signature("rsa", pss_sig.hex()), PAYLOAD)
        with self.assertRaises(UnverifiedSignatureError):
            pss_key.verify_signature(Signature("rsa", v15_sig.hex()), PAYLOAD)

        # Matching padding accepts and the key stays usable.
        pkcs_key.verify_signature(Signature("rsa", v15_sig.hex()), PAYLOAD)
        pss_key.verify_signature(Signature("rsa", pss_sig.hex()), PAYLOAD)

    def test_ecdsa_digest_cross_combination(self) -> None:
        """A signature made with one digest fails a different digest claim."""
        # Same curve on both sides so the curve guard passes; only the digest
        # differs. cryptography binds ECDSA(hash) at verify time.
        sig_sha384 = self.keys["ec384"].sign(PAYLOAD, ec.ECDSA(SHA384()))
        sig_sha256 = self.keys["ec384"].sign(PAYLOAD, ec.ECDSA(SHA256()))

        key_384 = SSlibKey(
            "ec384", KEY_TYPE_ECDSA, ECDSA_SHA2_NISTP384,
            {"public": self.publics["ec384"]},
        )
        key_384.verify_signature(Signature("ec384", sig_sha384.hex()), PAYLOAD)
        with self.assertRaises(UnverifiedSignatureError):
            key_384.verify_signature(
                Signature("ec384", sig_sha256.hex()), PAYLOAD
            )

    def test_signature_format_keyid_and_payload_mismatches(self) -> None:
        """Malformed bytes, wrong keyid and wrong payload all fail verify."""
        signer = CryptoSigner(self.keys["ed25519"])
        signature = signer.sign(PAYLOAD)
        key = signer.public_key

        # Non-hex encoding is a process error; a truncated but well-formed blob
        # is an unverifiable signature. Neither is accepted.
        with self.assertRaises(VerificationError):
            key.verify_signature(Signature(key.keyid, "not-hex"), PAYLOAD)
        with self.assertRaises(UnverifiedSignatureError):
            key.verify_signature(Signature(key.keyid, "00"), PAYLOAD)

        # A signature presented under another keyid is refused before crypto.
        with self.assertRaises(VerificationError):
            key.verify_signature(
                Signature("attacker-keyid", signature.signature), PAYLOAD
            )

        # The genuine signature over PAYLOAD must not verify another payload.
        with self.assertRaises(UnverifiedSignatureError):
            key.verify_signature(signature, OTHER_PAYLOAD)

        # After every rejection the key still verifies the genuine signature.
        key.verify_signature(signature, PAYLOAD)

    # -- Positive controls --------------------------------------------------
    def test_positive_roundtrip_for_each_supported_scheme(self) -> None:
        rsa_schemes = [
            "rsassa-pss-sha256",
            "rsassa-pss-sha384",
            "rsassa-pss-sha512",
            "rsa-pkcs1v15-sha256",
            "rsa-pkcs1v15-sha384",
            "rsa-pkcs1v15-sha512",
        ]
        ecdsa = [
            ("ec256", ECDSA_SHA2_NISTP256),
            ("ec384", ECDSA_SHA2_NISTP384),
            ("ec521", ECDSA_SHA2_NISTP521),
        ]

        for scheme in rsa_schemes:
            public = SSlibKey(
                "rsa", KEY_TYPE_RSA, scheme, {"public": self.publics["rsa"]}
            )
            signer = CryptoSigner(self.keys["rsa"], public)
            signature = signer.sign(PAYLOAD)
            public.verify_signature(signature, PAYLOAD)
            with self.assertRaises(UnverifiedSignatureError):
                public.verify_signature(signature, OTHER_PAYLOAD)

        for material, scheme in ecdsa:
            public = SSlibKey(
                material, KEY_TYPE_ECDSA, scheme,
                {"public": self.publics[material]},
            )
            signer = CryptoSigner(self.keys[material], public)
            public.verify_signature(signer.sign(PAYLOAD), PAYLOAD)

        ed_public = SSlibKey(
            "ed25519", KEY_TYPE_ED25519, ED25519,
            {"public": self.publics["ed25519"]},
        )
        ed_signer = CryptoSigner(self.keys["ed25519"], ed_public)
        ed_public.verify_signature(ed_signer.sign(PAYLOAD), PAYLOAD)

        if MLDSA_IMPORT_ERROR is None:
            mldsa_public = SSlibKey(
                "mldsa65", KEY_TYPE_MLDSA, MLDSA_65_1,
                {"public": self.publics["mldsa65"]},
            )
            mldsa_signer = CryptoSigner(self.keys["mldsa65"], mldsa_public)
            mldsa_public.verify_signature(mldsa_signer.sign(PAYLOAD), PAYLOAD)

    def test_legacy_ecdsa_keytype_alias_remains_accepted(self) -> None:
        """keytype == scheme (deprecated) still imports, signs and verifies."""
        for material, scheme in [
            ("ec256", ECDSA_SHA2_NISTP256),
            ("ec384", ECDSA_SHA2_NISTP384),
            ("ec521", ECDSA_SHA2_NISTP521),
        ]:
            with self.subTest(case_id=f"legacy_alias_{scheme}"):
                # Import through the public dispatch table, not the constructor.
                legacy = Key.from_dict(
                    material,
                    {
                        "keytype": scheme,
                        "scheme": scheme,
                        "keyval": {"public": self.publics[material]},
                    },
                )
                modern = Key.from_dict(
                    material,
                    {
                        "keytype": KEY_TYPE_ECDSA,
                        "scheme": scheme,
                        "keyval": {"public": self.publics[material]},
                    },
                )

                signer = CryptoSigner(self.keys[material], legacy)
                signature = signer.sign(PAYLOAD)

                with self.assertWarns(DeprecationWarning):
                    legacy.verify_signature(signature, PAYLOAD)
                # The modern keytype verifies the same signature, no warning.
                with warnings.catch_warnings():
                    warnings.simplefilter("error", DeprecationWarning)
                    modern.verify_signature(signature, PAYLOAD)

                # A tampered payload is still rejected under the legacy alias.
                with self.assertRaises(UnverifiedSignatureError):
                    legacy.verify_signature(signature, OTHER_PAYLOAD)

    def test_legacy_alias_cross_curve_still_rejected(self) -> None:
        """The legacy alias gets no special treatment: curve confusion fails."""
        legacy_confused = SSlibKey(
            "ec",
            ECDSA_SHA2_NISTP256,  # deprecated keytype == scheme spelling
            ECDSA_SHA2_NISTP256,
            {"public": self.publics["ec384"]},
        )
        with self.assertRaises(VerificationError):
            legacy_confused.verify_signature(Signature("ec", "0000"), PAYLOAD)

    # -- Stage 2: CryptoSigner construction --------------------------------
    def test_signer_construction_rejects_wrong_key_family(self) -> None:
        rsa_public = SSlibKey.from_crypto(self.keys["rsa"].public_key())
        ecdsa_public = SSlibKey.from_crypto(self.keys["ec256"].public_key())
        ed_public = SSlibKey.from_crypto(self.keys["ed25519"].public_key())

        mismatches = [
            (self.keys["ed25519"], rsa_public),
            (self.keys["rsa"], ecdsa_public),
            (self.keys["ec256"], ed_public),
        ]
        for private_key, public_key in mismatches:
            with self.subTest(public=public_key.scheme):
                with self.assertRaises(ValueError):
                    CryptoSigner(private_key, public_key)

    def test_signer_construction_rejects_curve_mismatch(self) -> None:
        """Defense in depth: signer rejects a curve the verify layer rejects."""
        public = SSlibKey.from_crypto(self.keys["ec384"].public_key())
        for scheme in (ECDSA_SHA2_NISTP256, ECDSA_SHA2_NISTP521):
            with self.subTest(case_id=f"signer_curve_mismatch_{scheme}"):
                confused = copy.copy(public)
                confused.scheme = scheme
                with self.assertRaises(ValueError):
                    CryptoSigner(self.keys["ec384"], confused)

        # The same private key with its genuine scheme constructs and signs.
        genuine = SSlibKey.from_crypto(
            self.keys["ec384"].public_key(), ECDSA_SHA2_NISTP384
        )
        signer = CryptoSigner(self.keys["ec384"], genuine)
        genuine.verify_signature(signer.sign(PAYLOAD), PAYLOAD)

    def test_signer_construction_rejects_unrelated_key_pair(self) -> None:
        """Two keys of the same family still must form one key pair."""
        first = CryptoSigner(self.keys["ec256"])
        second_private = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(Exception):
            CryptoSigner(second_private, first.public_key)

        # The original signer is unaffected by the failed construction attempt.
        first.public_key.verify_signature(first.sign(PAYLOAD), PAYLOAD)

    def test_from_crypto_loose_scheme_override_is_contained(self) -> None:
        """from_crypto trusts an explicit scheme, but the mismatch dies at signer.

        The override is a documented convenience (e.g. choosing RSA padding),
        so it must not be rejected at import - but a scheme contradicting the
        key material can never produce a working signer or verify.
        """
        ecdsa_key = SSlibKey.from_crypto(
            self.keys["ec256"].public_key(), scheme=RSA_PKCS1V15_SHA256
        )
        self.assertEqual(ecdsa_key.scheme, RSA_PKCS1V15_SHA256)
        with self.assertRaises(ValueError):
            CryptoSigner(self.keys["ec256"], ecdsa_key)

    # -- DSSE ---------------------------------------------------------------
    def test_dsse_accepts_genuine_envelope_and_rejects_confused_key(self) -> None:
        signer = CryptoSigner(self.keys["ec256"])
        envelope = Envelope(PAYLOAD, PAYLOAD_TYPE, {})
        signature = envelope.sign(signer)
        self.assertEqual(
            envelope.verify([signer.public_key], 1),
            {signer.public_key.keyid: signer.public_key},
        )

        # A different key that merely copies the signature's keyid cannot pass.
        foreign = SSlibKey.from_crypto(self.keys["ec384"].public_key())
        foreign.keyid = signature.keyid
        with self.assertRaises(VerificationError):
            envelope.verify([foreign], 1)

    def test_dsse_rejects_tampered_payload_and_type(self) -> None:
        signer = CryptoSigner(self.keys["rsa"])
        envelope = Envelope(PAYLOAD, PAYLOAD_TYPE, {})
        envelope.sign(signer)

        tampered_payload = Envelope(
            OTHER_PAYLOAD, PAYLOAD_TYPE, envelope.signatures
        )
        with self.assertRaises(VerificationError):
            tampered_payload.verify([signer.public_key], 1)

        tampered_type = Envelope(
            PAYLOAD, "application/vnd.attacker+json", envelope.signatures
        )
        with self.assertRaises(VerificationError):
            tampered_type.verify([signer.public_key], 1)

        # The untouched envelope still verifies after the failed attempts.
        envelope.verify([signer.public_key], 1)

    def test_dsse_roundtrip_via_dict_for_each_family(self) -> None:
        """Serialization must preserve the signature the envelope verifies."""
        signers = [
            CryptoSigner(self.keys["rsa"]),
            CryptoSigner(self.keys["ec256"]),
            CryptoSigner(self.keys["ed25519"]),
        ]
        if MLDSA_IMPORT_ERROR is None:
            signers.append(CryptoSigner(self.keys["mldsa65"]))

        envelope = Envelope(PAYLOAD, PAYLOAD_TYPE, {})
        for signer in signers:
            envelope.sign(signer)

        restored = Envelope.from_dict(envelope.to_dict())
        accepted = restored.verify(
            [s.public_key for s in signers], len(signers)
        )
        self.assertEqual(len(accepted), len(signers))

    def test_matrix_stage_labels_are_known(self) -> None:
        for case in IMPORT_CASES + VERIFY_CASES:
            self.assertIn(
                case.stage, {STAGE_IMPORT, STAGE_SIGNER, STAGE_VERIFY}
            )


if __name__ == "__main__":
    unittest.main()
