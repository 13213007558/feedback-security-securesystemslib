"""Test cases for group-threshold signature policy verification."""

import copy
import logging
import unittest

from securesystemslib.dsse import Envelope
from securesystemslib.exceptions import (
    UnsupportedAlgorithmError,
    VerificationError,
)
from securesystemslib.policy import (
    BAD_SIGNATURE,
    UNKNOWN_KEY,
    UNSUPPORTED_ALGORITHM,
    AmbiguousKeyError,
    PolicyVerificationError,
    ThresholdGroup,
    ThresholdPolicy,
    verify_policy,
)
from securesystemslib.signer import CryptoSigner, Key, Signature

PAYLOAD = b"release-2026.11.10"
PAYLOAD_TYPE = "application/vnd.example.release+json"

BUILDER = "builder-org"
BUILDER_TWO = "second-builder"
AUDITOR = "auditor-org"
OUTSIDER = "outsider"


def _envelope(signers):
    envelope = Envelope(PAYLOAD, PAYLOAD_TYPE, {})
    for signer in signers:
        envelope.sign(signer)
    return envelope


class UnsupportedKey(Key):
    """Minimal Key whose verification always fails with an unsupported algo."""

    def __init__(self, keyid):
        super().__init__(
            keyid,
            "unsupported-type",
            "unsupported-scheme",
            {
                "public": keyid,
            },
        )

    @classmethod
    def from_dict(cls, keyid, key_dict):
        return cls(keyid)

    def to_dict(self):
        return self._to_dict()

    def verify_signature(self, signature, data):
        raise VerificationError("unsupported key") from UnsupportedAlgorithmError(
            "no implementation"
        )


class TestThresholdPolicy(unittest.TestCase):
    """Policy construction and configuration validation."""

    @classmethod
    def setUpClass(cls):
        cls.builder_signer = CryptoSigner.generate_ed25519()
        cls.auditor_signer = CryptoSigner.generate_rsa(size=2048)

    def _policy(self, groups=None, key_subjects=None):
        if key_subjects is None:
            key_subjects = {
                self.builder_signer.public_key: BUILDER,
                self.auditor_signer.public_key: AUDITOR,
            }
        if groups is None:
            groups = [
                ThresholdGroup("build", 1, [BUILDER]),
                ThresholdGroup("audit", 1, [AUDITOR]),
            ]
        return ThresholdPolicy(groups, key_subjects)

    def test_invalid_group_arguments(self):
        with self.assertRaises(ValueError):
            ThresholdGroup("", 1, [BUILDER])
        with self.assertRaises(ValueError):
            ThresholdGroup("build", 0, [BUILDER])
        with self.assertRaises(ValueError):
            ThresholdGroup("build", 1, [])
        with self.assertRaises(ValueError):
            ThresholdGroup("build", 2, [BUILDER])

    def test_invalid_policy_arguments(self):
        group = ThresholdGroup("build", 1, [BUILDER])
        key = self.builder_signer.public_key

        with self.assertRaises(ValueError):
            ThresholdPolicy([], {key: BUILDER})
        with self.assertRaises(ValueError):
            ThresholdPolicy([group], {})
        with self.assertRaises(ValueError):
            ThresholdPolicy([group], {key: ""})
        with self.assertRaises(ValueError):
            ThresholdPolicy([group], {"not-a-key": BUILDER})

    def test_group_names_must_be_unique(self):
        groups = [
            ThresholdGroup("build", 1, [BUILDER]),
            ThresholdGroup("build", 1, [AUDITOR]),
        ]
        key_subjects = {
            self.builder_signer.public_key: BUILDER,
            self.auditor_signer.public_key: AUDITOR,
        }
        with self.assertRaises(ValueError):
            ThresholdPolicy(groups, key_subjects)

    def test_group_principal_without_key_rejected(self):
        groups = [
            ThresholdGroup("build", 1, [BUILDER, "ghost"]),
            ThresholdGroup("audit", 1, [AUDITOR]),
        ]
        key_subjects = {
            self.builder_signer.public_key: BUILDER,
            self.auditor_signer.public_key: AUDITOR,
        }
        with self.assertRaises(ValueError):
            ThresholdPolicy(groups, key_subjects)

    def test_duplicate_configuration_collapses(self):
        # The same key listed repeatedly for the same subject is harmless.
        key = self.builder_signer.public_key
        key_subjects = {key: BUILDER}
        key_subjects[key] = BUILDER
        policy = ThresholdPolicy(
            [ThresholdGroup("build", 1, [BUILDER])],
            key_subjects,
        )
        self.assertEqual(len(policy._key_by_identity), 1)

    def test_same_public_key_different_subjects_rejected(self):
        # Same key material under a different keyid is still the same key.
        renamed = copy.deepcopy(self.builder_signer.public_key)
        renamed.keyid = "renamed-keyid"
        key_subjects = {
            self.builder_signer.public_key: BUILDER,
            renamed: OUTSIDER,
        }
        with self.assertRaises(AmbiguousKeyError):
            ThresholdPolicy(
                [
                    ThresholdGroup("build", 1, [BUILDER, OUTSIDER]),
                ],
                key_subjects,
            )

    def test_ambiguous_config_rejected_even_when_thresholds_met(self):
        # An invalid policy must be rejected before any envelope is seen.
        renamed = copy.deepcopy(self.builder_signer.public_key)
        renamed.keyid = "renamed-keyid"
        with self.assertRaises(AmbiguousKeyError):
            ThresholdPolicy(
                [
                    ThresholdGroup("build", 1, [BUILDER, OUTSIDER]),
                    ThresholdGroup("audit", 1, [AUDITOR]),
                ],
                {
                    self.builder_signer.public_key: BUILDER,
                    renamed: OUTSIDER,
                    self.auditor_signer.public_key: AUDITOR,
                },
            )


class TestVerifyPolicy(unittest.TestCase):
    """Envelope verification against group-threshold policies."""

    @classmethod
    def setUpClass(cls):
        cls.builder_signer = CryptoSigner.generate_ed25519()
        cls.builder_two_signer = CryptoSigner.generate_rsa(size=2048)
        cls.auditor_signer = CryptoSigner.generate_ed25519()
        cls.outsider_signer = CryptoSigner.generate_ed25519()

        cls.two_org_policy = ThresholdPolicy(
            [
                ThresholdGroup("build", 1, [BUILDER]),
                ThresholdGroup("audit", 1, [AUDITOR]),
            ],
            {
                cls.builder_signer.public_key: BUILDER,
                cls.auditor_signer.public_key: AUDITOR,
            },
        )

    def test_both_organizations_satisfy_policy(self):
        envelope = _envelope([self.builder_signer, self.auditor_signer])
        result = envelope.verify_policy(self.two_org_policy)

        self.assertTrue(result.satisfied)
        self.assertEqual(result.verified_subjects, {BUILDER, AUDITOR})
        groups = {group.name: group for group in result.groups}
        self.assertTrue(groups["build"].satisfied)
        self.assertTrue(groups["audit"].satisfied)
        self.assertEqual(groups["build"].observed, frozenset({BUILDER}))
        self.assertEqual(groups["audit"].observed, frozenset({AUDITOR}))

    def test_missing_audit_group_reports_what_is_missing(self):
        envelope = _envelope([self.builder_signer])
        with self.assertRaises(PolicyVerificationError) as ctx:
            envelope.verify_policy(self.two_org_policy)

        message = str(ctx.exception)
        self.assertIn("audit", message)
        self.assertIn("0/1", message)
        self.assertNotIn(PAYLOAD.decode(), message)
        self.assertNotIn("private", message.lower())

    def test_no_signatures_mentions_every_unsatisfied_group(self):
        envelope = Envelope(PAYLOAD, PAYLOAD_TYPE, {})
        with self.assertRaises(PolicyVerificationError) as ctx:
            envelope.verify_policy(self.two_org_policy)
        message = str(ctx.exception)
        self.assertIn("build", message)
        self.assertIn("audit", message)

    def test_unknown_key_is_distinguishable(self):
        envelope = _envelope([self.outsider_signer])
        with self.assertLogs("securesystemslib.policy", level=logging.INFO) as logs:
            with self.assertRaises(PolicyVerificationError):
                envelope.verify_policy(self.two_org_policy)

        self.assertTrue(
            any(UNKNOWN_KEY in entry for entry in logs.output),
            logs.output,
        )

    def test_bad_signature_is_distinguishable(self):
        envelope = _envelope([self.builder_signer])
        # Corrupt the signature bytes while keeping the trusted keyid.
        for signature in envelope.signatures.values():
            raw = bytearray.fromhex(signature.signature)
            raw[0] ^= 0xFF
            signature.signature = raw.hex()

        with self.assertLogs("securesystemslib.policy", level=logging.INFO) as logs:
            with self.assertRaises(PolicyVerificationError):
                envelope.verify_policy(self.two_org_policy)

        self.assertTrue(
            any(BAD_SIGNATURE in entry for entry in logs.output),
            logs.output,
        )

    def test_unsupported_algorithm_is_distinguishable(self):
        unsupported = UnsupportedKey("unsupported-keyid")
        envelope = _envelope([self.auditor_signer])
        # Add a signature claiming the unsupported key id.
        envelope.signatures["unsupported-keyid"] = Signature("unsupported-keyid", "00")
        policy = ThresholdPolicy(
            [
                ThresholdGroup("build", 1, [BUILDER]),
                ThresholdGroup("audit", 1, [AUDITOR, OUTSIDER]),
            ],
            {
                self.builder_signer.public_key: BUILDER,
                self.auditor_signer.public_key: AUDITOR,
                unsupported: OUTSIDER,
            },
        )

        with self.assertLogs("securesystemslib.policy", level=logging.INFO) as logs:
            with self.assertRaises(PolicyVerificationError):
                envelope.verify_policy(policy)

        self.assertTrue(
            any(UNSUPPORTED_ALGORITHM in entry for entry in logs.output),
            logs.output,
        )

    def test_well_formed_but_unverified_signature_not_counted(self):
        envelope = _envelope([self.outsider_signer])
        with self.assertRaises(PolicyVerificationError):
            verify_policy(
                envelope.pae(), envelope.signatures.values(), self.two_org_policy
            )

    def test_same_key_with_renamed_keyid_cannot_spoof_subject(self):
        # An envelope signed only by the builder relabels its signature with
        # the auditor's real keyid, trying to satisfy the audit group. Crypto
        # verification against the auditor key fails; the signature can only
        # ever prove the builder subject.
        envelope = _envelope([self.builder_signer])
        for signature in envelope.signatures.values():
            signature.keyid = self.auditor_signer.public_key.keyid

        policy = ThresholdPolicy(
            [
                ThresholdGroup("build", 1, [BUILDER]),
                ThresholdGroup("audit", 1, [AUDITOR]),
            ],
            {
                self.builder_signer.public_key: BUILDER,
                self.auditor_signer.public_key: AUDITOR,
            },
        )

        with self.assertRaises(PolicyVerificationError) as ctx:
            envelope.verify_policy(policy)
        self.assertIn("audit", str(ctx.exception))

    def test_subject_with_two_keys_is_counted_once(self):
        second_builder_key = copy.deepcopy(self.builder_signer.public_key)
        second_builder_key.keyid = "builder-second-keyid"

        policy = ThresholdPolicy(
            [
                ThresholdGroup("build", 2, [BUILDER, BUILDER_TWO]),
                ThresholdGroup("audit", 1, [AUDITOR]),
            ],
            {
                self.builder_signer.public_key: BUILDER,
                second_builder_key: BUILDER,
                self.builder_two_signer.public_key: BUILDER_TWO,
                self.auditor_signer.public_key: AUDITOR,
            },
        )

        # Two signatures from the same subject (via two key ids) plus audit.
        envelope = _envelope([self.builder_signer, self.auditor_signer])
        envelope.signatures["builder-second-keyid"] = Signature(
            "builder-second-keyid",
            # Same signature bytes, different self-reported keyid.
            next(iter(_envelope([self.builder_signer]).signatures.values())).signature,
        )

        with self.assertRaises(PolicyVerificationError) as ctx:
            envelope.verify_policy(policy)
        self.assertIn("build", str(ctx.exception))

        # Adding the genuinely distinct second builder makes it pass.
        envelope.sign(self.builder_two_signer)
        result = envelope.verify_policy(policy)
        self.assertTrue(result.satisfied)
        groups = {group.name: group for group in result.groups}
        self.assertEqual(groups["build"].observed, frozenset({BUILDER, BUILDER_TWO}))

    def test_duplicate_signature_counts_once(self):
        envelope = _envelope([self.builder_signer, self.auditor_signer])
        signature = next(iter(envelope.signatures.values()))
        # Envelope.from_dict rejects duplicate keyids, so emulate a repeated
        # raw signature by passing the same signature twice to the entry point.
        with self.assertRaises(PolicyVerificationError):
            verify_policy(
                envelope.pae(),
                [signature, signature],
                ThresholdPolicy(
                    [
                        ThresholdGroup("build", 2, [BUILDER, BUILDER_TWO]),
                        ThresholdGroup("audit", 1, [AUDITOR]),
                    ],
                    {
                        self.builder_signer.public_key: BUILDER,
                        self.builder_two_signer.public_key: BUILDER_TWO,
                        self.auditor_signer.public_key: AUDITOR,
                    },
                ),
            )

    def test_pae_binds_payload_and_payload_type(self):
        envelope = _envelope([self.builder_signer, self.auditor_signer])
        tampered = Envelope(b"different payload", PAYLOAD_TYPE, envelope.signatures)
        with self.assertRaises(PolicyVerificationError):
            tampered.verify_policy(self.two_org_policy)

        tampered_type = Envelope(
            PAYLOAD, "application/vnd.other+json", envelope.signatures
        )
        with self.assertRaises(PolicyVerificationError):
            tampered_type.verify_policy(self.two_org_policy)

    def test_original_verify_behavior_unchanged(self):
        envelope = _envelope([self.builder_signer, self.auditor_signer])
        keys = [
            self.builder_signer.public_key,
            self.auditor_signer.public_key,
        ]
        accepted = envelope.verify(keys, 2)
        self.assertEqual(len(accepted), 2)

    def test_subject_membership_in_multiple_groups(self):
        # A subject may belong to more than one group; a single signature
        # counts in each group it belongs to.
        signer = self.builder_signer
        policy = ThresholdPolicy(
            [
                ThresholdGroup("build", 1, [BUILDER]),
                ThresholdGroup("release", 1, [BUILDER]),
            ],
            {signer.public_key: BUILDER},
        )
        envelope = _envelope([signer])
        result = envelope.verify_policy(policy)
        self.assertTrue(result.satisfied)
        for group in result.groups:
            self.assertEqual(group.observed, frozenset({BUILDER}))


if __name__ == "__main__":
    unittest.main()
