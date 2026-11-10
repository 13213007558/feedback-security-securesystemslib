"""Demo: group-threshold release approval policy on a DSSE envelope.

Run from the repository root:

    python examples/policy_verification_demo.py

The release policy requires two independent conditions:

* at least one signature from the "build" group, and
* at least one signature from the "audit" group.

All keys are generated locally (Ed25519 and RSA). The output only reports
verified subjects, per-group status and failure reasons; it never prints
private keys or the envelope payload.
"""

from __future__ import annotations

import copy
import logging

from securesystemslib.dsse import Envelope
from securesystemslib.policy import (
    AmbiguousKeyError,
    PolicyVerificationError,
    ThresholdGroup,
    ThresholdPolicy,
)
from securesystemslib.signer import CryptoSigner, Signature

logging.basicConfig(level=logging.INFO, format="  log: %(message)s")

BUILDER = "builder-org"
BUILDER_TWO = "second-builder"
AUDITOR = "auditor-org"
IMPERSONATOR = "impersonator"


def heading(title: str) -> None:
    print(f"\n=== {title} ===")


def show_result(result) -> None:
    print(f"verified subjects: {sorted(result.verified_subjects)}")
    for group in result.groups:
        status = "OK" if group.satisfied else "MISSING"
        print(
            f"  group {group.name!r}: {len(group.observed)}/{group.threshold}"
            f" distinct subjects -> {status}"
        )


def main() -> None:
    # Local, in-memory key generation: Ed25519 and RSA.
    builder_signer = CryptoSigner.generate_ed25519()
    second_builder_signer = CryptoSigner.generate_rsa(size=2048)
    auditor_signer = CryptoSigner.generate_ed25519()

    payload = b"release artifact (content hidden from demo output)"
    payload_type = "application/vnd.example.release+json"
    envelope = Envelope(payload, payload_type, {})
    envelope.sign(builder_signer)
    envelope.sign(auditor_signer)

    # ------------------------------------------------------------------
    # Scenario 1: both organizations sign -> policy satisfied.
    # ------------------------------------------------------------------
    heading("1. two organizations meet the policy (Ed25519 + RSA/Ed25519)")
    policy = ThresholdPolicy(
        groups=[
            ThresholdGroup("build", 1, [BUILDER]),
            ThresholdGroup("audit", 1, [AUDITOR]),
        ],
        key_subjects={
            builder_signer.public_key: BUILDER,
            auditor_signer.public_key: AUDITOR,
        },
    )
    show_result(envelope.verify_policy(policy))

    # ------------------------------------------------------------------
    # Scenario 2: same public key, renamed keyid, assigned to a new
    # subject in trusted configuration -> ambiguous config rejected up front.
    # ------------------------------------------------------------------
    heading("2. same key renamed and assigned to another subject -> rejected")
    renamed_key = copy.deepcopy(builder_signer.public_key)
    renamed_key.keyid = "renamed-keyid"
    try:
        ThresholdPolicy(
            groups=[
                ThresholdGroup("build", 1, [BUILDER, IMPERSONATOR]),
                ThresholdGroup("audit", 1, [AUDITOR]),
            ],
            key_subjects={
                builder_signer.public_key: BUILDER,
                renamed_key: IMPERSONATOR,
                auditor_signer.public_key: AUDITOR,
            },
        )
    except AmbiguousKeyError as error:
        print(f"rejected before touching the envelope: {error}")

    # Variant: an envelope signed only by the builder relabels that signature
    # with the auditor's real keyid, trying to pass the audit group. Crypto
    # verification against the auditor key fails; the signature can only ever
    # prove the builder, so the audit group stays unsatisfied.
    heading("2b. builder-only signature relabeled as auditor keyid -> fails")
    builder_only = Envelope(payload, payload_type, {})
    builder_only.sign(builder_signer)
    for signature in builder_only.signatures.values():
        signature.keyid = auditor_signer.public_key.keyid
    try:
        builder_only.verify_policy(policy)
    except PolicyVerificationError as error:
        print(f"verification failed: {error}")

    # ------------------------------------------------------------------
    # Scenario 3: one subject with two keys counts once.
    # ------------------------------------------------------------------
    heading("3. same subject with two keys is not double-counted")
    builder_second_key = copy.deepcopy(builder_signer.public_key)
    builder_second_key.keyid = "builder-second-keyid"
    two_builder_policy = ThresholdPolicy(
        groups=[
            ThresholdGroup("build", 2, [BUILDER, BUILDER_TWO]),
            ThresholdGroup("audit", 1, [AUDITOR]),
        ],
        key_subjects={
            builder_signer.public_key: BUILDER,
            builder_second_key: BUILDER,
            second_builder_signer.public_key: BUILDER_TWO,
            auditor_signer.public_key: AUDITOR,
        },
    )

    # Re-sign the same envelope with a second keyid of the same subject.
    builder_sig = next(
        sig
        for sig in envelope.signatures.values()
        if sig.keyid == builder_signer.public_key.keyid
    )
    envelope.signatures["builder-second-keyid"] = Signature(
        "builder-second-keyid", builder_sig.signature
    )
    try:
        envelope.verify_policy(two_builder_policy)
    except PolicyVerificationError as error:
        print(f"still one builder subject: {error}")

    # A genuinely distinct second builder makes the threshold pass.
    envelope.sign(second_builder_signer)
    show_result(envelope.verify_policy(two_builder_policy))

    print("\nDemo finished: no private key material or payload was printed.")


if __name__ == "__main__":
    main()
