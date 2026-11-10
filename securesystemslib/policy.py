"""Group-threshold signature policy for DSSE envelopes.

Provides an explicit policy verification entry point that expresses
independent per-group signature requirements, e.g. "at least one signature
from the build group and at least one signature from the audit group". This
cannot be expressed with :meth:`securesystemslib.dsse.Envelope.verify`, which
only supports a single overall threshold.

The policy is built solely from trusted caller-provided configuration:
trusted public keys, subject identifiers and the group each subject belongs
to. Roles or identities claimed inside the envelope are never consulted.

A subject is counted at most once per group even if it controls several
keys, and repeated signatures or repeated configuration entries never create
additional independent subjects. A public key that is assigned to different
subjects in the trusted configuration is ambiguous and rejected when the
policy is constructed.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from securesystemslib.exceptions import (
    UnsupportedAlgorithmError,
    UnsupportedLibraryError,
    UnverifiedSignatureError,
    VerificationError,
)
from securesystemslib.signer import Key, Signature

logger = logging.getLogger(__name__)

__all__ = [
    "BAD_SIGNATURE",
    "UNSUPPORTED_ALGORITHM",
    "UNKNOWN_KEY",
    "AmbiguousKeyError",
    "GroupVerificationResult",
    "PolicyError",
    "PolicyVerificationError",
    "PolicyVerificationResult",
    "SignatureFailure",
    "ThresholdGroup",
    "ThresholdPolicy",
    "verify_policy",
]

#: Envelope signature cannot be matched to any trusted key.
UNKNOWN_KEY = "unknown_key"
#: Envelope signature matched a trusted key but failed verification.
BAD_SIGNATURE = "bad_signature"
#: A trusted key uses an algorithm/scheme that cannot be verified here.
UNSUPPORTED_ALGORITHM = "unsupported_algorithm"


class PolicyError(Exception):
    """Base class for policy configuration and verification errors."""


class AmbiguousKeyError(PolicyError):
    """A trusted public key is assigned to more than one subject."""


class PolicyVerificationError(PolicyError):
    """The verified signatures do not satisfy the group thresholds.

    The message names the groups that are still missing signatures; it never
    contains private key material or the envelope payload.
    """


@dataclass(frozen=True)
class SignatureFailure:
    """Diagnostic for one envelope signature that could not be verified.

    Attributes:
        keyid: Key id claimed by the signature.
        reason: One of ``UNKNOWN_KEY``, ``BAD_SIGNATURE`` and
            ``UNSUPPORTED_ALGORITHM``.
    """

    keyid: str
    reason: str

    def __str__(self) -> str:
        return f"signature for keyid {self.keyid!r} not accepted: {self.reason}"


@dataclass(frozen=True)
class ThresholdGroup:
    """A named group of subjects with a minimum number of distinct subjects.

    Args:
        name: Unique group name.
        threshold: Minimum number of distinct verified subjects required.
        principals: Subject identifiers that belong to the group.

    Raises:
        ValueError: If arguments are malformed or the threshold is not
            reachable with the given principals.
    """

    name: str
    threshold: int
    principals: frozenset[str]

    def __init__(
        self,
        name: str,
        threshold: int,
        principals: Iterable[str],
    ):
        if not isinstance(name, str) or not name:
            raise ValueError("Group name must be a non-empty string")

        if not isinstance(threshold, int) or threshold <= 0:
            raise ValueError(f"Threshold for group {name!r} must be a positive integer")

        principals_set = frozenset(principals)
        if not principals_set or not all(
            isinstance(principal, str) and principal for principal in principals_set
        ):
            raise ValueError(f"Group {name!r} requires non-empty string principals")

        if threshold > len(principals_set):
            raise ValueError(
                f"Threshold {threshold} for group {name!r} exceeds number of"
                f" principals {len(principals_set)}"
            )

        object.__setattr__(self, "name", name)
        object.__setattr__(self, "threshold", threshold)
        object.__setattr__(self, "principals", principals_set)


@dataclass(frozen=True)
class ThresholdPolicy:
    """Trusted policy describing groups, subjects and their public keys.

    All information comes from trusted caller configuration; the envelope
    itself is never queried for roles or identities.

    Args:
        groups: Groups with their thresholds and member subjects.
        key_subjects: Mapping of each trusted public key to the single
            subject that controls it. A subject may own several keys.

    Raises:
        AmbiguousKeyError: If the same public key is assigned to different
            subjects.
        ValueError: If the configuration references unknown principals,
            leaves a group without any usable key, or is otherwise invalid.
    """

    groups: frozenset[ThresholdGroup]
    key_subjects: Mapping[Key, str]

    # Indexes built once from the trusted configuration.
    _key_by_identity: dict[object, Key] = field(
        default_factory=dict, init=False, repr=False
    )
    _subject_by_identity: dict[object, str] = field(
        default_factory=dict, init=False, repr=False
    )
    _subjects_by_group: dict[str, frozenset[str]] = field(
        default_factory=dict, init=False, repr=False
    )

    def __init__(
        self,
        groups: Iterable[ThresholdGroup],
        key_subjects: Mapping[Key, str],
    ):
        groups_set = frozenset(groups)
        if not groups_set:
            raise ValueError("At least one threshold group is required")

        group_names = [group.name for group in groups_set]
        if len(group_names) != len(set(group_names)):
            raise ValueError("Group names must be unique")

        if not key_subjects:
            raise ValueError("At least one trusted key is required")

        subjects_with_keys: dict[str, None] = {}
        key_by_identity: dict[object, Key] = {}
        subject_by_identity: dict[object, str] = {}

        for key, subject in key_subjects.items():
            if not isinstance(key, Key):
                raise ValueError(f"Trusted key has invalid type: {type(key)!r}")
            if not isinstance(subject, str) or not subject:
                raise ValueError("Key subjects must be non-empty strings")

            subjects_with_keys.setdefault(subject, None)
            identity = _key_identity(key)

            other_subject = subject_by_identity.get(identity)
            if other_subject is not None and other_subject != subject:
                raise AmbiguousKeyError(
                    f"Public key {key.keyid!r} is assigned to multiple"
                    f" subjects: {other_subject!r} and {subject!r}"
                )

            subject_by_identity[identity] = subject
            key_by_identity.setdefault(identity, key)

        subjects_by_group: dict[str, frozenset[str]] = {}
        for group in groups_set:
            unknown = group.principals - subjects_with_keys.keys()
            if unknown:
                raise ValueError(
                    f"Group {group.name!r} references principals without"
                    f" trusted keys: {sorted(unknown)}"
                )
            subjects_by_group[group.name] = group.principals

        object.__setattr__(self, "groups", groups_set)
        object.__setattr__(self, "key_subjects", dict(key_subjects))
        object.__setattr__(self, "_key_by_identity", key_by_identity)
        object.__setattr__(self, "_subject_by_identity", subject_by_identity)
        object.__setattr__(self, "_subjects_by_group", subjects_by_group)


@dataclass(frozen=True)
class GroupVerificationResult:
    """Verification outcome for one group.

    Attributes:
        name: Group name.
        threshold: Required number of distinct verified subjects.
        observed: Distinct verified subjects from the group. Only subjects
            proven by a valid signature are listed.
    """

    name: str
    threshold: int
    observed: frozenset[str]

    @property
    def satisfied(self) -> bool:
        """Whether the group threshold is met."""
        return len(self.observed) >= self.threshold


@dataclass(frozen=True)
class PolicyVerificationResult:
    """Outcome of a policy verification.

    Only verified subjects and per-group satisfaction are reported; entries
    that merely parse correctly are not treated as signed.

    Attributes:
        verified_subjects: Distinct subjects proven by valid signatures.
        groups: Per-group verification results.
    """

    verified_subjects: frozenset[str]
    groups: tuple[GroupVerificationResult, ...]

    @property
    def satisfied(self) -> bool:
        """Whether every group threshold is met."""
        return all(group.satisfied for group in self.groups)


def _key_identity(key: Key) -> object:
    """Return an identifier of the public key itself.

    The key id is deliberately excluded: the same public key under a
    different key id must still be recognized as the same key. The scheme is
    included so that a raw public value under a different (possibly
    unsupported) scheme remains a distinct entry.
    """

    return key.keytype, key.scheme, key.keyval.get("public")


def _failure_reason(error: UnverifiedSignatureError) -> str:
    """Map a verification exception to a distinguishable reason code."""

    cause = error.__cause__
    if isinstance(error, VerificationError) and (
        isinstance(cause, UnsupportedAlgorithmError | UnsupportedLibraryError)
        or (isinstance(cause, ValueError) and "Unsupported public key" in str(cause))
    ):
        return UNSUPPORTED_ALGORITHM
    return BAD_SIGNATURE


def verify_policy(
    pae: bytes,
    signatures: Iterable[Signature],
    policy: ThresholdPolicy,
) -> PolicyVerificationResult:
    """Verify signatures against a group-threshold policy.

    Every signature is checked against the PAE bytes that authenticate the
    original payload type and payload. Signatures are matched to trusted keys
    by public key material; the key id claimed in a signature is never trusted
    on its own.

    Args:
        pae: Pre-Auth-Encoding bytes of the envelope (see
            :meth:`securesystemslib.dsse.Envelope.pae`).
        signatures: Envelope signatures to verify.
        policy: Trusted group-threshold policy.

    Raises:
        PolicyVerificationError: If a group threshold is not met. The error
            names the unsatisfied groups and how many subjects are missing.

    Returns:
        A :class:`PolicyVerificationResult` containing only verified subjects
        and per-group satisfaction details.
    """

    failures: list[SignatureFailure] = []
    verified_subjects: set[str] = set()
    # Track which envelope signatures already proved a given key, so a
    # repeated signature never counts twice.
    verified_identities: set[object] = set()

    trusted_keys = list(policy._key_by_identity.values())

    for signature in signatures:
        matching = [key for key in trusted_keys if key.keyid == signature.keyid]
        others = [key for key in trusted_keys if key.keyid != signature.keyid]

        accepted_key: Key | None = None
        unsupported_seen = False

        # Try keys whose key id matches first: a failure there is a real
        # cryptographic failure rather than an unrecognized key id.
        for key in matching + others:
            # Re-sign the envelope signature with the trusted key id: key id
            # matching is handled here, not inside the crypto verification.
            candidate = Signature(key.keyid, signature.signature)
            try:
                key.verify_signature(candidate, pae)
            except UnverifiedSignatureError as error:
                reason = _failure_reason(error)
                unsupported_seen = unsupported_seen or reason == UNSUPPORTED_ALGORITHM
                continue

            identity = _key_identity(key)
            if identity not in verified_identities:
                verified_identities.add(identity)
                verified_subjects.add(policy._subject_by_identity[identity])
            accepted_key = key
            break

        if accepted_key is None:
            if unsupported_seen:
                reason = UNSUPPORTED_ALGORITHM
            elif matching:
                reason = BAD_SIGNATURE
            else:
                reason = UNKNOWN_KEY
            failure = SignatureFailure(signature.keyid, reason)
            failures.append(failure)
            logger.info("Policy verification rejected %s", failure)

    group_results: list[GroupVerificationResult] = []
    unsatisfied: list[str] = []
    for group in sorted(policy.groups, key=lambda group: group.name):
        observed = frozenset(policy._subjects_by_group[group.name] & verified_subjects)
        group_results.append(
            GroupVerificationResult(group.name, group.threshold, observed)
        )
        if len(observed) < group.threshold:
            unsatisfied.append(
                f"{group.name!r} (have {len(observed)}/{group.threshold})"
            )

    result = PolicyVerificationResult(
        verified_subjects=frozenset(verified_subjects),
        groups=tuple(group_results),
    )

    if unsatisfied:
        raise PolicyVerificationError(
            "Policy thresholds not met; missing signatures from groups: "
            + ", ".join(unsatisfied)
        )

    return result
