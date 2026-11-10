Group-Threshold Policy
======================

.. currentmodule:: securesystemslib.policy

The policy module verifies a DSSE envelope against independent per-group
signature requirements. A plain :meth:`securesystemslib.dsse.Envelope.verify`
call supports only one overall threshold; it cannot express conditions such as
"at least one signature from the build group **and** at least one signature
from the audit group".

A policy is built from trusted caller configuration only:

* trusted public keys,
* subject identifiers, and
* the group each subject belongs to, with a per-group minimum number of
  distinct subjects.

Roles or key ids claimed inside an envelope are never trusted on their own.
A valid signature proves that its subject participated, but a subject is
counted at most once per group even when it controls several keys. Repeated
signatures or repeated configuration entries never create additional
independent subjects. If the same public key is assigned to different
subjects in the trusted configuration, the policy is rejected up front with
:class:`AmbiguousKeyError`, even when the envelope itself would meet every
threshold.

Usage
-----

.. code-block:: python

    from securesystemslib.dsse import Envelope
    from securesystemslib.policy import ThresholdGroup, ThresholdPolicy

    policy = ThresholdPolicy(
        groups=[
            ThresholdGroup("build", 1, ["builder-org"]),
            ThresholdGroup("audit", 1, ["auditor-org"]),
        ],
        key_subjects={
            builder_key: "builder-org",
            auditor_key: "auditor-org",
        },
    )

    result = envelope.verify_policy(policy)

On success, the result reports only the verified subjects and, for each
group, how many distinct verified subjects were observed. When a threshold is
not met, :class:`PolicyVerificationError` names the unsatisfied groups and
the missing counts; it never includes payload contents or private key
material.

Verification details
--------------------

Every signature is checked against the PAE bytes that authenticate the
original payload type and payload. Signatures are matched to trusted keys by
public key material, so renaming a key id cannot turn one key or subject into
another. Signatures that cannot be accepted get distinguishable reasons:

* ``UNKNOWN_KEY``: no trusted key matches the signature,
* ``BAD_SIGNATURE``: a trusted key matched but the signature is invalid,
* ``UNSUPPORTED_ALGORITHM``: a trusted key uses an algorithm that cannot be
  verified in this environment.

These reasons are emitted through the ``securesystemslib.policy`` logger and
carried by :class:`SignatureFailure`.

API
---

.. autoclass:: ThresholdGroup
   :members:

.. autoclass:: ThresholdPolicy
   :members:

.. autoclass:: GroupVerificationResult
   :members:

.. autoclass:: PolicyVerificationResult
   :members:

.. autoclass:: SignatureFailure
   :members:

.. autofunction:: verify_policy

.. exception:: PolicyError

   Base class for policy configuration and verification errors.

.. exception:: AmbiguousKeyError

   A trusted public key is assigned to more than one subject.

.. exception:: PolicyVerificationError

   The verified signatures do not satisfy the group thresholds.
