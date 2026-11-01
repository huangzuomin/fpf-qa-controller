# Controller Governance

## Authority and separation

The Controller is a separate repository and execution plane from the FPF
Candidate repository. Changes to this repository, its specification, harness,
workflow, or branch protection require Controller maintenance authority.

Candidate DEV identities and automation may submit the repository and immutable
SHA to be tested. They may not modify the Controller, its dispatch definition,
its trusted tests, its evaluator, its decision rules, or its attestation.

## Roles

| Role | Current identity | Responsibility |
| --- | --- | --- |
| Controller maintainer | `huangzuomin` (repository owner) | protect `main`, approve controller changes, maintain Controller authority |
| QA dispatcher | authenticated GitHub actor | dispatch an exact Candidate repository and SHA |
| Candidate author | external repository actor | candidate code only; no Controller write authority |
| Evaluator | Controller workflow | derive the verdict from trusted specification and raw host evidence |

The coordinator can build and operate this Controller under delegated authority.
That operational role does not make a Candidate self-approving.

## Immutable bindings

Every QA result must bind:

- Controller repository;
- Controller branch and actual commit SHA;
- trusted specification hash;
- Candidate repository;
- Candidate commit SHA;
- candidate source-tree digest;
- pinned container image digest;
- workflow run and attempt identifiers;
- raw test result names, statuses, and exit codes;
- raw host exit code and logs;
- verified evidence manifest hash; and
- attestation verification result.

A mismatch or missing field is rejected.

## Test-source rule

The Controller owns the authoritative test suite. Candidate tests may be run as
supporting evidence, but they cannot determine the Controller verdict. This
prevents a Candidate from passing by deleting, weakening, or replacing its own
tests.

For a Candidate-quality run, `mode=candidate` executes both the exact target
module and the full discovered unittest suite in the same hardened,
network-disabled container. The evaluator requires their exact executed counts,
clean exit codes, zero failures, zero errors, and zero skips. These executions
remain supporting evidence; the Controller-owned assertions and independent QA
authority still decide the final verdict.

## Attestation rule

GitHub/Sigstore attestation proves artifact origin and integrity. It does not by
itself prove semantic correctness. The final verdict therefore requires both:

1. Controller-owned evaluation of raw execution evidence; and
2. successful verification of the signed QA bundle against the Controller
   repository and workflow identity.
