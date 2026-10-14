# Security

## Reporting a vulnerability

Please report it privately, through GitHub's "Report a vulnerability" button on the Security tab of this repository. Do not open a public issue for something that could help a censor or an attacker.

Include what you found, how to reproduce it, and what it lets an attacker do. I will answer within a week.

## What counts

- A way to tell a bridge from its cover site without the bridge key.
- A way to recover or guess a private key or a token.
- A flaw that lets a replayed or crafted connection reach the ORPort.
- A secret in a log, a bridge line, or published arguments.
- A flaw in the release pipeline, the Docker image, or the packages.

## What does not

The limits written down in [docs/threat-model.md](docs/threat-model.md) are known. A report that only restates one of them is welcome as an idea but is not a vulnerability.

## Releases

Release archives are checksummed and signed with cosign, carry an SBOM, and have build provenance attached. See the Releases page.
