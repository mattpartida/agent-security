# Security Policy

## Supported versions

This repository is currently pre-1.0. Security fixes are made on the `main` branch and included in the next tagged release.

## Reporting a vulnerability

If you find a vulnerability in the skillpack, helper scripts, examples, CI workflow, or packaged `.skill` artifacts, please open a private report through GitHub's vulnerability reporting flow if available, or contact the maintainer through the GitHub profile.

Please include:

- affected file, script, or workflow
- reproduction steps
- expected vs. actual behavior
- impact assessment
- any safe proof-of-concept input

Do **not** include real secrets, private keys, production credentials, or non-consensual data in reports.

## What counts as a security issue

Examples:

- a helper script that executes untrusted input
- a bypass in prompt-injection signal detection that affects documented guarantees
- incorrect high-risk config scoring that can hide a dangerous tool combination
- packaged skill contents that broaden permissions or weaken approval guidance unexpectedly
- CI or packaging behavior that publishes stale or unsafe artifacts

## Test content warning

This repository intentionally contains benign prompt-injection examples and fake malicious instructions for defensive testing. Treat all examples, fixtures, and copied test strings as untrusted data. Do not connect test prompts to real outbound tools, real credentials, or production agent runtimes without sandboxing and explicit approval gates.

## Disclosure expectations

This project provides defensive guidance and dependency-light analysis helpers. It does not claim to provide complete protection against prompt injection, tool misuse, or agent compromise. Reports that improve detection, documentation, or safe defaults are welcome.
