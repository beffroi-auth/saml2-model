# Security policy

This package decides, for an identity provider or a service provider, which element of a SAML message a signature
had to cover, whose key had to sign it, and whether an assertion is addressed to it, still valid and seen for the first
time: a flaw here is an authentication bypass in every application that trusts what the package accepts.

## Reporting

Report privately through [GitHub security advisories](https://github.com/beffroi-php/saml2-model/security/advisories/new).
Do not open a public issue, do not discuss it in a pull request.

You will get an acknowledgement within 72 hours, and a fix or a mitigation plan as fast as the severity requires.
Credit is given in the advisory unless you prefer otherwise.

A flaw of the XML layer below, the loader, the canonicalization, XML Signature or XML Encryption, belongs to
[`beffroi-php/xml-security`](https://github.com/beffroi-php/xml-security/security/advisories/new). When you cannot
tell which package it belongs to, report it here.

## What is published

Every security fix ships with a GitHub Security Advisory and a CVE requested for it, so that `composer audit`,
Packagist and the advisory databases see it (`spec/model.md`, section 10).

## Scope

Anything in this repository: the readers, the validators, the writers, the tooling and the CI. The rules the package
enforces are the invariants M-1 to M-17 of `spec/model.md`, section 4; a way to defeat one of them with input, without
a code change, is a vulnerability: a value read outside what a signature covers (M-1), an assertion accepted without
the signature the profile requires (M-2), a key taken from the message (M-3), an assertion accepted for another
audience, another endpoint or another request (M-8 to M-10), accepted twice (M-11), or after its window (M-7). A
refusal message that carries a value of the message is one too (M-16).

Out of scope: a consumer that calls what section 8 of the specification bans, which the PHPStan rules of this
repository exist to prevent; one that states a wrong expectation (the URL at which a message arrived, the ID of the
request it answers), reads with `MetadataReader::readTrusted()` metadata from a channel it does not trust, or
implements the replay port with a store that is not atomic or not shared by its workers (section 5.2); the HTTP
bindings, which are [`beffroi-php/saml2-bindings`](https://github.com/beffroi-php/saml2-bindings).

## Supported versions

Until the first tagged release, `main` only. From `1.0.0`, the latest minor of the latest major.
