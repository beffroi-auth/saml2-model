<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model;

/**
 * The names of SAML 2.0 (section 5.1): the three namespaces of the assertion, the protocol and the metadata, and the
 * one version a message carries (M-6).
 */
final class Saml
{
    public const string ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';

    public const string PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';

    public const string METADATA = 'urn:oasis:names:tc:SAML:2.0:metadata';

    public const string VERSION = '2.0';
}
