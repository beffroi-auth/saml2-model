<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Metadata;

/**
 * SAML Bindings §3.4, §3.5
 */
enum Binding: string
{
    case HttpRedirect = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
    case HttpPost = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
}
