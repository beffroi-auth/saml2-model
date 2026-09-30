<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Metadata;

/**
 * The two bindings an endpoint of the package is kept on (section 5.3, M-5): HTTP-Redirect and HTTP-POST (SAML
 * Bindings §3.4, §3.5). An endpoint on any other, Artifact, SOAP or PAOS, is dropped when metadata is read, so that a
 * real metadata listing them still loads (section 6.5 step 6); an assertion consumer service is kept on HTTP-POST only.
 */
enum Binding: string
{
    case HttpRedirect = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
    case HttpPost = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
}
