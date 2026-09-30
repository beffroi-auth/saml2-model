<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Validation;

/**
 * How a protocol message the validators accepted was authenticated (section 5.6, M-2): by a ds:Signature of the
 * message, verified here under the keys of the peer's metadata (M-3); by the signature of the HTTP-Redirect binding
 * over its query string, which saml2-bindings verified before calling (section 6.8); or by nothing, an AuthnRequest
 * that the metadata of neither party asks to be signed (Profiles §4.1.6).
 */
enum Authentication
{
    case XmlSignature;
    case Binding;
    case None;
}
