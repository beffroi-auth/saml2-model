<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Protocol;

/**
 * SAML Core §3.2.2.2
 *
 * The vocabulary is open: tryFromUri() reads an unknown URI as null rather than refusing it.
 */
enum SecondLevelStatusCode: string
{
    case AuthnFailed = 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed';
    case InvalidAttrNameOrValue = 'urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue';
    case InvalidNameIdPolicy = 'urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy';
    case NoAuthnContext = 'urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext';
    case NoAvailableIdp = 'urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP';
    case NoPassive = 'urn:oasis:names:tc:SAML:2.0:status:NoPassive';
    case NoSupportedIdp = 'urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP';
    case PartialLogout = 'urn:oasis:names:tc:SAML:2.0:status:PartialLogout';
    case ProxyCountExceeded = 'urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded';
    case RequestDenied = 'urn:oasis:names:tc:SAML:2.0:status:RequestDenied';
    case RequestUnsupported = 'urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported';
    case RequestVersionDeprecated = 'urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated';
    case RequestVersionTooHigh = 'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh';
    case RequestVersionTooLow = 'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow';
    case ResourceNotRecognized = 'urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized';
    case TooManyResponses = 'urn:oasis:names:tc:SAML:2.0:status:TooManyResponses';
    case UnknownAttrProfile = 'urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile';
    case UnknownPrincipal = 'urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal';
    case UnsupportedBinding = 'urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding';

    public static function tryFromUri(string $uri): ?self
    {
        return self::tryFrom($uri);
    }
}
