<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Value;

use Beffroi\Saml2\Model\Exception\LimitExceeded;

/**
 * The counts of section 7, in one place (M-17): the readers check each before they iterate over its list, and the
 * objects of section 5.3 whoever builds them, so that a writer never writes a list the peer's reader would refuse by
 * count (M-15). Each is a constant of the package until a real document needs more, and raising one is a change of
 * the specification, never a parameter.
 */
final readonly class Counts
{
    /** AudienceRestriction per Conditions. */
    public const int AUDIENCE_RESTRICTIONS = 8;

    /** Audience per AudienceRestriction. */
    public const int AUDIENCES = 16;

    /** Attribute per AttributeStatement. */
    public const int ATTRIBUTES = 256;

    /** AttributeValue per Attribute. */
    public const int ATTRIBUTE_VALUES = 256;

    /** SessionIndex per LogoutRequest. */
    public const int SESSION_INDEXES = 16;

    /** AuthnContextClassRef per RequestedAuthnContext. */
    public const int AUTHN_CONTEXT_CLASS_REFS = 16;

    /** Signing certificates per role, Dsig's maxVerificationKeys (dsig.md section 7). */
    public const int SIGNING_CERTIFICATES = 16;

    /** Encryption certificates per role. */
    public const int ENCRYPTION_CERTIFICATES = 16;

    /** Endpoints of one kind per role, the dropped ones counted. */
    public const int ENDPOINTS = 64;

    /** NameIDFormat per role, the dropped ones counted. */
    public const int NAME_ID_FORMATS = 16;

    /**
     * @param int $count how many a list holds, counted before anything iterates over it
     * @param int $bound one of the constants above
     * @param string $message the bound named, never a value of the list (M-16)
     *
     * @throws LimitExceeded when the count is over the bound (M-17)
     */
    public static function check(int $count, int $bound, string $message): void
    {
        if ($count > $bound) {
            throw new LimitExceeded($message);
        }
    }
}
