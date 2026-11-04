<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Value;

use Beffroi\Saml2\Model\Exception\LimitExceeded;

/**
 * Section 7, M-17
 */
final readonly class Counts
{
    public const int AUDIENCE_RESTRICTIONS = 8;

    public const int AUDIENCES = 16;

    public const int ATTRIBUTES = 256;

    public const int ATTRIBUTE_VALUES = 256;

    public const int SESSION_INDEXES = 16;

    public const int AUTHN_CONTEXT_CLASS_REFS = 16;

    /**
     * Per role, as many as Dsig's maxVerificationKeys (dsig.md section 7).
     */
    public const int SIGNING_CERTIFICATES = 16;

    public const int ENCRYPTION_CERTIFICATES = 16;

    /**
     * Per role and kind, the endpoints the reader drops counted.
     */
    public const int ENDPOINTS = 64;

    /**
     * Per role, the formats the reader drops counted.
     */
    public const int NAME_ID_FORMATS = 16;

    /**
     * @param int $count counted before anything iterates over the list
     * @param string $message the bound named, never a value of the list (M-16)
     *
     * @throws LimitExceeded
     */
    public static function check(int $count, int $bound, string $message): void
    {
        if ($count > $bound) {
            throw new LimitExceeded($message);
        }
    }
}
