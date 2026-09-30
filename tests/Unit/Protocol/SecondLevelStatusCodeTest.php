<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Protocol;

use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use function array_map;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3: the second-level status codes of SAML Core §3.2.2.2, an open vocabulary read as null when unknown.
 */
final class SecondLevelStatusCodeTest extends TestCase
{
    /**
     * SAML Core §3.2.2.2: the nineteen second-level codes the specification lists.
     */
    #[Test]
    public function itHoldsTheNineteenSecondLevelCodesOfSamlCore(): void
    {
        // When
        $uris = array_map(
            static fn (SecondLevelStatusCode $code): string => $code->value,
            SecondLevelStatusCode::cases(),
        );

        // Then
        static::assertSame(
            [
                'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed',
                'urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue',
                'urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy',
                'urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext',
                'urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP',
                'urn:oasis:names:tc:SAML:2.0:status:NoPassive',
                'urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP',
                'urn:oasis:names:tc:SAML:2.0:status:PartialLogout',
                'urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded',
                'urn:oasis:names:tc:SAML:2.0:status:RequestDenied',
                'urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported',
                'urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated',
                'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh',
                'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow',
                'urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized',
                'urn:oasis:names:tc:SAML:2.0:status:TooManyResponses',
                'urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile',
                'urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal',
                'urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding',
            ],
            $uris,
        );
    }

    #[Test]
    #[DataProvider('provideCodes')]
    public function itReadsEachCodeFromItsUri(SecondLevelStatusCode $code): void
    {
        // When / Then
        static::assertSame($code, SecondLevelStatusCode::tryFromUri($code->value));
    }

    /**
     * @return iterable<string, array{SecondLevelStatusCode}>
     */
    public static function provideCodes(): iterable
    {
        foreach (SecondLevelStatusCode::cases() as $code) {
            yield $code->name => [$code];
        }
    }

    /**
     * SAML Core §3.2.2.2: system entities define codes of their own; a code SAML Core does not list reads as null,
     * compared byte for byte, and is never refused.
     */
    #[Test]
    #[DataProvider('provideUnknownUris')]
    public function itReadsAnUnknownCodeAsNull(string $uri): void
    {
        // When / Then
        static::assertNull(SecondLevelStatusCode::tryFromUri($uri));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUnknownUris(): iterable
    {
        yield 'a top-level code' => ['urn:oasis:names:tc:SAML:2.0:status:Responder'];
        yield 'a code of a system entity' => ['urn:example:status:AccountLocked'];
        yield 'a case that differs' => ['urn:oasis:names:tc:SAML:2.0:status:InvalidNameIdPolicy'];
        yield 'a trailing space' => ['urn:oasis:names:tc:SAML:2.0:status:AuthnFailed '];
        yield 'empty' => [''];
    }
}
