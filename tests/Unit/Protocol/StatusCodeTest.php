<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Protocol;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use function array_map;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3, M-5: the top-level status codes, a closed vocabulary (SAML Core §3.2.2.2).
 */
final class StatusCodeTest extends TestCase
{
    /**
     * SAML Core §3.2.2.2: the four URIs the top-level StatusCode MUST take, and no other.
     */
    #[Test]
    public function itHoldsTheFourTopLevelCodesOfSamlCore(): void
    {
        // When
        $uris = array_map(static fn (StatusCode $code): string => $code->value, StatusCode::cases());

        // Then
        static::assertSame(
            [
                'urn:oasis:names:tc:SAML:2.0:status:Success',
                'urn:oasis:names:tc:SAML:2.0:status:Requester',
                'urn:oasis:names:tc:SAML:2.0:status:Responder',
                'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch',
            ],
            $uris,
        );
    }

    #[Test]
    #[DataProvider('provideCodes')]
    public function itReadsEachCodeFromItsUri(StatusCode $code): void
    {
        // When / Then
        static::assertSame($code, StatusCode::fromUri($code->value));
    }

    /**
     * @return iterable<string, array{StatusCode}>
     */
    public static function provideCodes(): iterable
    {
        foreach (StatusCode::cases() as $code) {
            yield $code->name => [$code];
        }
    }

    /**
     * M-5, M-6: any other URI is refused, compared byte for byte, and the refusal carries none of it (M-16).
     */
    #[Test]
    #[DataProvider('provideRefusedUris')]
    public function itRefusesEveryOtherUri(string $uri): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The top-level status code is not one of the four of SAML Core (M-5).');

        // When
        StatusCode::fromUri($uri);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRefusedUris(): iterable
    {
        yield 'a second-level code' => ['urn:oasis:names:tc:SAML:2.0:status:AuthnFailed'];
        yield 'the SAML 1.1 success' => ['samlp:Success'];
        yield 'a code of its own' => ['urn:example:status:Success'];
        yield 'a case that differs' => ['urn:oasis:names:tc:SAML:2.0:status:success'];
        yield 'a leading space' => [' urn:oasis:names:tc:SAML:2.0:status:Success'];
        yield 'a trailing newline' => ["urn:oasis:names:tc:SAML:2.0:status:Success\n"];
        yield 'empty' => [''];
    }
}
