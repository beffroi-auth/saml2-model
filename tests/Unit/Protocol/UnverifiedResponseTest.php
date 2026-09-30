<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Protocol;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Protocol\UnverifiedResponse;
use Beffroi\Saml2\Model\Tests\Unit\Internal\Assertion\AssertionFixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.4, M-1: a response read before any signature is verified, its root, its Issuer and its InResponseTo, and
 * nothing else, so that the consumer can choose the identity provider whose keys verify it.
 */
final class UnverifiedResponseTest extends TestCase
{
    use AssertionFixtures;

    /**
     * Section 5.4: the document as loaded, the response's own Issuer, and its InResponseTo.
     */
    #[Test]
    public function itReadsTheIssuerAndTheInResponseToOfTheResponse(): void
    {
        // Given
        $document = $this->document('hostile/response-issuer-another-entity-refused.xml');

        // When
        $response = UnverifiedResponse::of($document);

        // Then
        static::assertSame(
            [$document, 'https://other-idp.example.com/saml', '_request'],
            [$response->document, $response->issuer, $response->inResponseTo],
        );
    }

    /**
     * Section 5.4, SAML Profiles §4.1.4.2: a response without Issuer names its issuer through its one assertion.
     */
    #[Test]
    public function itReadsTheIssuerOfTheAssertionOfAResponseWithoutOne(): void
    {
        // Given
        $document = $this->document('behaviour/response-without-issuer-accepted.xml');

        // When
        $response = UnverifiedResponse::of($document);

        // Then
        static::assertSame('https://idp.example.com/saml', $response->issuer);
    }

    /**
     * Section 5.4, M-4: without an Issuer of its own, a response names no issuer unless it holds exactly one
     * assertion, never the first of several.
     */
    #[Test]
    #[DataProvider('provideResponsesNamingNoIssuer')]
    public function itReadsNoIssuerWhereNoneIsOne(string $fixture): void
    {
        // Given
        $document = $this->document($fixture);

        // When
        $response = UnverifiedResponse::of($document);

        // Then
        static::assertNull($response->issuer);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideResponsesNamingNoIssuer(): iterable
    {
        yield 'a failure without Issuer nor assertion' => [
            'behaviour/response-status-requester-without-issuer-refused.xml',
        ];
        yield 'two assertions and no Issuer' => ['hostile/response-two-assertions-without-issuer-refused.xml'];
    }

    /**
     * M-10, SAML Profiles §4.1.5: an unsolicited response has no InResponseTo.
     */
    #[Test]
    public function itReadsNoInResponseToOfAnUnsolicitedResponse(): void
    {
        // Given
        $document = $this->document('behaviour/response-unsolicited-accepted.xml');

        // When
        $response = UnverifiedResponse::of($document);

        // Then
        static::assertNull($response->inResponseTo);
    }

    /**
     * M-1, M-4, M-6: another root, a repeated Issuer, an InResponseTo that is not an NCName.
     */
    #[Test]
    #[DataProvider('provideMalformedResponses')]
    public function itRefusesAMalformedResponse(string $fixture, string $message): void
    {
        // Given
        $document = $this->document($fixture);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        UnverifiedResponse::of($document);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideMalformedResponses(): iterable
    {
        yield 'the root a saml:Assertion' => [
            'behaviour/assertion-valid-accepted.xml',
            'The root of the document is not a samlp:Response (M-1).',
        ];
        yield 'two saml:Issuer' => [
            'hostile/response-two-issuers-refused.xml',
            'The samlp:Response holds more than one saml:Issuer (M-4).',
        ];
        yield 'an InResponseTo that is not an NCName' => [
            'hostile/response-in-response-to-not-an-ncname-refused.xml',
            'An ID is not an NCName (M-6).',
        ];
    }
}
