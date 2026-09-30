<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Protocol;

use Beffroi\Saml2\Model\Assertion\Assertion;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\Assertion\AssertionReader;
use Beffroi\Saml2\Model\Protocol\Response;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Tests\Unit\Internal\Assertion\AssertionFixtures;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3, M-6, M-13: a response and the rules of its values, whoever builds it.
 */
final class ResponseTest extends TestCase
{
    use AssertionFixtures;

    /**
     * Section 5.3: a successful response, its values as given, its one assertion.
     */
    #[Test]
    public function itKeepsTheValuesOfASuccessfulResponse(): void
    {
        // Given
        $assertion = $this->assertion();

        // When
        $response = new Response(
            '_response',
            new DateTimeImmutable('2026-09-30T11:59:59Z'),
            new Issuer('https://idp.example.com/saml'),
            'https://sp.example.com/saml/acs',
            '_request',
            new Status(StatusCode::Success),
            $assertion,
        );

        // Then
        static::assertSame(
            ['_response', '2026-09-30T11:59:59Z', 'https://idp.example.com/saml', 'https://sp.example.com/saml/acs'],
            [
                $response->id,
                $response->issueInstant->format('Y-m-d\TH:i:s\Z'),
                $response->issuer->entityId,
                $response->destination,
            ],
        );
        static::assertSame(['_request', StatusCode::Success, $assertion], [
            $response->inResponseTo,
            $response->status->code,
            $response->assertion,
        ]);
    }

    /**
     * M-13, SAML Profiles §4.1.4.2: a failure carries no assertion; unsolicited and unsigned, it has neither
     * InResponseTo nor Destination.
     */
    #[Test]
    public function itKeepsAFailureWithoutAssertion(): void
    {
        // When
        $response = new Response(
            '_response',
            new DateTimeImmutable('2026-09-30T11:59:59Z'),
            new Issuer('https://idp.example.com/saml'),
            null,
            null,
            new Status(StatusCode::Responder, SecondLevelStatusCode::AuthnFailed),
            null,
        );

        // Then
        static::assertSame([null, null, null], [$response->destination, $response->inResponseTo, $response->assertion]);
    }

    /**
     * M-6: an ID or an InResponseTo that is not an NCName, a relative Destination.
     */
    #[Test]
    #[DataProvider('provideValuesNotOfTheirLexicalForm')]
    public function itRefusesAValueNotOfItsLexicalForm(
        string $id,
        ?string $destination,
        ?string $inResponseTo,
        string $message,
    ): void {
        // Given
        $assertion = $this->assertion();

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);

        // When
        new Response(
            $id,
            new DateTimeImmutable('2026-09-30T11:59:59Z'),
            new Issuer('https://idp.example.com/saml'),
            $destination,
            $inResponseTo,
            new Status(StatusCode::Success),
            $assertion,
        );
    }

    /**
     * @return iterable<string, array{string, ?string, ?string, string}>
     */
    public static function provideValuesNotOfTheirLexicalForm(): iterable
    {
        $acs = 'https://sp.example.com/saml/acs';
        yield 'an ID that is not an NCName' => ['1response', $acs, '_request', 'An ID is not an NCName (M-6).'];
        yield 'a relative Destination' => ['_response', 'saml/acs', '_request', 'A URI is not absolute (M-6).'];
        yield 'an InResponseTo that is not an NCName' => [
            '_response',
            $acs,
            '1request',
            'An ID is not an NCName (M-6).',
        ];
    }

    /**
     * M-13: a response whose status is Success carries its assertion.
     */
    #[Test]
    public function itRefusesASuccessWithoutAssertion(): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A response whose status is Success carries an assertion (M-13).');

        // When
        new Response(
            '_response',
            new DateTimeImmutable('2026-09-30T11:59:59Z'),
            new Issuer('https://idp.example.com/saml'),
            'https://sp.example.com/saml/acs',
            '_request',
            new Status(StatusCode::Success),
            null,
        );
    }

    /**
     * M-13, SAML Profiles §4.1.4.2: a failure carries no assertion.
     */
    #[Test]
    public function itRefusesAFailureWithAnAssertion(): void
    {
        // Given
        $assertion = $this->assertion();

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A response whose status is not Success carries no assertion (M-13).');

        // When
        new Response(
            '_response',
            new DateTimeImmutable('2026-09-30T11:59:59Z'),
            new Issuer('https://idp.example.com/saml'),
            'https://sp.example.com/saml/acs',
            '_request',
            new Status(StatusCode::Responder),
            $assertion,
        );
    }

    private function assertion(): Assertion
    {
        return AssertionReader::read($this->document('behaviour/assertion-valid-accepted.xml'), $this->context());
    }
}
