<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Response;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\Response\Envelope;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\Tests\Unit\Internal\Assertion\AssertionFixtures;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Name;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.1 step 2, M-4, M-5, M-13: the structure of the envelope of a response, read before any key is touched.
 */
final class EnvelopeTest extends TestCase
{
    use AssertionFixtures;

    /**
     * M-4, section 6.1 step 2: a status of Success and its one assertion, the direct child of the element read.
     */
    #[Test]
    public function itKeepsTheStatusAndTheOneAssertion(): void
    {
        // Given
        $response = $this->document('behaviour/response-signed-both-accepted.xml')->root();

        // When
        $envelope = Envelope::of($response);

        // Then
        static::assertSame(
            [StatusCode::Success, Children::one($response, new Name(Saml::ASSERTION, 'Assertion'))],
            [$envelope->status->code, $envelope->assertion],
        );
    }

    /**
     * M-13, SAML Profiles §4.1.4.2: a failure holds no assertion.
     */
    #[Test]
    public function itKeepsTheStatusOfAFailureWithoutAssertion(): void
    {
        // Given
        $response = $this->document('behaviour/response-status-responder-authn-failed-refused.xml')->root();

        // When
        $envelope = Envelope::of($response);

        // Then
        static::assertSame([StatusCode::Responder, null], [$envelope->status->code, $envelope->assertion]);
    }

    /**
     * §9.2 rows 5, 6, 22 and 25, M-4, M-5, M-13: a child out of the order of the schema, an Issuer repeated, the
     * assertions the status forbids or more than one.
     */
    #[Test]
    #[DataProvider('provideMalformedEnvelopes')]
    public function itRefusesAMalformedEnvelope(string $fixture, string $message): void
    {
        // Given
        $document = $this->document($fixture);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        Envelope::of($document->root());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideMalformedEnvelopes(): iterable
    {
        $order = 'The samlp:Response holds a child out of the order of the schema, or one it does not allow there (M-5).';
        yield 'the Status after the assertion' => ['hostile/response-status-after-assertion-refused.xml', $order];
        yield 'the ds:Signature before the Issuer' => ['hostile/response-signature-before-issuer-refused.xml', $order];
        yield 'two Issuer' => [
            'hostile/response-two-issuers-refused.xml',
            'The samlp:Response holds more than one saml:Issuer (M-4).',
        ];
        yield 'Responder with an assertion' => [
            'hostile/response-status-responder-with-assertion-refused.xml',
            'The samlp:Response has a status other than Success and holds a saml:Assertion (M-13).',
        ];
        yield 'Success without assertion' => [
            'hostile/response-success-without-assertion-refused.xml',
            'The samlp:Response has the status Success and holds no saml:Assertion (M-13).',
        ];
        yield 'two assertions' => [
            'hostile/response-two-assertions-without-issuer-refused.xml',
            'The samlp:Response holds more than one saml:Assertion (M-4).',
        ];
    }

    /**
     * §9.2 row 29, section 6.7: a saml:EncryptedAssertion is refused by name until sub-spike 9e.
     */
    #[Test]
    public function itRefusesAnEncryptedAssertion(): void
    {
        // Given
        $document = $this->document('hostile/response-encrypted-assertion-refused.xml');
        $message = 'The response holds a saml:EncryptedAssertion, which the package does not support until sub-spike 9e (section 6.7).';

        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        Envelope::of($document->root());
    }
}
