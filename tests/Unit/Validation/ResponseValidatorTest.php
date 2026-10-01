<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Validation;

use Beffroi\Saml2\Model\Exception\DestinationMismatch;
use Beffroi\Saml2\Model\Exception\InResponseToMismatch;
use Beffroi\Saml2\Model\Exception\IssuerMismatch;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\RecipientMismatch;
use Beffroi\Saml2\Model\Exception\Replayed;
use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Exception\UnsuccessfulResponse;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\FrozenClock;
use Beffroi\Saml2\Model\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Model\Tests\Unit\Internal\Response\ResponseFixtures;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use Beffroi\Saml2\Model\Validation\SignatureCoverage;
use Beffroi\Xml\Core\Exception\DuplicateId;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Dsig\Exception\DigestMismatch;
use Beffroi\Xml\Dsig\Exception\MalformedSignature;
use Beffroi\Xml\Dsig\Exception\SignatureMismatch;
use Beffroi\Xml\Dsig\Exception\WrongReference;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.1, M-1, M-2, M-3, M-4, M-8, M-10, M-11, M-13: a response validated in the order of section 6.1, from
 * UnverifiedResponse::of() to AcceptedAssertion; the message-level wrapping corpus of §9.2 and the rows of §9.3 that
 * concern a response (SAML Profiles §4.1.4.2, §4.1.4.3, §4.1.4.5).
 */
final class ResponseValidatorTest extends TestCase
{
    use ResponseFixtures;

    /**
     * §9.3 rows 2 and 3, M-2, SAML Profiles §4.1.4.5 as corrected by E26: the assertion covered by its own signature,
     * by the response's, or by both, each verified.
     */
    #[Test]
    #[DataProvider('provideCoverages')]
    public function itAcceptsAnAssertionASignatureCovers(string $fixture, SignatureCoverage $coverage): void
    {
        // Given
        $response = $this->unverified($fixture);

        // When
        $accepted = $this->validator()->validate($response, self::identityProvider(), self::expected());

        // Then
        static::assertSame($coverage, $accepted->coverage);
    }

    /**
     * @return iterable<string, array{string, SignatureCoverage}>
     */
    public static function provideCoverages(): iterable
    {
        yield 'the assertion signed, the response not' => [
            'behaviour/response-signed-assertion-accepted.xml',
            SignatureCoverage::Assertion,
        ];
        yield 'the response signed, the assertion not' => [
            'behaviour/response-signed-response-accepted.xml',
            SignatureCoverage::Response,
        ];
        yield 'both signed' => ['behaviour/response-signed-both-accepted.xml', SignatureCoverage::AssertionAndResponse];
    }

    /**
     * Section 5.5, section 6.1 step 14, M-1: the ID of the response and the values of the assertion, read from the
     * verified documents.
     */
    #[Test]
    public function itReturnsTheValuesOfTheVerifiedResponse(): void
    {
        // Given
        $response = $this->unverified('behaviour/response-signed-both-accepted.xml');

        // When
        $accepted = $this->validator()->validate($response, self::identityProvider(), self::expected());

        // Then
        static::assertSame(
            [
                '_response',
                '_assertion',
                'https://idp.example.com/saml',
                '_7a2f4c1d9e',
                'https://sp.example.com/saml/acs',
                '_request',
                [['https://sp.example.com/saml']],
                '_session',
            ],
            [
                $accepted->responseId,
                $accepted->assertion->id,
                $accepted->assertion->issuer->entityId,
                $accepted->assertion->nameId->value,
                $accepted->assertion->confirmation->recipient,
                $accepted->assertion->confirmation->inResponseTo,
                $accepted->assertion->conditions->audiences,
                $accepted->assertion->authnStatement->sessionIndex,
            ],
        );
    }

    /**
     * §9.3 row 4, section 6.1 step 5: a signed response over an assertion signed with a PrefixList naming a prefix the
     * response declares is accepted, the assertion verified where it arrived, not in the response's re-parse.
     */
    #[Test]
    public function itAcceptsAnAssertionSignedWithAPrefixListNamingAPrefixOfTheResponse(): void
    {
        // Given
        $response = $this->unverified('behaviour/response-signed-both-prefix-list-accepted.xml');

        // When
        $accepted = $this->validator()->validate($response, self::identityProvider(), self::expected());

        // Then
        static::assertSame(SignatureCoverage::AssertionAndResponse, $accepted->coverage);
    }

    /**
     * M-10, SAML Profiles §4.1.5: an unsolicited response, InResponseTo absent everywhere, where the consumer accepts
     * one.
     */
    #[Test]
    public function itAcceptsAnUnsolicitedResponse(): void
    {
        // Given
        $response = $this->unverified('behaviour/response-unsolicited-accepted.xml');

        // When
        $accepted = $this->validator()->validate($response, self::identityProvider(), self::unsolicited());

        // Then
        static::assertNull($accepted->assertion->confirmation->inResponseTo);
    }

    /**
     * §9.3 row 7, M-11: the replay key is the pair of the issuer and the ID, so the same assertion ID from another
     * issuer is accepted too.
     */
    #[Test]
    public function itAcceptsTheSameAssertionIdFromAnotherIssuer(): void
    {
        // Given
        $replay = new InMemoryReplayGuard();
        $this->validator($replay)->validate(
            $this->unverified('behaviour/response-signed-assertion-accepted.xml'),
            self::identityProvider(),
            self::expected(),
        );
        $response = $this->unverified('behaviour/response-same-assertion-id-another-issuer-accepted.xml');

        // When
        $accepted = $this->validator($replay)->validate(
            $response,
            self::identityProvider('https://other-idp.example.com/saml'),
            self::expected(),
        );

        // Then
        static::assertSame(
            ['_assertion', 'https://other-idp.example.com/saml'],
            [$accepted->assertion->id, $accepted->assertion->issuer->entityId],
        );
    }

    /**
     * §9.3 row 9, M-5: a samlp:Extensions with content is accepted and never read.
     */
    #[Test]
    public function itAcceptsExtensionsItDoesNotRead(): void
    {
        // Given
        $response = $this->unverified('behaviour/response-extensions-with-content-accepted.xml');

        // When
        $accepted = $this->validator()->validate($response, self::identityProvider(), self::expected());

        // Then
        static::assertSame('_assertion', $accepted->assertion->id);
    }

    /**
     * Section 6.1 step 6, SAML Profiles §4.1.4.2 as corrected by E17, SAML Core §3.2.1: an unsigned response needs
     * neither an Issuer nor a Destination, its assertion signed.
     */
    #[Test]
    #[DataProvider('provideUnsignedResponsesWithoutOptionalParts')]
    public function itAcceptsAnUnsignedResponseWithoutItsOptionalParts(string $fixture): void
    {
        // Given
        $response = $this->unverified($fixture);

        // When
        $accepted = $this->validator()->validate($response, self::identityProvider(), self::expected());

        // Then
        static::assertSame('_response', $accepted->responseId);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUnsignedResponsesWithoutOptionalParts(): iterable
    {
        yield 'without Issuer' => ['behaviour/response-without-issuer-accepted.xml'];
        yield 'without Destination' => ['behaviour/response-without-destination-accepted.xml'];
    }

    /**
     * M-11, section 6.1 step 13: the verified ID of the assertion is remembered under its issuer until the end of its
     * bearer window plus the skew.
     */
    #[Test]
    public function itRemembersTheAssertionUntilItsBearerWindowEndsPlusTheSkew(): void
    {
        // Given
        $replay = new InMemoryReplayGuard();
        $response = $this->unverified('behaviour/response-signed-both-accepted.xml');

        // When
        $this->validator($replay)->validate($response, self::identityProvider(), self::expected());

        // Then
        static::assertEquals(
            new DateTimeImmutable('2026-09-30T12:07:58Z'),
            $replay->expiresAt('https://idp.example.com/saml', '_assertion'),
        );
    }

    /**
     * §9.2 row 1, I-8, M-14: the signed assertion moved into samlp:Extensions, an unsigned assertion of the same ID
     * in its place, is refused by the loader.
     */
    #[Test]
    public function itRefusesAtLoadAnAssertionOfTheSameIdAsTheWrappedOne(): void
    {
        // Given
        $bytes = MetadataFixtures::bytes('hostile/response-assertion-in-extensions-same-id-refused.xml');

        // Then
        $this->expectException(DuplicateId::class);
        $this->expectExceptionMessageIs('An ID value appears twice in the document (I-8).');

        // When
        SamlLoader::create()->load($bytes);
    }

    /**
     * §9.2 rows 2, 3, 4 and 8, M-1, M-4, D-2, D-9: the signed assertion moved into samlp:Extensions or into the
     * ds:Object of the signature, an assertion of another ID in its place: the direct child is the one verified, and
     * the wrapped one is never found.
     *
     * @param class-string<RefusedXml> $exception
     */
    #[Test]
    #[DataProvider('provideWrappedAssertions')]
    public function itRefusesAWrappedAssertion(string $fixture, string $exception, string $message): void
    {
        // Given
        $response = $this->unverified($fixture);

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $response->document);

        // When
        $this->validator()->validate($response, self::identityProvider(), self::expected());
    }

    /**
     * @return iterable<string, array{string, class-string<RefusedXml>, string}>
     */
    public static function provideWrappedAssertions(): iterable
    {
        yield 'in samlp:Extensions, the response unsigned' => [
            'hostile/response-assertion-in-extensions-another-id-refused.xml',
            SignatureRequired::class,
            'Neither the response nor its assertion carries a ds:Signature, one of which the profile requires (M-2).',
        ];
        yield 'in samlp:Extensions, its ds:Signature copied into the one in its place' => [
            'hostile/response-assertion-in-extensions-signature-copied-refused.xml',
            WrongReference::class,
            'The reference does not name the claimed element (D-2).',
        ];
        yield 'in samlp:Extensions, under a signed response' => [
            'hostile/response-assertion-in-extensions-signed-response-refused.xml',
            DigestMismatch::class,
            'The claimed element is not what was signed (D-8).',
        ];
        yield 'in the ds:Object of the signature' => [
            'hostile/response-assertion-in-signature-object-refused.xml',
            MalformedSignature::class,
            'A Signature holds a child other than SignedInfo, SignatureValue and KeyInfo (D-9).',
        ];
    }

    /**
     * §9.2 rows 5 and 6, M-4, section 6.1 step 2: two assertions as direct children, signed or not, in either order,
     * are refused before any signature is verified: the metadata here lists a key that verifies none of them.
     */
    #[Test]
    #[DataProvider('provideSeveralAssertions')]
    public function itRefusesSeveralAssertionsBeforeAnySignatureIsVerified(string $fixture): void
    {
        // Given
        $response = $this->unverified($fixture);
        $message = 'The samlp:Response holds more than one saml:Assertion (M-4).';

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $response->document);

        // When
        $this->validator()->validate(
            $response,
            self::identityProvider('https://idp.example.com/saml', 'sp'),
            self::expected(),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSeveralAssertions(): iterable
    {
        yield 'two signed assertions' => ['hostile/response-two-signed-assertions-refused.xml'];
        yield 'an unsigned assertion before the signed one' => [
            'hostile/response-unsigned-assertion-before-signed-refused.xml',
        ];
        yield 'an unsigned assertion after the signed one' => [
            'hostile/response-unsigned-assertion-after-signed-refused.xml',
        ];
    }

    /**
     * §9.2 row 7, section 8: an assertion inside the signed assertion's saml:Advice.
     */
    #[Test]
    public function itRefusesAnAssertionInAdvice(): void
    {
        // Given
        $response = $this->unverified('hostile/response-assertion-in-advice-refused.xml');
        $message = 'The assertion holds a saml:Advice, which the package does not support (section 8).';

        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $response->document);

        // When
        $this->validator()->validate($response, self::identityProvider(), self::expected());
    }

    /**
     * §9.2 row 9, M-2, SAML Profiles §4.1.4.5 as corrected by E26: a response and an assertion both unsigned.
     */
    #[Test]
    public function itRefusesAResponseNoSignatureCovers(): void
    {
        // Given
        $response = $this->unverified('hostile/response-unsigned-refused.xml');
        $message = 'Neither the response nor its assertion carries a ds:Signature, one of which the profile requires (M-2).';

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $response->document);

        // When
        $this->validator()->validate($response, self::identityProvider(), self::expected());
    }

    /**
     * §9.2 row 10, M-2: a signed response whose assertion carries a signature that fails; a present signature is
     * never skipped.
     */
    #[Test]
    public function itRefusesAnAssertionWhoseSignatureFailsUnderASignedResponse(): void
    {
        // Given
        $response = $this->unverified('hostile/response-assertion-signature-fails-under-signed-response-refused.xml');

        // Then
        $this->expectException(DigestMismatch::class);
        $this->expectExceptionMessageIs('The claimed element is not what was signed (D-8).');

        // When
        $this->validator()->validate($response, self::identityProvider(), self::expected());
    }

    /**
     * §9.2 row 11, M-3, D-7: the assertion signed by a key the metadata does not list, its certificate in KeyInfo.
     */
    #[Test]
    public function itRefusesASignatureUnderAKeyTheMetadataDoesNotList(): void
    {
        // Given
        $response = $this->unverified('hostile/response-assertion-signed-by-another-key-refused.xml');

        // Then
        $this->expectException(SignatureMismatch::class);
        $this->expectExceptionMessageIs('No trusted key verifies the signature over SignedInfo (D-7, D-8).');

        // When
        $this->validator()->validate($response, self::identityProvider(), self::expected());
    }

    /**
     * M-3, section 5.3: the metadata of an identity provider without a signing key verifies nothing.
     */
    #[Test]
    public function itRefusesAResponseFromAnIdentityProviderWithoutSigningKey(): void
    {
        // Given
        $response = $this->unverified('behaviour/response-signed-assertion-accepted.xml');
        $idp = new IdentityProvider(
            'https://idp.example.com/saml',
            [],
            [],
            [new Endpoint(Binding::HttpRedirect, 'https://idp.example.com/saml/sso')],
        );

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs('The metadata of the peer holds no signing key to verify the message with (M-3).');

        // When
        $this->validator()->validate($response, $idp, self::expected());
    }

    /**
     * §9.2 rows 12 and 13, M-8: the Destination of a signed response other than the URL of arrival, compared byte for
     * byte: another URL, a trailing slash, another case in the host, a percent-encoded character.
     */
    #[Test]
    #[DataProvider('provideOtherDestinations')]
    public function itRefusesADestinationOtherThanTheUrlOfArrival(string $fixture): void
    {
        // Given
        $response = $this->unverified($fixture);
        $message = 'The Destination of the response is not the URL at which it arrived (M-8).';

        // Then
        $this->expectException(DestinationMismatch::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $response->document);

        // When
        $this->validator()->validate($response, self::identityProvider(), self::expected());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideOtherDestinations(): iterable
    {
        yield 'another URL' => ['hostile/response-destination-another-url-refused.xml'];
        yield 'a trailing slash' => ['hostile/response-destination-trailing-slash-refused.xml'];
        yield 'another case in the host' => ['hostile/response-destination-host-case-refused.xml'];
        yield 'a percent-encoded character' => ['hostile/response-destination-percent-encoded-refused.xml'];
    }

    /**
     * §9.2 row 12, M-8, SAML Bindings §3.5.5.2: a signed response without Destination.
     */
    #[Test]
    public function itRefusesASignedResponseWithoutDestination(): void
    {
        // Given
        $response = $this->unverified('hostile/response-signed-without-destination-refused.xml');
        $message = 'The response is signed and has no Destination (M-8).';

        // Then
        $this->expectException(DestinationMismatch::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $response->document);

        // When
        $this->validator()->validate($response, self::identityProvider(), self::expected());
    }

    /**
     * §9.2 row 14, M-8, SAML Profiles §4.1.4.3: the Recipient of the bearer confirmation other than the URL of arrival.
     */
    #[Test]
    public function itRefusesARecipientOtherThanTheUrlOfArrival(): void
    {
        // Given
        $response = $this->unverified('hostile/response-recipient-another-url-refused.xml');
        $message = 'The Recipient of the bearer confirmation is not the URL at which the response arrived (M-8).';

        // Then
        $this->expectException(RecipientMismatch::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $response->document);

        // When
        $this->validator()->validate($response, self::identityProvider(), self::expected());
    }

    /**
     * §9.2 row 14, M-8: a bearer confirmation without Recipient.
     */
    #[Test]
    public function itRefusesAConfirmationWithoutRecipient(): void
    {
        // Given
        $response = $this->unverified('hostile/response-without-recipient-refused.xml');
        $message = 'The bearer confirmation has no Recipient (M-8).';

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $response->document);

        // When
        $this->validator()->validate($response, self::identityProvider(), self::expected());
    }

    /**
     * §9.2 row 16, M-8, SAML Core §8.3.6: the response's Issuer another entity than the assertion's and the identity
     * provider's, or carrying a qualifier.
     */
    #[Test]
    #[DataProvider('provideIssuersOfTheResponse')]
    public function itRefusesAnIssuerOfTheResponseThatIsNotTheIdentityProviders(string $fixture, string $message): void
    {
        // Given
        $response = $this->unverified($fixture);

        // Then
        $this->expectException(IssuerMismatch::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $response->document);

        // When
        $this->validator()->validate($response, self::identityProvider(), self::expected());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideIssuersOfTheResponse(): iterable
    {
        yield 'another entity' => [
            'hostile/response-issuer-another-entity-refused.xml',
            'The Issuer is not the entity ID of the peer (M-8).',
        ];
        yield 'a NameQualifier' => [
            'hostile/response-issuer-name-qualifier-refused.xml',
            'The Issuer carries a NameQualifier, an SPNameQualifier or an SPProvidedID, which an entity identifier omits (M-8).',
        ];
    }

    /**
     * M-8, SAML Profiles §4.1.4.2 as corrected by E17: a signed response without Issuer.
     */
    #[Test]
    public function itRefusesASignedResponseWithoutIssuer(): void
    {
        // Given
        $response = $this->unverified('hostile/response-signed-without-issuer-refused.xml');
        $message = 'The response is signed and has no saml:Issuer (M-8).';

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $response->document);

        // When
        $this->validator()->validate($response, self::identityProvider(), self::expected());
    }

    /**
     * §9.2 row 17, M-10, SAML Profiles §4.1.4.3, §4.1.5: the InResponseTo of the response, then of the confirmation,
     * other than the request; present on an unsolicited response; absent on a solicited one.
     */
    #[Test]
    #[DataProvider('provideOtherInResponseTo')]
    public function itRefusesAnInResponseToOtherThanExpected(
        string $fixture,
        ExpectedResponse $expected,
        string $message,
    ): void {
        // Given
        $response = $this->unverified($fixture);

        // Then
        $this->expectException(InResponseToMismatch::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $response->document);

        // When
        $this->validator()->validate($response, self::identityProvider(), $expected);
    }

    /**
     * @return iterable<string, array{string, ExpectedResponse, string}>
     */
    public static function provideOtherInResponseTo(): iterable
    {
        $response = 'The InResponseTo of the response is not the one the consumer expects (M-10).';
        yield 'the response, another request' => [
            'hostile/response-in-response-to-another-request-refused.xml',
            self::expected(),
            $response,
        ];
        yield 'the confirmation, another request' => [
            'hostile/response-confirmation-in-response-to-another-request-refused.xml',
            self::expected(),
            'The InResponseTo of the bearer confirmation is not the one the consumer expects (M-10).',
        ];
        yield 'present on an unsolicited response' => [
            'behaviour/response-signed-assertion-accepted.xml',
            self::unsolicited(),
            $response,
        ];
        yield 'absent on a solicited response' => [
            'behaviour/response-unsolicited-accepted.xml',
            self::expected(),
            $response,
        ];
    }

    /**
     * §9.2 row 21, M-11: the same valid response validated twice.
     */
    #[Test]
    public function itRefusesTheSameResponseTwice(): void
    {
        // Given
        $replay = new InMemoryReplayGuard();
        $this->validator($replay)->validate(
            $this->unverified('behaviour/response-signed-both-accepted.xml'),
            self::identityProvider(),
            self::expected(),
        );
        $response = $this->unverified('behaviour/response-signed-both-accepted.xml');
        $message = 'The assertion was already accepted from its issuer (M-11).';

        // Then
        $this->expectException(Replayed::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $response->document);

        // When
        $this->validator($replay)->validate($response, self::identityProvider(), self::expected());
    }

    /**
     * §9.3 row 8, M-11: an assertion refused for its audience leaves nothing in the replay store.
     */
    #[Test]
    public function itRemembersNothingOfAnAssertionItRefuses(): void
    {
        // Given
        $replay = new InMemoryReplayGuard();
        $response = $this->unverified('hostile/response-audience-another-sp-refused.xml');

        // When
        try {
            $this->validator($replay)->validate($response, self::identityProvider(), self::expected());
        } catch (RefusedXml) {
        }

        // Then
        static::assertTrue($replay->isEmpty());
    }

    /**
     * §9.2 row 22, M-13, SAML Profiles §4.1.4.2: a status of Responder with an assertion; Success without one.
     */
    #[Test]
    #[DataProvider('provideAssertionsTheStatusForbids')]
    public function itRefusesAnAssertionTheStatusForbids(string $fixture, string $message): void
    {
        // Given
        $response = $this->unverified($fixture);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $response->document);

        // When
        $this->validator()->validate($response, self::identityProvider(), self::expected());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideAssertionsTheStatusForbids(): iterable
    {
        yield 'Responder with an assertion' => [
            'hostile/response-status-responder-with-assertion-refused.xml',
            'The samlp:Response has a status other than Success and holds a saml:Assertion (M-13).',
        ];
        yield 'Success without assertion' => [
            'hostile/response-success-without-assertion-refused.xml',
            'The samlp:Response has the status Success and holds no saml:Assertion (M-13).',
        ];
    }

    /**
     * §9.2 row 29, section 6.7: a saml:EncryptedAssertion, until sub-spike 9e.
     */
    #[Test]
    public function itRefusesAnEncryptedAssertion(): void
    {
        // Given
        $response = $this->unverified('hostile/response-encrypted-assertion-refused.xml');
        $message = 'The response holds a saml:EncryptedAssertion, which the package does not support until sub-spike 9e (section 6.7).';

        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $response->document);

        // When
        $this->validator()->validate($response, self::identityProvider(), self::expected());
    }

    /**
     * §9.2 row 25, M-5, section 6.1 steps 2 and 5: a ds:Signature before the Issuer, the response's refused before
     * its signature is verified, the assertion's refused on the received element, since the verification removes it
     * from the document the reader reads (D-10).
     */
    #[Test]
    #[DataProvider('provideSignaturesOutOfTheirPlace')]
    public function itRefusesASignatureOutOfItsPlace(string $fixture, string $message): void
    {
        // Given
        $response = $this->unverified($fixture);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $response->document);

        // When
        $this->validator()->validate($response, self::identityProvider(), self::expected());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideSignaturesOutOfTheirPlace(): iterable
    {
        yield 'the response\'s' => [
            'hostile/response-signature-before-issuer-refused.xml',
            'The samlp:Response holds a child out of the order of the schema, or one it does not allow there (M-5).',
        ];
        yield 'the assertion\'s' => [
            'hostile/response-assertion-signature-before-issuer-refused.xml',
            'The saml:Assertion holds a child out of the order of the schema, or one it does not allow there (M-5).',
        ];
    }

    /**
     * §9.3 row 14, M-13, M-16, section 6.1 step 4: a failure Responder / AuthnFailed, unsigned or signed, is
     * UnsuccessfulResponse carrying both codes; its message is fixed and carries no StatusMessage.
     */
    #[Test]
    #[DataProvider('provideFailures')]
    public function itReportsAFailureWithItsTwoCodes(string $fixture): void
    {
        // Given
        $response = $this->unverified($fixture);

        // When
        try {
            $this->validator()->validate($response, self::identityProvider(), self::expected());
            static::fail('The failure is not reported.');
        } catch (UnsuccessfulResponse $failure) {
            // Then
            static::assertSame(
                [
                    StatusCode::Responder,
                    SecondLevelStatusCode::AuthnFailed,
                    'The status of the response is not Success, and the response yields no assertion (M-13).',
                ],
                [$failure->status->code, $failure->status->secondLevel, $failure->getMessage()],
            );
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideFailures(): iterable
    {
        yield 'unsigned' => ['behaviour/response-status-responder-authn-failed-refused.xml'];
        yield 'signed' => ['behaviour/response-status-responder-authn-failed-signed-refused.xml'];
    }

    /**
     * M-2, section 6.1 steps 3 and 4: the signature of a failure is verified before the failure is reported.
     */
    #[Test]
    public function itVerifiesTheSignatureOfAFailureBeforeReportingIt(): void
    {
        // Given
        $response = $this->unverified('hostile/response-status-signed-then-altered-refused.xml');

        // Then
        $this->expectException(DigestMismatch::class);
        $this->expectExceptionMessageIs('The claimed element is not what was signed (D-8).');

        // When
        $this->validator()->validate($response, self::identityProvider(), self::expected());
    }

    /**
     * M-10, section 6.1 step 4: the envelope rules run on a failure before it is reported, so that a failure
     * answering another request is refused as such.
     */
    #[Test]
    public function itAppliesTheEnvelopeRulesToAFailure(): void
    {
        // Given
        $response = $this->unverified('hostile/response-status-in-response-to-another-request-refused.xml');
        $message = 'The InResponseTo of the response is not the one the consumer expects (M-10).';

        // Then
        $this->expectException(InResponseToMismatch::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $response->document);

        // When
        $this->validator()->validate($response, self::identityProvider(), self::expected());
    }

    /**
     * A response to the request _request, received at our assertion consumer service, for our entity ID.
     */
    private static function expected(): ExpectedResponse
    {
        return ExpectedResponse::toRequest(
            '_request',
            'https://sp.example.com/saml/acs',
            'https://sp.example.com/saml',
        );
    }

    /**
     * An unsolicited response, received at our assertion consumer service, for our entity ID.
     */
    private static function unsolicited(): ExpectedResponse
    {
        return ExpectedResponse::unsolicited('https://sp.example.com/saml/acs', 'https://sp.example.com/saml');
    }

    /**
     * The validator, its clock frozen at 2026-09-30T12:00:00Z, a second after the response was issued, its replay
     * store $replay.
     */
    private function validator(InMemoryReplayGuard $replay = new InMemoryReplayGuard()): ResponseValidator
    {
        return new ResponseValidator(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable('2026-09-30T12:00:00Z')),
            $replay,
        );
    }
}
