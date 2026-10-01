<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Validation;

use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\DestinationMismatch;
use Beffroi\Saml2\Model\Exception\InvalidNameId;
use Beffroi\Saml2\Model\Exception\IssuerMismatch;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\MessageRefused;
use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Exception\UnknownEndpoint;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Protocol\AuthnContextComparison;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\Protocol\NameIdPolicy;
use Beffroi\Saml2\Model\Protocol\RequestedAuthnContext;
use Beffroi\Saml2\Model\Protocol\UnverifiedAuthnRequest;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\AcceptedAuthnRequest;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Dsig\Exception\DigestMismatch;
use Beffroi\Xml\Dsig\Exception\SignatureMismatch;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use function sprintf;

/**
 * Sections 5.6 and 6.2: an AuthnRequest validated by the identity provider, in order; the request rows of sections
 * 9.2 and 9.3; M-1, M-2, M-3, M-5, M-6, M-7, M-8, M-9 on the way.
 */
final class AuthnRequestValidatorTest extends TestCase
{
    private const string SIGNED = 'behaviour/authn-request-signed.xml';

    private const string UNSIGNED = 'behaviour/authn-request-unsigned.xml';

    /**
     * M-2, M-1, Profiles §4.1.6: a signed request is verified under the service provider's keys and read from what
     * was verified, whether the metadata of a party asks for the signature or neither does: every signature present
     * is verified.
     */
    #[Test]
    #[DataProvider('provideWhoAsksForTheSignature')]
    public function itAcceptsASignedRequest(bool $authnRequestsSigned, bool $wantAuthnRequestsSigned): void
    {
        // Given
        $request = AuthnRequestFixtures::load(self::SIGNED);

        // When
        $accepted = AuthnRequestFixtures::validator()->validate(
            $request,
            AuthnRequestFixtures::serviceProvider($authnRequestsSigned),
            AuthnRequestFixtures::identityProvider($wantAuthnRequestsSigned),
            AuthnRequestFixtures::SINGLE_SIGN_ON,
        );

        // Then
        static::assertEquals(
            [
                new AuthnRequest(
                    AuthnRequestFixtures::ID,
                    new DateTimeImmutable(AuthnRequestFixtures::NOW),
                    new Issuer(AuthnRequestFixtures::SERVICE_PROVIDER),
                    AuthnRequestFixtures::SINGLE_SIGN_ON,
                    AuthnRequestFixtures::ASSERTION_CONSUMER,
                    null,
                    AuthnRequestFixtures::POST,
                ),
                0,
                Authentication::XmlSignature,
            ],
            [$accepted->request, $accepted->assertionConsumerService->index, $accepted->authentication],
        );
    }

    /**
     * @return iterable<string, array{bool, bool}>
     */
    public static function provideWhoAsksForTheSignature(): iterable
    {
        yield 'the service provider signs its requests' => [true, false];
        yield 'the identity provider wants them signed' => [false, true];
        yield 'both' => [true, true];
        yield 'neither, the signature verified all the same' => [false, false];
    }

    /**
     * §9.2 row 31, "an unsigned AuthnRequest from a service provider whose metadata says AuthnRequestsSigned", M-2,
     * Profiles §4.1.6: refused, and refused as well when our own metadata wants the requests signed.
     */
    #[Test]
    #[DataProvider('providePartyAskingForTheSignature')]
    public function itRefusesAnUnsignedRequestAPartyWantsSigned(
        bool $authnRequestsSigned,
        bool $wantAuthnRequestsSigned,
    ): void {
        // Given
        $request = AuthnRequestFixtures::load(self::UNSIGNED);

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs('The message carries no ds:Signature, which the profile requires (M-2).');

        // When
        AuthnRequestFixtures::validator()->validate(
            $request,
            AuthnRequestFixtures::serviceProvider($authnRequestsSigned),
            AuthnRequestFixtures::identityProvider($wantAuthnRequestsSigned),
            AuthnRequestFixtures::SINGLE_SIGN_ON,
        );
    }

    /**
     * @return iterable<string, array{bool, bool}>
     */
    public static function providePartyAskingForTheSignature(): iterable
    {
        yield 'the service provider says AuthnRequestsSigned' => [true, false];
        yield 'the identity provider says WantAuthnRequestsSigned' => [false, true];
    }

    /**
     * M-2, Profiles §4.1.6: an unsigned request that neither party's metadata asks to be signed was authenticated by
     * nothing, and is accepted.
     */
    #[Test]
    public function itAcceptsAnUnsignedRequestNoPartyWantsSigned(): void
    {
        // Given
        $request = AuthnRequestFixtures::load(self::UNSIGNED);

        // When
        $accepted = $this->validate($request);

        // Then
        static::assertSame(
            [AuthnRequestFixtures::ID, 0, Authentication::None],
            [$accepted->request->id, $accepted->assertionConsumerService->index, $accepted->authentication],
        );
    }

    /**
     * Section 6.8, M-2: a request whose query string saml2-bindings verified under the service provider's keys, the
     * metadata of both parties asking for signed requests.
     */
    #[Test]
    public function itAcceptsARequestTheBindingAuthenticated(): void
    {
        // Given
        $request = AuthnRequestFixtures::load(self::UNSIGNED);

        // When
        $accepted = AuthnRequestFixtures::validator()->validateAuthenticatedByBinding(
            $request,
            AuthnRequestFixtures::serviceProvider(true),
            AuthnRequestFixtures::identityProvider(true),
            AuthnRequestFixtures::SINGLE_SIGN_ON,
        );

        // Then
        static::assertSame(
            [AuthnRequestFixtures::ID, 0, Authentication::Binding],
            [$accepted->request->id, $accepted->assertionConsumerService->index, $accepted->authentication],
        );
    }

    /**
     * Section 6.8, M-3: the binding verified the query string with the keys of the service provider's metadata; one
     * whose metadata holds no signing key cannot have been verified so, and is refused as validate() refuses a signed
     * request from it, whatever the two parties ask for.
     */
    #[Test]
    #[TestWith([false, false])]
    #[TestWith([true, true])]
    public function itRefusesTheBindingPathForAServiceProviderWithoutKey(bool $signed, bool $wanted): void
    {
        // Given
        $sp = AuthnRequestFixtures::serviceProvider($signed);
        $withoutKey = new ServiceProvider(
            $sp->entityId,
            [],
            [],
            $sp->assertionConsumerServices,
            authnRequestsSigned: $signed,
        );

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs('The metadata of the peer holds no signing key to verify the message with (M-3).');

        // When
        AuthnRequestFixtures::validator()->validateAuthenticatedByBinding(
            AuthnRequestFixtures::load(self::UNSIGNED),
            $withoutKey,
            AuthnRequestFixtures::identityProvider($wanted),
            AuthnRequestFixtures::SINGLE_SIGN_ON,
        );
    }

    /**
     * §9.2 row 32, "an AuthnRequest with a ds:Signature given to validateAuthenticatedByBinding()", SAML Bindings
     * §3.4.4.1: the HTTP-Redirect encoding removes the signature of the message.
     */
    #[Test]
    public function itRefusesASignatureGivenToTheBindingPath(): void
    {
        // Given
        $request = AuthnRequestFixtures::load(self::SIGNED);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The message carries a ds:Signature, which the HTTP-Redirect encoding removes (SAML Bindings §3.4.4.1).');

        // When
        AuthnRequestFixtures::validator()->validateAuthenticatedByBinding(
            $request,
            AuthnRequestFixtures::serviceProvider(),
            AuthnRequestFixtures::identityProvider(),
            AuthnRequestFixtures::SINGLE_SIGN_ON,
        );
    }

    /**
     * M-3, D-7: the request signed by a key the service provider's metadata does not list, its own or not.
     */
    #[Test]
    public function itRefusesARequestSignedByAKeyNotOfTheServiceProvider(): void
    {
        // Given
        $request = AuthnRequestFixtures::load(self::SIGNED);

        // Then
        $this->expectException(SignatureMismatch::class);
        $this->expectExceptionMessageIs('No trusted key verifies the signature over SignedInfo (D-7, D-8).');

        // When
        AuthnRequestFixtures::validator()->validate(
            $request,
            AuthnRequestFixtures::serviceProvider(true, 'idp'),
            AuthnRequestFixtures::identityProvider(),
            AuthnRequestFixtures::SINGLE_SIGN_ON,
        );
    }

    /**
     * M-2, section 5.8: the AssertionConsumerServiceURL changed after signing, to a service the metadata lists, is
     * Dsig's refusal, as it is, whether the signature is required or not.
     */
    #[Test]
    #[DataProvider('provideWhoAsksForTheSignature')]
    public function itRefusesARequestAlteredAfterSigning(bool $authnRequestsSigned, bool $wantAuthnRequestsSigned): void
    {
        // Given
        $request = AuthnRequestFixtures::load('hostile/authn-request-signed-then-altered-refused.xml');

        // Then
        $this->expectException(DigestMismatch::class);
        $this->expectExceptionMessageIs('The claimed element is not what was signed (D-8).');

        // When
        AuthnRequestFixtures::validator()->validate(
            $request,
            AuthnRequestFixtures::serviceProvider($authnRequestsSigned),
            AuthnRequestFixtures::identityProvider($wantAuthnRequestsSigned),
            AuthnRequestFixtures::SINGLE_SIGN_ON,
        );
    }

    /**
     * M-9, §9.3 row 13, "an AuthnRequest without an assertion consumer service": the service of the URL, of the
     * index, or the default of the metadata (SAML Metadata §2.2.3), never a location the request brings.
     */
    #[Test]
    #[DataProvider('provideAssertionConsumerServices')]
    public function itResolvesTheAssertionConsumerServiceInTheMetadata(
        string $path,
        int $index,
        string $location,
    ): void {
        // Given
        $request = AuthnRequestFixtures::load($path);

        // When
        $accepted = $this->validate($request);

        // Then
        static::assertSame([$index, $location], [
            $accepted->assertionConsumerService->index,
            $accepted->assertionConsumerService->location,
        ]);
    }

    /**
     * @return iterable<string, array{string, int, string}>
     */
    public static function provideAssertionConsumerServices(): iterable
    {
        yield 'by URL' => [self::UNSIGNED, 0, AuthnRequestFixtures::ASSERTION_CONSUMER];
        yield 'by index' => [
            'behaviour/authn-request-assertion-consumer-service-index.xml',
            0,
            AuthnRequestFixtures::ASSERTION_CONSUMER,
        ];
        yield 'none, the default endpoint of the metadata' => [
            'behaviour/authn-request-without-assertion-consumer-service.xml',
            1,
            AuthnRequestFixtures::ASSERTION_CONSUMER . '/second',
        ];
    }

    /**
     * §9.2 row 30, "an AuthnRequest whose AssertionConsumerServiceURL the metadata does not list; whose index it
     * does not list; with both", M-9, SAML Core §3.4.1.
     *
     * @param class-string<MessageRefused> $exception
     */
    #[Test]
    #[DataProvider('provideAssertionConsumerServicesRefused')]
    public function itRefusesAnAssertionConsumerServiceTheMetadataDoesNotEstablish(
        string $path,
        string $exception,
        string $message,
    ): void {
        // Given
        $request = AuthnRequestFixtures::load($path);

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        $this->validate($request);
    }

    /**
     * @return iterable<string, array{string, class-string<MessageRefused>, string}>
     */
    public static function provideAssertionConsumerServicesRefused(): iterable
    {
        $exclusive = 'An AuthnRequest carries an AssertionConsumerServiceIndex next to an AssertionConsumerServiceURL or a ProtocolBinding, which SAML Core §3.4.1 makes mutually exclusive (M-9).';
        yield 'a URL the metadata does not list' => [
            'hostile/authn-request-assertion-consumer-service-url-not-listed-refused.xml',
            UnknownEndpoint::class,
            'No assertion consumer service of the metadata has that location (M-9).',
        ];
        yield 'an index the metadata does not list' => [
            'hostile/authn-request-assertion-consumer-service-index-not-listed-refused.xml',
            UnknownEndpoint::class,
            'No assertion consumer service of the metadata has that index (M-9).',
        ];
        yield 'a URL and an index' => [
            'hostile/authn-request-assertion-consumer-service-url-and-index-refused.xml',
            MalformedMessage::class,
            $exclusive,
        ];
        yield 'an index and a ProtocolBinding' => [
            'hostile/authn-request-assertion-consumer-service-index-and-protocol-binding-refused.xml',
            MalformedMessage::class,
            $exclusive,
        ];
    }

    /**
     * §9.2 row 33, "an AuthnRequest with ProtocolBinding HTTP-Redirect", section 8: the Redirect binding cannot
     * carry a response.
     */
    #[Test]
    public function itRefusesTheRedirectProtocolBinding(): void
    {
        // Given
        $request = AuthnRequestFixtures::load('hostile/authn-request-protocol-binding-redirect-refused.xml');

        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs('The ProtocolBinding of an AuthnRequest is not HTTP-POST, the one binding the package answers over (section 8).');

        // When
        $this->validate($request);
    }

    /**
     * §9.2 row 33, "an AuthnRequest without Issuer", Profiles §4.1.4.1, M-4.
     */
    #[Test]
    public function itRefusesARequestWithoutIssuer(): void
    {
        // Given
        $request = AuthnRequestFixtures::load('hostile/authn-request-without-issuer-refused.xml');

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The samlp:AuthnRequest holds no saml:Issuer (M-4).');

        // When
        $this->validate($request);
    }

    /**
     * §9.2 row 33, "an AuthnRequest with a saml:Subject", section 8: saml:Subject, saml:Conditions and
     * samlp:Scoping refused by name, wherever they are.
     */
    #[Test]
    #[DataProvider('provideUnsupportedChildren')]
    public function itRefusesWhatThePackageDoesNotSupport(string $path): void
    {
        // Given
        $request = AuthnRequestFixtures::load($path);

        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs('The samlp:AuthnRequest holds a saml:Subject, a saml:Conditions or a samlp:Scoping, which the package does not support (section 8).');

        // When
        $this->validate($request);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUnsupportedChildren(): iterable
    {
        yield 'a saml:Subject' => ['hostile/authn-request-subject-refused.xml'];
        yield 'a saml:Subject before the saml:Issuer' => ['hostile/authn-request-subject-before-issuer-refused.xml'];
        yield 'a saml:Conditions' => ['hostile/authn-request-conditions-refused.xml'];
        yield 'a samlp:Scoping' => ['hostile/authn-request-scoping-refused.xml'];
    }

    /**
     * M-4, M-5, section 6.2 step 1: the children in the order and with the cardinality of the schema, checked before
     * any signature is touched.
     */
    #[Test]
    #[DataProvider('provideStructuresOutsideTheSchema')]
    public function itRefusesAStructureOutsideTheSchema(string $path, string $message): void
    {
        // Given
        $request = AuthnRequestFixtures::load($path);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);

        // When
        AuthnRequestFixtures::validator()->validate(
            $request,
            AuthnRequestFixtures::serviceProvider(true),
            AuthnRequestFixtures::identityProvider(),
            AuthnRequestFixtures::SINGLE_SIGN_ON,
        );
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideStructuresOutsideTheSchema(): iterable
    {
        $order = 'The samlp:AuthnRequest holds a child out of the order of the schema, or one it does not allow there (M-5).';
        yield 'a ds:Signature before the saml:Issuer' => [
            'hostile/authn-request-signature-before-issuer-refused.xml',
            $order,
        ];
        yield 'a samlp:NameIDPolicy before the samlp:Extensions' => [
            'hostile/authn-request-name-id-policy-before-extensions-refused.xml',
            $order,
        ];
        yield 'an unknown samlp: element' => ['hostile/authn-request-unknown-protocol-element-refused.xml', $order];
        yield 'an element of another namespace outside samlp:Extensions' => [
            'hostile/authn-request-element-of-another-namespace-refused.xml',
            $order,
        ];
        yield 'two ds:Signature' => [
            'hostile/authn-request-two-signatures-refused.xml',
            'The samlp:AuthnRequest holds more than one ds:Signature (M-4).',
        ];
        yield 'two samlp:NameIDPolicy' => [
            'hostile/authn-request-two-name-id-policies-refused.xml',
            'The samlp:AuthnRequest holds more than one samlp:NameIDPolicy (M-4).',
        ];
    }

    /**
     * §9.2 row 12, a Destination other than the URL of arrival, M-8, Bindings §3.4.5.2, §3.5.5.2: the Destination is
     * the URL at which the request arrived, byte for byte, whether the request is signed, unsigned or authenticated by
     * the binding.
     */
    #[Test]
    #[DataProvider('provideDestinationsOfAnotherUrl')]
    public function itRefusesADestinationOtherThanTheUrlOfArrival(string $path, string $validation): void
    {
        // Given
        $request = AuthnRequestFixtures::load($path);

        // Then
        $this->expectException(DestinationMismatch::class);
        $this->expectExceptionMessageIs('The Destination of the request is not the URL at which it arrived (M-8).');

        // When
        $this->validate($request, $validation);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideDestinationsOfAnotherUrl(): iterable
    {
        yield 'signed' => ['hostile/authn-request-destination-another-url-signed-refused.xml', 'validate'];
        yield 'unsigned' => ['hostile/authn-request-destination-another-url-refused.xml', 'validate'];
        yield 'authenticated by the binding' => [
            'hostile/authn-request-destination-another-url-refused.xml',
            'binding',
        ];
    }

    /**
     * M-8, SAML Bindings §3.4.5.2, §3.5.5.2: a request that carries a signature, its own or the binding's, carries its
     * Destination.
     */
    #[Test]
    #[DataProvider('provideSignedWithoutDestination')]
    public function itRefusesASignedRequestWithoutDestination(string $path, string $validation): void
    {
        // Given
        $request = AuthnRequestFixtures::load($path);

        // Then
        $this->expectException(DestinationMismatch::class);
        $this->expectExceptionMessageIs('The request is signed, by XML or by the binding, and carries no Destination (M-8).');

        // When
        $this->validate($request, $validation);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideSignedWithoutDestination(): iterable
    {
        yield 'signed' => ['hostile/authn-request-without-destination-signed-refused.xml', 'validate'];
        yield 'authenticated by the binding' => ['behaviour/authn-request-without-destination.xml', 'binding'];
    }

    /**
     * SAML Core §3.2.1: the Destination of a request that nothing signed is optional.
     */
    #[Test]
    public function itAcceptsAnUnsignedRequestWithoutDestination(): void
    {
        // Given
        $request = AuthnRequestFixtures::load('behaviour/authn-request-without-destination.xml');

        // When
        $accepted = $this->validate($request);

        // Then
        static::assertSame([null, Authentication::None], [
            $accepted->request->destination,
            $accepted->authentication,
        ]);
    }

    /**
     * M-8, section 6.2 step 3: the request arrived at one of our single sign-on services, any of them.
     */
    #[Test]
    public function itAcceptsARequestAtAnyOfOurSingleSignOnServices(): void
    {
        // Given
        $receivedAt = AuthnRequestFixtures::SINGLE_SIGN_ON . '/post';
        $request = AuthnRequestFixtures::request(['Destination' => $receivedAt]);

        // When
        $accepted = AuthnRequestFixtures::validator()->validate(
            $request,
            AuthnRequestFixtures::serviceProvider(),
            AuthnRequestFixtures::identityProvider(),
            $receivedAt,
        );

        // Then
        static::assertSame($receivedAt, $accepted->request->destination);
    }

    /**
     * M-8, section 6.2 step 3: the URL the consumer says the request arrived at is one of our single sign-on
     * services, the Destination equal to it or absent.
     */
    #[Test]
    #[DataProvider('provideDestinationsOfNoService')]
    public function itRefusesAUrlOfArrivalThatIsNotOurs(?string $destination): void
    {
        // Given
        $receivedAt = AuthnRequestFixtures::IDENTITY_PROVIDER . '/other';
        $request = AuthnRequestFixtures::request(['Destination' => $destination]);

        // Then
        $this->expectException(DestinationMismatch::class);
        $this->expectExceptionMessageIs('The URL at which the request arrived is not a single sign-on service of the identity provider (M-8).');

        // When
        AuthnRequestFixtures::validator()->validate(
            $request,
            AuthnRequestFixtures::serviceProvider(),
            AuthnRequestFixtures::identityProvider(),
            $receivedAt,
        );
    }

    /**
     * @return iterable<string, array{?string}>
     */
    public static function provideDestinationsOfNoService(): iterable
    {
        yield 'the Destination that URL' => [AuthnRequestFixtures::IDENTITY_PROVIDER . '/other'];
        yield 'no Destination' => [null];
    }

    /**
     * M-8, Profiles §4.1.4.1: the Issuer is the service provider's entity ID, its Format omitted or entity.
     */
    #[Test]
    #[DataProvider('provideIssuersRefused')]
    public function itRefusesAnIssuerOtherThanTheServiceProvider(string $path, string $message): void
    {
        // Given
        $request = AuthnRequestFixtures::load($path);

        // Then
        $this->expectException(IssuerMismatch::class);
        $this->expectExceptionMessageIs($message);

        // When
        $this->validate($request);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideIssuersRefused(): iterable
    {
        yield 'another entity' => [
            'hostile/authn-request-issuer-another-entity-refused.xml',
            'The Issuer is not the entity ID of the peer (M-8).',
        ];
        yield 'with Format unspecified' => [
            'hostile/authn-request-issuer-format-unspecified-refused.xml',
            'The Issuer has a Format other than entity (M-8).',
        ];
        yield 'with a NameQualifier, which the adversarial pass found accepted (section 9.8)' => [
            'hostile/adversarial-authn-request-issuer-name-qualifier-refused.xml',
            'The Issuer carries a NameQualifier, an SPNameQualifier or an SPProvidedID, which an entity identifier omits (M-8).',
        ];
    }

    /**
     * M-8, §9.2 row 16, "the Issuer ... with a NameQualifier, an SPNameQualifier or an SPProvidedID", SAML Core §8.3.6:
     * the Issuer of a request carries none of the three qualifiers an entity identifier omits.
     */
    #[Test]
    #[DataProvider('provideIssuerQualifiers')]
    public function itRefusesAnIssuerWithAQualifier(string $qualifier): void
    {
        // Given
        $request = AuthnRequestFixtures::request(children: sprintf(
            '<saml:Issuer %s="%s">%s</saml:Issuer>',
            $qualifier,
            AuthnRequestFixtures::SERVICE_PROVIDER,
            AuthnRequestFixtures::SERVICE_PROVIDER,
        ));

        // Then
        $this->expectException(IssuerMismatch::class);
        $this->expectExceptionMessageIs('The Issuer carries a NameQualifier, an SPNameQualifier or an SPProvidedID, which an entity identifier omits (M-8).');

        // When
        $this->validate($request);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideIssuerQualifiers(): iterable
    {
        yield 'NameQualifier' => ['NameQualifier'];
        yield 'SPNameQualifier' => ['SPNameQualifier'];
        yield 'SPProvidedID' => ['SPProvidedID'];
    }

    /**
     * M-8, SAML Core §2.2.5: an Issuer whose Format is entity, what its absence means.
     */
    #[Test]
    public function itAcceptsAnIssuerOfFormatEntity(): void
    {
        // Given
        $request = AuthnRequestFixtures::request(
            children: '<saml:Issuer Format="'
            . NameIdFormat::Entity->value
            . '">'
            . AuthnRequestFixtures::SERVICE_PROVIDER
            . '</saml:Issuer>',
        );

        // When
        $accepted = $this->validate($request);

        // Then
        static::assertSame(AuthnRequestFixtures::SERVICE_PROVIDER, $accepted->request->issuer->entityId);
    }

    /**
     * M-7: the IssueInstant at now plus the skew, and exactly maxMessageAge old, the two edges of its window.
     */
    #[Test]
    #[DataProvider('provideEdgesOfTheWindow')]
    public function itAcceptsAnIssueInstantAtTheEdgesOfItsWindow(int $seconds): void
    {
        // Given
        $request = AuthnRequestFixtures::load(self::UNSIGNED);

        // When
        $accepted = AuthnRequestFixtures::validator($seconds)->validate(
            $request,
            AuthnRequestFixtures::serviceProvider(),
            AuthnRequestFixtures::identityProvider(),
            AuthnRequestFixtures::SINGLE_SIGN_ON,
        );

        // Then
        static::assertSame(AuthnRequestFixtures::ID, $accepted->request->id);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideEdgesOfTheWindow(): iterable
    {
        yield 'issued at now plus the skew' => [-180];
        yield 'issued maxMessageAge ago' => [300];
    }

    /**
     * §9.2 row 18, M-7: an IssueInstant one second beyond now plus the skew, or one second
     * older than maxMessageAge.
     */
    #[Test]
    #[DataProvider('provideOutsideTheWindow')]
    public function itRefusesAnIssueInstantOutsideItsWindow(int $seconds, string $message): void
    {
        // Given
        $request = AuthnRequestFixtures::load(self::UNSIGNED);

        // Then
        $this->expectException(OutsideValidityWindow::class);
        $this->expectExceptionMessageIs($message);

        // When
        AuthnRequestFixtures::validator($seconds)->validate(
            $request,
            AuthnRequestFixtures::serviceProvider(),
            AuthnRequestFixtures::identityProvider(),
            AuthnRequestFixtures::SINGLE_SIGN_ON,
        );
    }

    /**
     * @return iterable<string, array{int, string}>
     */
    public static function provideOutsideTheWindow(): iterable
    {
        yield 'issued one second beyond now plus the skew' => [
            -181,
            'The IssueInstant of the request is later than now plus the clock skew (M-7).',
        ];
        yield 'issued one second before maxMessageAge' => [
            301,
            'The IssueInstant of the request is older than maxMessageAge (M-7).',
        ];
    }

    /**
     * M-7: now is read once per validation.
     */
    #[Test]
    #[DataProvider('provideValidations')]
    public function itReadsTheClockOnce(string $validation): void
    {
        // Given
        $clock = $this->createMock(ClockInterface::class);
        $clock->expects($this->once())->method('now')->willReturn(new DateTimeImmutable(AuthnRequestFixtures::NOW));
        $validator = new AuthnRequestValidator(SamlLoader::create(), $clock);

        // When
        $accepted = $validation === 'binding'
            ? $validator->validateAuthenticatedByBinding(
                AuthnRequestFixtures::load(self::UNSIGNED),
                AuthnRequestFixtures::serviceProvider(),
                AuthnRequestFixtures::identityProvider(),
                AuthnRequestFixtures::SINGLE_SIGN_ON,
            )
            : $validator->validate(
                AuthnRequestFixtures::load(self::UNSIGNED),
                AuthnRequestFixtures::serviceProvider(),
                AuthnRequestFixtures::identityProvider(),
                AuthnRequestFixtures::SINGLE_SIGN_ON,
            );

        // Then
        static::assertSame(AuthnRequestFixtures::ID, $accepted->request->id);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideValidations(): iterable
    {
        yield 'validate()' => ['validate'];
        yield 'validateAuthenticatedByBinding()' => ['binding'];
    }

    /**
     * Section 6.2 step 5: what the request asks, returned and never enforced: ForceAuthn, IsPassive in any of the
     * forms of a boolean (M-6), the NameIDPolicy and the requested authentication context; the attributes the model
     * does not read left aside.
     */
    #[Test]
    public function itReturnsWhatTheRequestAsks(): void
    {
        // Given
        $request = AuthnRequestFixtures::load('behaviour/authn-request-everything-asked.xml');

        // When
        $accepted = $this->validate($request);

        // Then
        static::assertEquals(
            [
                true,
                true,
                new NameIdPolicy(NameIdFormat::Persistent->value, 'https://affiliation.example.com', true),
                new RequestedAuthnContext(AuthnContextComparison::Minimum, [
                    'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
                    'urn:oasis:names:tc:SAML:2.0:ac:classes:X509',
                ]),
            ],
            [
                $accepted->request->forceAuthn,
                $accepted->request->isPassive,
                $accepted->request->nameIdPolicy,
                $accepted->request->requestedAuthnContext,
            ],
        );
    }

    /**
     * SAML Core §3.4.1: ForceAuthn and IsPassive false, written as false or 0, or absent.
     */
    #[Test]
    #[DataProvider('provideFalseFlags')]
    public function itReadsFlagsThatAreFalse(?string $value): void
    {
        // Given
        $request = AuthnRequestFixtures::request(['ForceAuthn' => $value, 'IsPassive' => $value]);

        // When
        $accepted = $this->validate($request);

        // Then
        static::assertSame([false, false], [$accepted->request->forceAuthn, $accepted->request->isPassive]);
    }

    /**
     * @return iterable<string, array{?string}>
     */
    public static function provideFalseFlags(): iterable
    {
        yield 'false' => ['false'];
        yield '0' => ['0'];
        yield 'absent' => [null];
    }

    /**
     * §9.3 row 9, "a samlp:Extensions with content in a request": accepted, not read.
     */
    #[Test]
    public function itAcceptsExtensionsWithContentUnread(): void
    {
        // Given
        $request = AuthnRequestFixtures::load('behaviour/authn-request-extensions-with-content.xml');

        // When
        $accepted = $this->validate($request);

        // Then
        static::assertSame([AuthnRequestFixtures::ID, null, null], [
            $accepted->request->id,
            $accepted->request->nameIdPolicy,
            $accepted->request->requestedAuthnContext,
        ]);
    }

    /**
     * Section 6.2 step 5, section 8, M-5, M-12: a NameIDPolicy or a requested authentication context outside its
     * vocabulary.
     *
     * @param class-string<MessageRefused> $exception
     */
    #[Test]
    #[DataProvider('provideAsksOutsideTheirVocabulary')]
    public function itRefusesWhatTheRequestAsksOutsideItsVocabulary(
        string $path,
        string $exception,
        string $message,
    ): void {
        // Given
        $request = AuthnRequestFixtures::load($path);

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        $this->validate($request);
    }

    /**
     * @return iterable<string, array{string, class-string<MessageRefused>, string}>
     */
    public static function provideAsksOutsideTheirVocabulary(): iterable
    {
        yield 'a NameIDPolicy format of its own' => [
            'hostile/authn-request-name-id-policy-unknown-format-refused.xml',
            InvalidNameId::class,
            'The format of a samlp:NameIDPolicy is neither one of the eight of SAML Core nor encrypted (M-12).',
        ];
        yield 'a NameIDPolicy holding an element' => [
            'hostile/authn-request-name-id-policy-with-child-refused.xml',
            MalformedMessage::class,
            'The samlp:NameIDPolicy holds an element, which the schema does not allow there (M-5).',
        ];
        yield 'a saml:AuthnContextDeclRef' => [
            'hostile/authn-request-authn-context-decl-ref-refused.xml',
            Unsupported::class,
            'The samlp:RequestedAuthnContext holds a saml:AuthnContextDeclRef, which the package does not support (section 8).',
        ];
        yield 'a requested context without class reference' => [
            'hostile/authn-request-authn-context-without-class-ref-refused.xml',
            MalformedMessage::class,
            'A samlp:RequestedAuthnContext holds no saml:AuthnContextClassRef (M-5).',
        ];
        yield 'a requested context holding another element' => [
            'hostile/authn-request-authn-context-unknown-child-refused.xml',
            MalformedMessage::class,
            'The samlp:RequestedAuthnContext holds a child other than saml:AuthnContextClassRef (M-5).',
        ];
    }

    /**
     * Section 9.2 row of M-6 (IsPassive="TRUE", " true", "yes", a Version of 2.1, a time without Z), section 9.7: a
     * value not of its lexical form, or a required attribute absent (M-5).
     *
     * @param array<string, ?string> $changes
     */
    #[Test]
    #[DataProvider('provideValuesNotOfTheirForm')]
    public function itRefusesAValueNotOfItsLexicalForm(array $changes, string $children, string $message): void
    {
        // Given
        $request = AuthnRequestFixtures::request($changes, $children);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);

        // When
        $this->validate($request);
    }

    /**
     * @return iterable<string, array{array<string, ?string>, string, string}>
     */
    public static function provideValuesNotOfTheirForm(): iterable
    {
        $issuer = AuthnRequestFixtures::ISSUER;
        $boolean = 'A boolean is not one of true, false, 1 and 0 (M-6).';
        yield 'Version="2.1"' => [['Version' => '2.1'], $issuer, 'The version is not 2.0 (M-6).'];
        yield 'no Version' => [['Version' => null], $issuer, 'The samlp:AuthnRequest has no Version (M-5).'];
        yield 'no ID' => [['ID' => null], $issuer, 'The samlp:AuthnRequest has no ID (M-5).'];
        yield 'no IssueInstant' => [
            ['IssueInstant' => null],
            $issuer,
            'The samlp:AuthnRequest has no IssueInstant (M-5).',
        ];
        yield 'an IssueInstant without Z' => [
            ['IssueInstant' => '2026-10-01T12:00:00'],
            $issuer,
            'A time is not an xs:dateTime in UTC with the Z designator (M-6).',
        ];
        yield 'a relative Destination' => [['Destination' => '/saml/sso'], $issuer, 'A URI is not absolute (M-6).'];
        yield 'IsPassive="TRUE"' => [['IsPassive' => 'TRUE'], $issuer, $boolean];
        yield 'IsPassive=" true"' => [['IsPassive' => ' true'], $issuer, $boolean];
        yield 'IsPassive="yes"' => [['IsPassive' => 'yes'], $issuer, $boolean];
        yield 'ForceAuthn="yes"' => [['ForceAuthn' => 'yes'], $issuer, $boolean];
        yield 'AllowCreate="yes"' => [[], $issuer . '<samlp:NameIDPolicy AllowCreate="yes"/>', $boolean];
        yield 'a NameIDPolicy SPNameQualifier that is not a URI' => [
            [],
            $issuer . '<samlp:NameIDPolicy SPNameQualifier="affiliation"/>',
            'A URI is not absolute (M-6).',
        ];
        yield 'Comparison="Exact"' => [
            [],
            $issuer
                . '<samlp:RequestedAuthnContext Comparison="Exact"><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:X509</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>',
            'The Comparison of a samlp:RequestedAuthnContext is not one of exact, minimum, maximum and better (M-5).',
        ];
        yield 'a class reference that is not a URI' => [
            [],
            $issuer
                . '<samlp:RequestedAuthnContext><saml:AuthnContextClassRef>X509</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>',
            'A URI is not absolute (M-6).',
        ];
    }

    /**
     * Section 6.2: the rules apply in their order, the first a request breaks is the one that refuses it; two faults
     * each, the second of a later step.
     *
     * @param array<string, ?string> $changes
     * @param class-string<MessageRefused> $exception
     */
    #[Test]
    #[DataProvider('provideTwoFaults')]
    public function itAppliesTheRulesInTheOrderOfSection62(
        array $changes,
        string $children,
        string $exception,
        string $message,
    ): void {
        // Given
        $request = AuthnRequestFixtures::request($changes, $children);

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        $this->validate($request);
    }

    /**
     * @return iterable<string, array{array<string, ?string>, string, class-string<MessageRefused>, string}>
     */
    public static function provideTwoFaults(): iterable
    {
        $issuer = AuthnRequestFixtures::ISSUER;
        $another = '<saml:Issuer>https://attacker.example.com/saml</saml:Issuer>';
        yield 'step 1 before step 3: a saml:Subject and Version="2.1"' => [
            ['Version' => '2.1'],
            $issuer . '<saml:Subject/>',
            Unsupported::class,
            'The samlp:AuthnRequest holds a saml:Subject, a saml:Conditions or a samlp:Scoping, which the package does not support (section 8).',
        ];
        yield 'the Version before the ID' => [
            ['Version' => '2.1', 'ID' => null],
            $issuer,
            MalformedMessage::class,
            'The version is not 2.0 (M-6).',
        ];
        yield 'the ID before the IssueInstant' => [
            ['ID' => null, 'IssueInstant' => null],
            $issuer,
            MalformedMessage::class,
            'The samlp:AuthnRequest has no ID (M-5).',
        ];
        yield 'the IssueInstant before the Issuer' => [
            ['IssueInstant' => '2026-10-01T12:03:01Z'],
            $another,
            OutsideValidityWindow::class,
            'The IssueInstant of the request is later than now plus the clock skew (M-7).',
        ];
        yield 'the IssueInstant before the Destination' => [
            ['IssueInstant' => '2026-10-01T11:54:59Z', 'Destination' => 'https://attacker.example.com/sso'],
            $issuer,
            OutsideValidityWindow::class,
            'The IssueInstant of the request is older than maxMessageAge (M-7).',
        ];
        yield 'a relative Destination before the Issuer' => [
            ['Destination' => '/saml/sso'],
            $another,
            MalformedMessage::class,
            'A URI is not absolute (M-6).',
        ];
        yield 'the Destination before the Issuer' => [
            ['Destination' => 'https://attacker.example.com/sso'],
            $another,
            DestinationMismatch::class,
            'The Destination of the request is not the URL at which it arrived (M-8).',
        ];
        yield 'step 3 before step 4: the Issuer and a URL the metadata does not list' => [
            ['AssertionConsumerServiceURL' => 'https://attacker.example.com/acs'],
            $another,
            IssuerMismatch::class,
            'The Issuer is not the entity ID of the peer (M-8).',
        ];
        yield 'the index next to a URL before the URL is looked for' => [
            [
                'AssertionConsumerServiceURL' => 'https://attacker.example.com/acs',
                'AssertionConsumerServiceIndex' => '0',
            ],
            $issuer,
            MalformedMessage::class,
            'An AuthnRequest carries an AssertionConsumerServiceIndex next to an AssertionConsumerServiceURL or a ProtocolBinding, which SAML Core §3.4.1 makes mutually exclusive (M-9).',
        ];
        yield 'the index over 65535 before it is looked for' => [
            [
                'AssertionConsumerServiceURL' => null,
                'ProtocolBinding' => null,
                'AssertionConsumerServiceIndex' => '65536',
            ],
            $issuer,
            MalformedMessage::class,
            'An index is not an xs:unsignedShort, digits without sign or leading zero from 0 to 65535 (M-6).',
        ];
        yield 'step 4 before step 5: HTTP-Redirect and IsPassive="yes"' => [
            ['ProtocolBinding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', 'IsPassive' => 'yes'],
            $issuer,
            Unsupported::class,
            'The ProtocolBinding of an AuthnRequest is not HTTP-POST, the one binding the package answers over (section 8).',
        ];
    }

    /**
     * The service provider and our identity provider of the fixtures, neither asking for signed requests, the request
     * arrived at our single sign-on service; $validation names the method.
     *
     * @throws MessageRefused
     * @throws RefusedXml
     */
    private function validate(UnverifiedAuthnRequest $request, string $validation = 'validate'): AcceptedAuthnRequest
    {
        $validator = AuthnRequestFixtures::validator();

        return $validation === 'binding'
            ? $validator->validateAuthenticatedByBinding(
                $request,
                AuthnRequestFixtures::serviceProvider(),
                AuthnRequestFixtures::identityProvider(),
                AuthnRequestFixtures::SINGLE_SIGN_ON,
            )
            : $validator->validate(
                $request,
                AuthnRequestFixtures::serviceProvider(),
                AuthnRequestFixtures::identityProvider(),
                AuthnRequestFixtures::SINGLE_SIGN_ON,
            );
    }
}
