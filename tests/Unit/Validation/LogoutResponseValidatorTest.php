<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Validation;

use Beffroi\Saml2\Model\Exception\DestinationMismatch;
use Beffroi\Saml2\Model\Exception\InResponseToMismatch;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Exception\IssuerMismatch;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutResponse;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Validation\AcceptedLogoutResponse;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Xml\Core\Document;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strtr;

/**
 * Sections 5.6 and 6.4: a samlp:LogoutResponse validated by either role, signed (M-2, SAML Profiles §4.4.4.2) or
 * authenticated by its binding (section 6.8), answering the request the consumer names (M-10); the service provider's
 * response to the identity provider's request unless a test says otherwise. The rules of the header it shares with a
 * request are LogoutRequestValidatorTest's.
 */
final class LogoutResponseValidatorTest extends TestCase
{
    private const string SIGNED = 'behaviour/logout-response-written-and-signed-by-the-writer.xml';

    private const string REDIRECT = 'behaviour/logout-response-written-for-http-redirect.xml';

    /**
     * Section 6.4, M-2, M-1: a response signed by the peer, at the ResponseLocation of our single logout service on
     * HTTP-POST (SAML Metadata §2.2.2), is verified with the keys of its metadata and read from what the signature
     * covered.
     */
    #[Test]
    public function itAcceptsAResponseSignedByThePeer(): void
    {
        // Given
        $response = UnverifiedLogoutResponse::of(MetadataFixtures::load(self::SIGNED));

        // When
        $accepted = LogoutFixtures::responseValidator()->validate(
            $response,
            LogoutFixtures::serviceProvider(),
            LogoutFixtures::identityProvider(),
            LogoutFixtures::IDP_SLO_RESPONSE,
            LogoutFixtures::REQUEST_ID,
        );

        // Then
        static::assertEquals(
            new AcceptedLogoutResponse(LogoutFixtures::response(), Authentication::XmlSignature),
            $accepted,
        );
    }

    /**
     * Section 6.8, SAML Metadata §2.2.2: a response the binding authenticated, at the Location of our single logout
     * service on HTTP-Redirect, which has no ResponseLocation, is read as received.
     */
    #[Test]
    public function itAcceptsAResponseTheBindingAuthenticated(): void
    {
        // When
        $accepted = $this->byBinding(MetadataFixtures::load(self::REDIRECT));

        // Then
        static::assertEquals(
            new AcceptedLogoutResponse(
                LogoutFixtures::response(destination: LogoutFixtures::IDP_SLO),
                Authentication::Binding,
            ),
            $accepted,
        );
    }

    /**
     * §9.2 row 34, M-10: a signed response that answers another request than the one the consumer names.
     */
    #[Test]
    public function itRefusesAResponseAnsweringAnotherRequest(): void
    {
        // Given
        $response = UnverifiedLogoutResponse::of(
            MetadataFixtures::load('hostile/logout-response-answering-another-request-refused.xml'),
        );

        // Then
        $this->expectException(InResponseToMismatch::class);
        $this->expectExceptionMessageIs('The InResponseTo of the LogoutResponse is not the ID of the LogoutRequest the consumer names (M-10).');

        // When
        LogoutFixtures::responseValidator()->validate(
            $response,
            LogoutFixtures::serviceProvider(),
            LogoutFixtures::identityProvider(),
            LogoutFixtures::IDP_SLO_RESPONSE,
            LogoutFixtures::REQUEST_ID,
        );
    }

    /**
     * §9.2 row 17, M-10: a response that names no request answers none.
     */
    #[Test]
    public function itRefusesAResponseWithoutInResponseTo(): void
    {
        // Given
        $document = $this->variant([' InResponseTo="' . LogoutFixtures::REQUEST_ID . '"' => '']);

        // Then
        $this->expectException(InResponseToMismatch::class);
        $this->expectExceptionMessageIs('The InResponseTo of the LogoutResponse is not the ID of the LogoutRequest the consumer names (M-10).');

        // When
        $this->byBinding($document);
    }

    /**
     * M-2, SAML Profiles §4.4.4.2: an unsigned LogoutResponse given to validate() is refused; the same document is
     * accepted by the binding path.
     */
    #[Test]
    public function itRefusesAnUnsignedResponseGivenToValidate(): void
    {
        // Given
        $response = UnverifiedLogoutResponse::of(MetadataFixtures::load(self::REDIRECT));

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs('The message carries no ds:Signature, which the profile requires (M-2).');

        // When
        LogoutFixtures::responseValidator()->validate(
            $response,
            LogoutFixtures::serviceProvider(),
            LogoutFixtures::identityProvider(),
            LogoutFixtures::IDP_SLO,
            LogoutFixtures::REQUEST_ID,
        );
    }

    /**
     * Section 5.6, SAML Bindings §3.4.4.1: a response the binding authenticated carries no ds:Signature.
     */
    #[Test]
    public function itRefusesASignatureInAResponseTheBindingAuthenticated(): void
    {
        // Given
        $document = MetadataFixtures::load(self::SIGNED);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The message carries a ds:Signature, which the HTTP-Redirect encoding removes (SAML Bindings §3.4.4.1).');

        // When
        $this->byBinding($document, LogoutFixtures::IDP_SLO_RESPONSE);
    }

    /**
     * §9.3 row 15, section 6.4: a signed response whose status is Success with PartialLogout as second level is an
     * answer, returned and not thrown.
     */
    #[Test]
    public function itReturnsAPartialLogout(): void
    {
        // Given
        $response = UnverifiedLogoutResponse::of(MetadataFixtures::load('behaviour/logout-response-partial-logout.xml'));

        // When
        $accepted = LogoutFixtures::responseValidator()->validate(
            $response,
            LogoutFixtures::serviceProvider(),
            LogoutFixtures::identityProvider(),
            LogoutFixtures::IDP_SLO_RESPONSE,
            LogoutFixtures::REQUEST_ID,
        );

        // Then
        static::assertEquals(LogoutFixtures::partialLogout(), $accepted->response->status);
    }

    /**
     * Section 6.4, M-13: whatever the status, a failure included, it is returned, never thrown; a second-level code
     * SAML Core does not list reads as null.
     */
    #[Test]
    #[DataProvider('provideStatuses')]
    public function itReturnsTheStatusWhateverItIs(string $status, Status $expected): void
    {
        // Given
        $document = $this->variant([
            '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>' => $status,
        ]);

        // When
        $accepted = $this->byBinding($document);

        // Then
        static::assertEquals($expected, $accepted->response->status);
    }

    /**
     * @return iterable<string, array{string, Status}>
     */
    public static function provideStatuses(): iterable
    {
        $top = 'urn:oasis:names:tc:SAML:2.0:status:';
        yield 'Responder' => ['<samlp:StatusCode Value="' . $top . 'Responder"/>', new Status(StatusCode::Responder)];
        yield 'Requester, RequestDenied' => [
            '<samlp:StatusCode Value="'
                . $top
                . 'Requester"><samlp:StatusCode Value="'
                . $top
                . 'RequestDenied"/></samlp:StatusCode>',
            new Status(StatusCode::Requester, SecondLevelStatusCode::RequestDenied),
        ];
        yield 'Responder, a second level SAML Core does not list' => [
            '<samlp:StatusCode Value="'
                . $top
                . 'Responder"><samlp:StatusCode Value="urn:example:status:busy"/></samlp:StatusCode>',
            new Status(StatusCode::Responder),
        ];
    }

    /**
     * SAML Core §3.2.2: the StatusMessage and the StatusDetail are accepted and not read, nor is a third-level code.
     */
    #[Test]
    public function itReadsNeitherTheStatusMessageNorTheStatusDetail(): void
    {
        // When
        $accepted = $this->byBinding(MetadataFixtures::load('behaviour/logout-response-status-message-and-detail.xml'));

        // Then
        static::assertEquals(LogoutFixtures::partialLogout(), $accepted->response->status);
    }

    /**
     * M-5, SAML Core §3.2.2.2: the top-level status code is one of the four of SAML Core, and every code read has a
     * Value.
     */
    #[Test]
    #[DataProvider('provideStatusValuesRefused')]
    public function itRefusesAStatusCodeValue(string $path, string $message): void
    {
        // Given
        $document = MetadataFixtures::load($path);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);

        // When
        $this->byBinding($document);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideStatusValuesRefused(): iterable
    {
        yield 'a top-level code without Value' => [
            'hostile/logout-response-status-code-without-value-refused.xml',
            'An samlp:StatusCode has no Value (M-5).',
        ];
        yield 'a second-level code without Value' => [
            'hostile/logout-response-second-level-status-code-without-value-refused.xml',
            'An samlp:StatusCode has no Value (M-5).',
        ];
    }

    /**
     * M-5, SAML Core §3.2.2.2: a top-level status code outside the four of SAML Core; the message carries nothing of
     * it (M-16).
     */
    #[Test]
    public function itRefusesAnUnknownTopLevelStatusCode(): void
    {
        // Given
        $document = $this->variant(['status:Success' => 'status:PartialLogout']);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The top-level status code is not one of the four of SAML Core (M-5).');

        // When
        $this->byBinding($document);
    }

    /**
     * M-5, section 6.4, SAML Profiles §4.4.4.2: the structure of the response and of its status is the schema's,
     * checked before any signature.
     */
    #[Test]
    #[DataProvider('provideStructuresRefused')]
    public function itRefusesAStructureTheSchemaDoesNotAllow(string $path, string $message): void
    {
        // Given
        $response = UnverifiedLogoutResponse::of(MetadataFixtures::load($path));

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);

        // When
        LogoutFixtures::responseValidator()->validate(
            $response,
            LogoutFixtures::serviceProvider(),
            LogoutFixtures::identityProvider(),
            LogoutFixtures::IDP_SLO,
            LogoutFixtures::REQUEST_ID,
        );
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideStructuresRefused(): iterable
    {
        yield 'no saml:Issuer' => [
            'hostile/logout-response-without-issuer-refused.xml',
            'A samlp:LogoutResponse holds no saml:Issuer, which the profile requires (SAML Profiles §4.4.4.2).',
        ];
        yield 'no samlp:Status' => [
            'hostile/logout-response-without-status-refused.xml',
            'An samlp:LogoutResponse holds no samlp:Status (M-5).',
        ];
        yield 'a samlp:Status without samlp:StatusCode' => [
            'hostile/logout-response-status-without-status-code-refused.xml',
            'An samlp:Status holds no samlp:StatusCode (M-5).',
        ];
        yield 'two samlp:StatusCode' => [
            'hostile/logout-response-two-status-codes-refused.xml',
            'An samlp:Status holds more than one samlp:StatusCode (M-5).',
        ];
        yield 'two samlp:StatusMessage' => [
            'hostile/logout-response-two-status-messages-refused.xml',
            'An samlp:Status holds more than one samlp:StatusMessage (M-5).',
        ];
        yield 'two samlp:StatusDetail' => [
            'hostile/logout-response-two-status-details-refused.xml',
            'An samlp:Status holds more than one samlp:StatusDetail (M-5).',
        ];
        yield 'a samlp:StatusDetail before a samlp:StatusMessage' => [
            'hostile/logout-response-status-detail-before-status-message-refused.xml',
            'An samlp:Status holds a child the schema does not allow there, or out of its order (M-5).',
        ];
        yield 'two second-level codes' => [
            'hostile/logout-response-two-second-level-status-codes-refused.xml',
            'An samlp:StatusCode holds more than one samlp:StatusCode (M-5).',
        ];
        yield 'two third-level codes' => [
            'hostile/logout-response-two-third-level-status-codes-refused.xml',
            'An samlp:StatusCode holds more than one samlp:StatusCode (M-5).',
        ];
    }

    /**
     * Sections 5.6 and 6.4, SAML Metadata §2.2.2: a response arrives at the ResponseLocation of a single logout
     * service that has one, not at its Location, where requests arrive.
     */
    #[Test]
    public function itRefusesAResponseAtTheLocationOfAServiceWithAResponseLocation(): void
    {
        // Given
        $document = $this->variant([
            'Destination="' . LogoutFixtures::IDP_SLO . '"' => 'Destination="' . LogoutFixtures::IDP_SLO_POST . '"',
        ]);

        // Then
        $this->expectException(DestinationMismatch::class);
        $this->expectExceptionMessageIs('The URL at which the message arrived is not one of our single logout services (M-8).');

        // When
        $this->byBinding($document, LogoutFixtures::IDP_SLO_POST);
    }

    /**
     * Section 6.4: the identity provider's response to the service provider's request, at the Location of the service
     * provider's single logout service, which has no ResponseLocation.
     */
    #[Test]
    public function itAcceptsAResponseToTheServiceProvider(): void
    {
        // Given
        $document = $this->variant([
            '>' . LogoutFixtures::SP . '</saml:Issuer>' => '>' . LogoutFixtures::IDP . '</saml:Issuer>',
            'Destination="' . LogoutFixtures::IDP_SLO . '"' => 'Destination="' . LogoutFixtures::SP_SLO . '"',
        ]);

        // When
        $accepted = LogoutFixtures::responseValidator()->validateAuthenticatedByBinding(
            UnverifiedLogoutResponse::of($document),
            LogoutFixtures::identityProvider(),
            LogoutFixtures::serviceProvider(),
            LogoutFixtures::SP_SLO,
            LogoutFixtures::REQUEST_ID,
        );

        // Then
        static::assertSame([LogoutFixtures::IDP, LogoutFixtures::SP_SLO], [
            $accepted->response->issuer->entityId,
            $accepted->response->destination,
        ]);
    }

    /**
     * M-8, §9.2 row "the Issuer ... with a NameQualifier, an SPNameQualifier or an SPProvidedID", SAML Core §8.3.6: the
     * Issuer of a response carries none of the three qualifiers an entity identifier omits.
     *
     * @param array<string, string> $replacements
     */
    #[Test]
    #[DataProvider('provideIssuerQualifiers')]
    public function itRefusesAnIssuerWithAQualifier(string $path, array $replacements): void
    {
        // Given
        $document = SamlLoader::create()->load(strtr(MetadataFixtures::bytes($path), $replacements));

        // Then
        $this->expectException(IssuerMismatch::class);
        $this->expectExceptionMessageIs('The Issuer carries a NameQualifier, an SPNameQualifier or an SPProvidedID, which an entity identifier omits (M-8).');

        // When
        $this->byBinding($document);
    }

    /**
     * @return iterable<string, array{string, array<string, string>}>
     */
    public static function provideIssuerQualifiers(): iterable
    {
        yield 'an SPProvidedID, which the adversarial pass found accepted (section 9.8)' => [
            'hostile/adversarial-logout-response-issuer-sp-provided-id-refused.xml',
            [],
        ];
        foreach (['NameQualifier', 'SPNameQualifier', 'SPProvidedID'] as $qualifier) {
            yield 'a ' . $qualifier => [
                self::REDIRECT,
                ['<saml:Issuer>' => '<saml:Issuer ' . $qualifier . '="' . LogoutFixtures::SP . '">'],
            ];
        }
    }

    /**
     * Section 5.6: our role is the one that faces the peer's.
     */
    #[Test]
    #[DataProvider('provideRolesThatDoNotFaceEachOther')]
    public function itRefusesRolesThatDoNotFaceEachOther(
        IdentityProvider|ServiceProvider $peer,
        IdentityProvider|ServiceProvider $self,
    ): void {
        // Given
        $response = UnverifiedLogoutResponse::of(MetadataFixtures::load(self::REDIRECT));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('Our role is the one that faces the peer\'s, a service provider facing an identity provider or the reverse (section 5.6).');

        // When
        LogoutFixtures::responseValidator()->validateAuthenticatedByBinding(
            $response,
            $peer,
            $self,
            LogoutFixtures::IDP_SLO,
            LogoutFixtures::REQUEST_ID,
        );
    }

    /**
     * @return iterable<string, array{IdentityProvider|ServiceProvider, IdentityProvider|ServiceProvider}>
     */
    public static function provideRolesThatDoNotFaceEachOther(): iterable
    {
        yield 'two identity providers' => [LogoutFixtures::identityProvider(), LogoutFixtures::identityProvider()];
        yield 'two service providers' => [LogoutFixtures::serviceProvider(), LogoutFixtures::serviceProvider()];
    }

    /**
     * The response of the fixture for HTTP-Redirect with the replacements made, loaded with SamlLoader::create().
     *
     * @param array<string, string> $replacements
     */
    private function variant(array $replacements): Document
    {
        return SamlLoader::create()->load(strtr(MetadataFixtures::bytes(self::REDIRECT), $replacements));
    }

    /**
     * The service provider's response given to the identity provider's validateAuthenticatedByBinding().
     */
    private function byBinding(
        Document $document,
        string $receivedAt = LogoutFixtures::IDP_SLO,
    ): AcceptedLogoutResponse {
        return LogoutFixtures::responseValidator()->validateAuthenticatedByBinding(
            UnverifiedLogoutResponse::of($document),
            LogoutFixtures::serviceProvider(),
            LogoutFixtures::identityProvider(),
            $receivedAt,
            LogoutFixtures::REQUEST_ID,
        );
    }
}
