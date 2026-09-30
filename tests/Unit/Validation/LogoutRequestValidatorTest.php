<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Validation;

use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Exception\DestinationMismatch;
use Beffroi\Saml2\Model\Exception\InvalidNameId;
use Beffroi\Saml2\Model\Exception\IssuerMismatch;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\MessageRefused;
use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutRequest;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Validation\AcceptedLogoutRequest;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Dsig\Exception\SignatureMismatch;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strtr;

/**
 * Sections 5.6 and 6.3: a samlp:LogoutRequest validated by either role, signed (M-2, SAML Profiles §4.4.4.1) or
 * authenticated by its binding (section 6.8); the identity provider's request to the service provider unless a test
 * says otherwise.
 */
final class LogoutRequestValidatorTest extends TestCase
{
    private const string SIGNED = 'behaviour/logout-request-written-and-signed-by-the-writer.xml';

    private const string REDIRECT = 'behaviour/logout-request-written-for-http-redirect.xml';

    /**
     * Section 6.3, M-2, M-1: a request signed by the peer is verified with the keys of its metadata and read from what
     * the signature covered.
     */
    #[Test]
    public function itAcceptsARequestSignedByThePeer(): void
    {
        // Given
        $request = UnverifiedLogoutRequest::of(MetadataFixtures::load(self::SIGNED));

        // When
        $accepted = LogoutFixtures::requestValidator()->validate(
            $request,
            LogoutFixtures::identityProvider(),
            LogoutFixtures::serviceProvider(),
            LogoutFixtures::SP_SLO,
        );

        // Then
        static::assertEquals(
            new AcceptedLogoutRequest(LogoutFixtures::request(), Authentication::XmlSignature),
            $accepted,
        );
    }

    /**
     * Section 6.8, SAML Bindings §3.4.4.1: a request whose signature over the query string saml2-bindings verified is
     * read as received.
     */
    #[Test]
    public function itAcceptsARequestTheBindingAuthenticated(): void
    {
        // When
        $accepted = $this->byBinding(MetadataFixtures::load(self::REDIRECT));

        // Then
        static::assertEquals(new AcceptedLogoutRequest(LogoutFixtures::request(), Authentication::Binding), $accepted);
    }

    /**
     * §9.2 row 34, M-2, SAML Profiles §4.4.4.1: an unsigned LogoutRequest given to validate(), the path of HTTP-POST
     * and of an HTTP-Redirect without signature, is refused; the same document is accepted by the binding path.
     */
    #[Test]
    public function itRefusesAnUnsignedRequestGivenToValidate(): void
    {
        // Given
        $request = UnverifiedLogoutRequest::of(MetadataFixtures::load(self::REDIRECT));

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs('The message carries no ds:Signature, which the profile requires (M-2).');

        // When
        LogoutFixtures::requestValidator()->validate(
            $request,
            LogoutFixtures::identityProvider(),
            LogoutFixtures::serviceProvider(),
            LogoutFixtures::SP_SLO,
        );
    }

    /**
     * M-3, D-7: the keys are those of the peer's metadata; a signature by another key does not verify.
     */
    #[Test]
    public function itRefusesARequestSignedByAKeyNotOfThePeer(): void
    {
        // Given
        $request = UnverifiedLogoutRequest::of(MetadataFixtures::load(self::SIGNED));

        // Then
        $this->expectException(SignatureMismatch::class);
        $this->expectExceptionMessageIs('No trusted key verifies the signature over SignedInfo (D-7, D-8).');

        // When
        LogoutFixtures::requestValidator()->validate(
            $request,
            LogoutFixtures::identityProvider('sp'),
            LogoutFixtures::serviceProvider(),
            LogoutFixtures::SP_SLO,
        );
    }

    /**
     * M-3, section 5.3: a peer whose metadata holds no signing key cannot have signed the request.
     */
    #[Test]
    public function itRefusesWhenThePeerHasNoSigningKey(): void
    {
        // Given
        $request = UnverifiedLogoutRequest::of(MetadataFixtures::load(self::SIGNED));

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs('The metadata of the peer holds no signing key to verify the message with (M-3).');

        // When
        LogoutFixtures::requestValidator()->validate(
            $request,
            LogoutFixtures::identityProvider(''),
            LogoutFixtures::serviceProvider(),
            LogoutFixtures::SP_SLO,
        );
    }

    /**
     * Section 5.6, SAML Bindings §3.4.4.1: the HTTP-Redirect encoding removes the ds:Signature of the message; one that
     * carries it did not come that way.
     */
    #[Test]
    public function itRefusesASignatureInARequestTheBindingAuthenticated(): void
    {
        // Given
        $document = MetadataFixtures::load(self::SIGNED);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The message carries a ds:Signature, which the HTTP-Redirect encoding removes (SAML Bindings §3.4.4.1).');

        // When
        $this->byBinding($document);
    }

    /**
     * §9.2 row 34, M-7, SAML Core §3.7.1: a signed request whose NotOnOrAfter is at now minus the clock skew has
     * expired, its IssueInstant earlier still and within maxMessageAge, so that the window alone refuses it.
     */
    #[Test]
    public function itRefusesARequestWhoseNotOnOrAfterHasPassed(): void
    {
        // Given
        $request = UnverifiedLogoutRequest::of(
            MetadataFixtures::load('hostile/logout-request-not-on-or-after-passed-refused.xml'),
        );

        // Then
        $this->expectException(OutsideValidityWindow::class);
        $this->expectExceptionMessageIs('The NotOnOrAfter of the LogoutRequest is at or before now minus the clock skew (M-7).');

        // When
        LogoutFixtures::requestValidator()->validate(
            $request,
            LogoutFixtures::identityProvider(),
            LogoutFixtures::serviceProvider(),
            LogoutFixtures::SP_SLO,
        );
    }

    /**
     * §9.2 row 16, M-8, SAML Profiles §4.4.4.1: a request signed with the peer's key whose Issuer names another entity.
     */
    #[Test]
    public function itRefusesTheIssuerOfAnotherEntity(): void
    {
        // Given
        $request = UnverifiedLogoutRequest::of(
            MetadataFixtures::load('hostile/logout-request-issuer-of-another-entity-refused.xml'),
        );

        // Then
        $this->expectException(IssuerMismatch::class);
        $this->expectExceptionMessageIs('The Issuer is not the entity ID of the peer (M-8).');

        // When
        LogoutFixtures::requestValidator()->validate(
            $request,
            LogoutFixtures::identityProvider(),
            LogoutFixtures::serviceProvider(),
            LogoutFixtures::SP_SLO,
        );
    }

    /**
     * §9.2 row 36, section 7, M-17: a signed request that names one session index over the bound.
     */
    #[Test]
    public function itRefusesOneSessionIndexOverTheBound(): void
    {
        // Given
        $request = UnverifiedLogoutRequest::of(
            MetadataFixtures::load('hostile/logout-request-seventeen-session-indexes-refused.xml'),
        );

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('A LogoutRequest names more than 16 session indexes, the bound of section 7 (M-17).');

        // When
        LogoutFixtures::requestValidator()->validate(
            $request,
            LogoutFixtures::identityProvider(),
            LogoutFixtures::serviceProvider(),
            LogoutFixtures::SP_SLO,
        );
    }

    /**
     * M-17, D-6: the session indexes are counted before any key is touched, even from a peer that has none.
     */
    #[Test]
    public function itCountsTheSessionIndexesBeforeAnySignature(): void
    {
        // Given
        $request = UnverifiedLogoutRequest::of(
            MetadataFixtures::load('hostile/logout-request-seventeen-session-indexes-refused.xml'),
        );

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('A LogoutRequest names more than 16 session indexes, the bound of section 7 (M-17).');

        // When
        LogoutFixtures::requestValidator()->validate(
            $request,
            LogoutFixtures::identityProvider(''),
            LogoutFixtures::serviceProvider(),
            LogoutFixtures::SP_SLO,
        );
    }

    /**
     * §9.2 row 25, M-5, section 6.3: the structure of the request is the schema's, checked before any signature;
     * saml:BaseID is refused by name (section 8), saml:EncryptedID until sub-spike 9e (§9.2 row 29, section 6.7).
     *
     * @param class-string<MessageRefused> $exception
     */
    #[Test]
    #[DataProvider('provideStructuresRefused')]
    public function itRefusesAStructureTheSchemaDoesNotAllow(string $path, string $exception, string $message): void
    {
        // Given
        $request = UnverifiedLogoutRequest::of(MetadataFixtures::load($path));

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        LogoutFixtures::requestValidator()->validate(
            $request,
            LogoutFixtures::identityProvider(),
            LogoutFixtures::serviceProvider(),
            LogoutFixtures::SP_SLO,
        );
    }

    /**
     * @return iterable<string, array{string, class-string<MessageRefused>, string}>
     */
    public static function provideStructuresRefused(): iterable
    {
        $outOfOrder = 'The samlp:LogoutRequest holds a child out of the order of the schema, or one it does not allow there (M-5).';
        yield 'no saml:Issuer' => [
            'hostile/logout-request-without-issuer-refused.xml',
            MalformedMessage::class,
            'A samlp:LogoutRequest holds no saml:Issuer, which the profile requires (SAML Profiles §4.4.4.1).',
        ];
        yield 'the ds:Signature before the saml:Issuer' => [
            'hostile/logout-request-signature-before-issuer-refused.xml',
            MalformedMessage::class,
            $outOfOrder,
        ];
        yield 'the saml:NameID before the saml:Issuer' => [
            'hostile/logout-request-name-id-before-issuer-refused.xml',
            MalformedMessage::class,
            $outOfOrder,
        ];
        yield 'a saml:NameID after a samlp:SessionIndex' => [
            'hostile/logout-request-name-id-after-session-index-refused.xml',
            MalformedMessage::class,
            $outOfOrder,
        ];
        yield 'no saml:NameID' => [
            'hostile/logout-request-without-name-id-refused.xml',
            MalformedMessage::class,
            'The samlp:LogoutRequest holds no identifier (M-4).',
        ];
        yield 'two saml:NameID' => [
            'hostile/logout-request-two-name-ids-refused.xml',
            MalformedMessage::class,
            'The samlp:LogoutRequest holds more than one identifier (M-4).',
        ];
        yield 'a saml:BaseID' => [
            'hostile/logout-request-base-id-refused.xml',
            Unsupported::class,
            'The LogoutRequest names its principal with a saml:BaseID, which the package does not support (section 8).',
        ];
        yield 'a saml:EncryptedID' => [
            'hostile/logout-request-encrypted-id-refused.xml',
            Unsupported::class,
            'The LogoutRequest names its principal with a saml:EncryptedID, which the package does not support until sub-spike 9e (section 6.7).',
        ];
    }

    /**
     * §9.2 rows 16, 26 and 27, M-6, M-8, M-12: a value of the request that is not of its lexical form or not the
     * peer's; the message carries nothing of it (M-16).
     *
     * @param array<string, string> $replacements
     * @param class-string<MessageRefused> $exception
     */
    #[Test]
    #[DataProvider('provideValuesRefused')]
    public function itRefusesAValue(array $replacements, string $exception, string $message): void
    {
        // Given
        $document = $this->variant($replacements);

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        $this->byBinding($document);
    }

    /**
     * @return iterable<string, array{array<string, string>, class-string<MessageRefused>, string}>
     */
    public static function provideValuesRefused(): iterable
    {
        $issuer = '<saml:Issuer>' . LogoutFixtures::IDP . '</saml:Issuer>';
        $nameId = '>_7a2f4c1d9e</saml:NameID>';
        yield 'an Issuer with Format unspecified' => [
            [
                $issuer =>
                    '<saml:Issuer Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">'
                        . LogoutFixtures::IDP
                        . '</saml:Issuer>',
            ],
            IssuerMismatch::class,
            'The Issuer has a Format other than entity (M-8).',
        ];
        foreach (['NameQualifier', 'SPNameQualifier', 'SPProvidedID'] as $qualifier) {
            yield 'an Issuer with an ' . $qualifier . ' (section 9.8)' => [
                [
                    $issuer =>
                        '<saml:Issuer '
                            . $qualifier
                            . '="'
                            . LogoutFixtures::IDP
                            . '">'
                            . LogoutFixtures::IDP
                            . '</saml:Issuer>',
                ],
                IssuerMismatch::class,
                'The Issuer carries a NameQualifier, an SPNameQualifier or an SPProvidedID, which an entity identifier omits (M-8).',
            ];
        }
        yield 'an Issuer with another case' => [
            [$issuer => '<saml:Issuer>https://IDP.example.com/saml</saml:Issuer>'],
            IssuerMismatch::class,
            'The Issuer is not the entity ID of the peer (M-8).',
        ];
        yield 'Version 2.1' => [
            ['Version="2.0"' => 'Version="2.1"'],
            MalformedMessage::class,
            'The version is not 2.0 (M-6).',
        ];
        yield 'no Version' => [
            ['Version="2.0"' => ''],
            MalformedMessage::class,
            'The samlp:LogoutRequest has no Version (M-5).',
        ];
        yield 'no ID' => [
            ['ID="' . LogoutFixtures::REQUEST_ID . '"' => ''],
            MalformedMessage::class,
            'The samlp:LogoutRequest has no ID (M-5).',
        ];
        yield 'no IssueInstant' => [
            ['IssueInstant="2026-09-30T12:00:00Z"' => ''],
            MalformedMessage::class,
            'The samlp:LogoutRequest has no IssueInstant (M-5).',
        ];
        yield 'an IssueInstant with +00:00' => [
            ['IssueInstant="2026-09-30T12:00:00Z"' => 'IssueInstant="2026-09-30T12:00:00+00:00"'],
            MalformedMessage::class,
            'A time is not an xs:dateTime in UTC with the Z designator (M-6).',
        ];
        yield 'a NotOnOrAfter without Z' => [
            ['NotOnOrAfter="2026-09-30T12:05:00Z"' => 'NotOnOrAfter="2026-09-30T12:05:00"'],
            MalformedMessage::class,
            'A time is not an xs:dateTime in UTC with the Z designator (M-6).',
        ];
        yield 'an empty NameID' => [
            [$nameId => '></saml:NameID>'],
            InvalidNameId::class,
            'The NameID is empty (M-12).',
        ];
        yield 'a NameID with a leading space' => [
            [$nameId => '> _7a2f4c1d9e</saml:NameID>'],
            InvalidNameId::class,
            'The NameID starts or ends with whitespace or a control character, or is not UTF-8 (M-12).',
        ];
        yield 'an unknown NameID Format' => [
            ['nameid-format:persistent' => 'nameid-format:pairwise'],
            InvalidNameId::class,
            'The NameID format is not one of the eight of SAML Core (M-12).',
        ];
        yield 'a relative Reason' => [
            ['Reason="urn:oasis:names:tc:SAML:2.0:logout:user"' => 'Reason="user"'],
            MalformedMessage::class,
            'A URI is not absolute (M-6).',
        ];
    }

    /**
     * M-7: an IssueInstant later than now plus the clock skew, or older than maxMessageAge, and a NotOnOrAfter at now
     * minus the skew, each naming its window.
     */
    #[Test]
    #[DataProvider('provideInstantsRefused')]
    public function itRefusesAnInstantOutsideItsWindow(int $seconds, string $notOnOrAfter, string $message): void
    {
        // Given
        $document = $this->variant(['NotOnOrAfter="2026-09-30T12:05:00Z"' => 'NotOnOrAfter="' . $notOnOrAfter . '"']);

        // Then
        $this->expectException(OutsideValidityWindow::class);
        $this->expectExceptionMessageIs($message);

        // When
        $this->byBinding($document, $seconds);
    }

    /**
     * @return iterable<string, array{int, string, string}>
     */
    public static function provideInstantsRefused(): iterable
    {
        yield 'issued one second beyond now plus the skew' => [
            -181,
            '2026-09-30T12:05:00Z',
            'The IssueInstant of the message is later than now plus the clock skew (M-7).',
        ];
        yield 'one second older than maxMessageAge' => [
            301,
            '2026-09-30T12:10:00Z',
            'The IssueInstant of the message is older than maxMessageAge (M-7).',
        ];
        yield 'a NotOnOrAfter at now minus the skew' => [
            200,
            '2026-09-30T12:00:20Z',
            'The NotOnOrAfter of the LogoutRequest is at or before now minus the clock skew (M-7).',
        ];
    }

    /**
     * M-7, section 6.3: the edges of the windows are accepted: an IssueInstant at now plus the skew, or exactly
     * maxMessageAge old, a NotOnOrAfter one second after now minus the skew, or one second after the IssueInstant.
     */
    #[Test]
    #[DataProvider('provideInstantsAccepted')]
    public function itAcceptsTheEdgesOfTheWindows(int $seconds, string $notOnOrAfter): void
    {
        // Given
        $document = $this->variant(['NotOnOrAfter="2026-09-30T12:05:00Z"' => 'NotOnOrAfter="' . $notOnOrAfter . '"']);

        // When
        $accepted = $this->byBinding($document, $seconds);

        // Then
        static::assertSame($notOnOrAfter, $accepted->request->notOnOrAfter?->format('Y-m-d\TH:i:s\Z'));
    }

    /**
     * @return iterable<string, array{int, string}>
     */
    public static function provideInstantsAccepted(): iterable
    {
        yield 'issued at now plus the skew' => [-180, '2026-09-30T12:05:00Z'];
        yield 'exactly maxMessageAge old' => [300, '2026-09-30T12:10:00Z'];
        yield 'a NotOnOrAfter one second after now minus the skew' => [200, '2026-09-30T12:00:21Z'];
        yield 'a NotOnOrAfter one second after the IssueInstant' => [0, '2026-09-30T12:00:01Z'];
    }

    /**
     * M-8, section 9.8: the adversarial pass found a request whose Issuer carries an SPNameQualifier accepted; the one
     * reader of an Issuer refuses it.
     */
    #[Test]
    public function itRefusesTheIssuerQualifierTheAdversarialPassFound(): void
    {
        // Given
        $document = MetadataFixtures::load('hostile/adversarial-logout-request-issuer-sp-name-qualifier-refused.xml');

        // Then
        $this->expectException(IssuerMismatch::class);
        $this->expectExceptionMessageIs('The Issuer carries a NameQualifier, an SPNameQualifier or an SPProvidedID, which an entity identifier omits (M-8).');

        // When
        $this->byBinding($document);
    }

    /**
     * §9.2 row 34, section 6.3, SAML Core §3.7.1: a request whose NotOnOrAfter is at or before its IssueInstant
     * expires when it is issued, and is malformed, whatever the clock says.
     */
    #[Test]
    #[DataProvider('provideNotOnOrAfterNotAfterTheIssueInstant')]
    public function itRefusesANotOnOrAfterNotLaterThanTheIssueInstant(string $notOnOrAfter): void
    {
        // Given
        $document = $this->variant(['NotOnOrAfter="2026-09-30T12:05:00Z"' => 'NotOnOrAfter="' . $notOnOrAfter . '"']);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The NotOnOrAfter of the LogoutRequest is not later than its IssueInstant (section 6.3).');

        // When
        $this->byBinding($document);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNotOnOrAfterNotAfterTheIssueInstant(): iterable
    {
        yield 'at the IssueInstant' => ['2026-09-30T12:00:00Z'];
        yield 'a second before the IssueInstant' => ['2026-09-30T11:59:59Z'];
    }

    /**
     * §9.2 rows 12 and 13, M-8, SAML Bindings §3.4.5.2: the Destination of an authenticated request is required and is
     * the URL at which it arrived, compared byte for byte, without normalisation.
     */
    #[Test]
    #[DataProvider('provideDestinationsRefused')]
    public function itRefusesADestinationOtherThanTheUrlOfArrival(string $destination, string $message): void
    {
        // Given
        $document = $this->variant(['Destination="' . LogoutFixtures::SP_SLO . '"' => $destination]);

        // Then
        $this->expectException(DestinationMismatch::class);
        $this->expectExceptionMessageIs($message);

        // When
        $this->byBinding($document);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideDestinationsRefused(): iterable
    {
        $other = 'The Destination of the message is not the URL at which it arrived (M-8).';
        yield 'absent' => ['', 'The message has no Destination, which a signed message carries (M-8).'];
        yield 'another URL' => ['Destination="https://sp.example.com/saml/acs"', $other];
        yield 'a trailing slash' => ['Destination="https://sp.example.com/saml/slo/"', $other];
        yield 'another case in the host' => ['Destination="https://SP.example.com/saml/slo"', $other];
        yield 'a percent-encoded character' => ['Destination="https://sp.example.com/saml/%73lo"', $other];
    }

    /**
     * Sections 5.6 and 6.3, M-8: the URL of arrival is one of our single logout services, its Location for a request,
     * never a URL the caller made up nor the ResponseLocation where responses arrive (SAML Metadata §2.2.2).
     */
    #[Test]
    #[DataProvider('provideUrlsOfArrivalNotOurs')]
    public function itRefusesAUrlOfArrivalThatIsNotOneOfOurSingleLogoutServices(
        string $issuer,
        string $url,
        IdentityProvider|ServiceProvider $peer,
        IdentityProvider|ServiceProvider $self,
    ): void {
        // Given
        $document = $this->variant([
            '>' . LogoutFixtures::IDP . '</saml:Issuer>' => '>' . $issuer . '</saml:Issuer>',
            'Destination="' . LogoutFixtures::SP_SLO . '"' => 'Destination="' . $url . '"',
        ]);

        // Then
        $this->expectException(DestinationMismatch::class);
        $this->expectExceptionMessageIs('The URL at which the message arrived is not one of our single logout services (M-8).');

        // When
        $this->byBinding($document, 0, $peer, $self, $url);
    }

    /**
     * @return iterable<string, array{string, string, IdentityProvider|ServiceProvider, IdentityProvider|ServiceProvider}>
     */
    public static function provideUrlsOfArrivalNotOurs(): iterable
    {
        yield 'a URL of the service provider that is not a single logout service' => [
            LogoutFixtures::IDP,
            'https://sp.example.com/saml/acs',
            LogoutFixtures::identityProvider(),
            LogoutFixtures::serviceProvider(),
        ];
        yield 'the ResponseLocation of the identity provider' => [
            LogoutFixtures::SP,
            LogoutFixtures::IDP_SLO_RESPONSE,
            LogoutFixtures::serviceProvider(),
            LogoutFixtures::identityProvider(),
        ];
    }

    /**
     * Sections 5.6 and 6.3, SAML Profiles §4.4.4.1: the service provider's request to the identity provider, at the
     * Location of either of its single logout services.
     */
    #[Test]
    #[DataProvider('provideLocationsOfTheIdentityProvider')]
    public function itAcceptsARequestToTheIdentityProvider(string $url): void
    {
        // Given
        $document = $this->variant([
            '>' . LogoutFixtures::IDP . '</saml:Issuer>' => '>' . LogoutFixtures::SP . '</saml:Issuer>',
            'Destination="' . LogoutFixtures::SP_SLO . '"' => 'Destination="' . $url . '"',
        ]);

        // When
        $accepted = $this->byBinding(
            $document,
            0,
            LogoutFixtures::serviceProvider(),
            LogoutFixtures::identityProvider(),
            $url,
        );

        // Then
        static::assertSame([LogoutFixtures::SP, $url], [
            $accepted->request->issuer->entityId,
            $accepted->request->destination,
        ]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideLocationsOfTheIdentityProvider(): iterable
    {
        yield 'HTTP-Redirect' => [LogoutFixtures::IDP_SLO];
        yield 'HTTP-POST' => [LogoutFixtures::IDP_SLO_POST];
    }

    /**
     * Section 5.6: our role is the one that faces the peer's; two identity providers or two service providers are a
     * programming error of the caller.
     */
    #[Test]
    #[DataProvider('provideRolesThatDoNotFaceEachOther')]
    public function itRefusesRolesThatDoNotFaceEachOther(
        IdentityProvider|ServiceProvider $peer,
        IdentityProvider|ServiceProvider $self,
    ): void {
        // Given
        $document = MetadataFixtures::load(self::REDIRECT);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('Our role is the one that faces the peer\'s, a service provider facing an identity provider or the reverse (section 5.6).');

        // When
        $this->byBinding($document, 0, $peer, $self);
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
     * M-8: an Issuer whose Format is entity is the peer's entity ID.
     */
    #[Test]
    public function itAcceptsAnIssuerOfFormatEntity(): void
    {
        // Given
        $document = $this->variant([
            '<saml:Issuer>' => '<saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">',
        ]);

        // When
        $accepted = $this->byBinding($document);

        // Then
        static::assertEquals(new Issuer(LogoutFixtures::IDP), $accepted->request->issuer);
    }

    /**
     * M-12, I-12, §9.3 row 1: the NameID is read with Text::of(), its comments concatenated.
     */
    #[Test]
    public function itReadsTheNameIdAroundAComment(): void
    {
        // Given
        $document = $this->variant(['>_7a2f4c1d9e<' => '>_7a2f<!---->4c1d9e<']);

        // When
        $accepted = $this->byBinding($document);

        // Then
        static::assertSame('_7a2f4c1d9e', $accepted->request->nameId->value);
    }

    /**
     * §9.3 row 9, M-5: a samlp:Extensions with content is accepted and never read.
     */
    #[Test]
    public function itAcceptsExtensionsWithoutReadingThem(): void
    {
        // When
        $accepted = $this->byBinding(MetadataFixtures::load('behaviour/logout-request-extensions.xml'));

        // Then
        static::assertEquals(LogoutFixtures::request(), $accepted->request);
    }

    /**
     * SAML Core §3.7.1: a request without NotOnOrAfter, Reason or session index, its NameID of the unspecified format.
     */
    #[Test]
    public function itAcceptsARequestWithoutItsOptionalParts(): void
    {
        // Given
        $document = $this->variant([
            ' NotOnOrAfter="2026-09-30T12:05:00Z"' => '',
            ' Reason="urn:oasis:names:tc:SAML:2.0:logout:user"' => '',
            '<samlp:SessionIndex>_session-1</samlp:SessionIndex>' => '',
        ]);

        // When
        $accepted = $this->byBinding($document);

        // Then
        static::assertSame([null, [], null], [
            $accepted->request->notOnOrAfter,
            $accepted->request->sessionIndexes,
            $accepted->request->reason,
        ]);
    }

    /**
     * The request of the fixture for HTTP-Redirect with the replacements made, loaded with SamlLoader::create().
     *
     * @param array<string, string> $replacements
     */
    private function variant(array $replacements): Document
    {
        return SamlLoader::create()->load(strtr(MetadataFixtures::bytes(self::REDIRECT), $replacements));
    }

    /**
     * The request given to validateAuthenticatedByBinding(), from the identity provider to the service provider unless
     * other roles are given, with the clock moved by $seconds.
     */
    private function byBinding(
        Document $document,
        int $seconds = 0,
        IdentityProvider|ServiceProvider|null $peer = null,
        IdentityProvider|ServiceProvider|null $self = null,
        string $receivedAt = LogoutFixtures::SP_SLO,
    ): AcceptedLogoutRequest {
        return LogoutFixtures::requestValidator($seconds)->validateAuthenticatedByBinding(
            UnverifiedLogoutRequest::of($document),
            $peer ?? LogoutFixtures::identityProvider(),
            $self ?? LogoutFixtures::serviceProvider(),
            $receivedAt,
        );
    }
}
