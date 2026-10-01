<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit;

use function array_map;
use function array_replace;
use Beffroi\Saml2\Model\Assertion\Attribute;
use Beffroi\Saml2\Model\Exception\AudienceMismatch;
use Beffroi\Saml2\Model\Exception\DestinationMismatch;
use Beffroi\Saml2\Model\Exception\IndeterminateCondition;
use Beffroi\Saml2\Model\Exception\InResponseToMismatch;
use Beffroi\Saml2\Model\Exception\InvalidNameId;
use Beffroi\Saml2\Model\Exception\IssuerMismatch;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use Beffroi\Saml2\Model\Exception\RecipientMismatch;
use Beffroi\Saml2\Model\Exception\Replayed;
use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Exception\UnknownEndpoint;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Protocol\UnverifiedAuthnRequest;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutRequest;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutResponse;
use Beffroi\Saml2\Model\Protocol\UnverifiedResponse;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\AdversarialFixtureBuilder;
use Beffroi\Saml2\Model\Tests\Support\FrozenClock;
use Beffroi\Saml2\Model\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Tests\Unit\Validation\AuthnRequestFixtures;
use Beffroi\Saml2\Model\Tests\Unit\Validation\LogoutFixtures;
use Beffroi\Saml2\Model\Validation\AcceptedAssertion;
use Beffroi\Saml2\Model\Validation\AcceptedAuthnRequest;
use Beffroi\Saml2\Model\Validation\AcceptedLogoutRequest;
use Beffroi\Saml2\Model\Validation\AcceptedLogoutResponse;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use Beffroi\Saml2\Model\Validation\SignatureCoverage;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\DuplicateId;
use Beffroi\Xml\Core\Exception\InvalidId;
use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Dsig\Exception\DigestMismatch;
use Beffroi\Xml\Dsig\Exception\SignatureMismatch;
use Beffroi\Xml\Dsig\Exception\WrongReference;
use function count;
use DateTimeImmutable;
use function file_get_contents;
use function ksort;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_repeat;

/**
 * Section 9.8, the adversarial pass of 30 September 2026: each row of section 3 attacked with inputs the corpus of 9.2
 * and 9.3 does not list, every attempt a fixture of tests/Support/AdversarialFixtureBuilder whatever its outcome,
 * refused with the exception and the message it got, or accepted with the values read. Two attempts bypassed a rule
 * and were reported before their fix: the Issuer of an AuthnRequest, a LogoutRequest or a LogoutResponse carrying a
 * qualifier (M-8), fixed and asserted by the tests of those validators, and a time within a microsecond after its
 * bound (M-6, M-7), which section 9.8 records and the attempts below pin. The clock is frozen at 2026-09-30T12:00:00Z,
 * a second after every message was issued.
 */
final class AdversarialTest extends TestCase
{
    private const string NOW = '2026-09-30T12:00:00Z';

    /**
     * The attempts written by hand with the fix of the bypass they found (tests/Fixture/hostile/adversarial-README.md),
     * asserted here as the builder's are.
     */
    private const array WRITTEN_BY_HAND = [
        'hostile/adversarial-authn-request-issuer-name-qualifier-refused.xml',
        'hostile/adversarial-logout-request-issuer-sp-name-qualifier-refused.xml',
        'hostile/adversarial-logout-response-issuer-sp-provided-id-refused.xml',
    ];

    /**
     * Section 9.8, section 9.7: every adversarial fixture on disk is what the builder writes, byte for byte, so that
     * the command of tests/Fixture/hostile/adversarial-README.md writes them again.
     */
    #[Test]
    public function itBuildsTheCommittedFixtures(): void
    {
        // When
        $fixtures = AdversarialFixtureBuilder::fixtures();

        // Then
        foreach ($fixtures as $path => $bytes) {
            static::assertSame(file_get_contents(__DIR__ . '/../Fixture/' . $path), $bytes, $path);
        }
    }

    /**
     * Section 9.8: every attempt, the builder's and those written by hand, is asserted by one case of this class, none
     * left unread.
     */
    #[Test]
    public function itAssertsEveryAttempt(): void
    {
        // Given
        $asserted = [$this->refused('response-same-signed-assertion-in-another-response') => true];
        foreach ([
            self::provideRefusedResponses(),
            self::provideRefusedAuthnRequests(),
            self::provideRefusedLogoutRequests(),
            self::provideRefusedLogoutResponses(),
            self::provideRefusedMetadata(),
        ] as $cases) {
            foreach ($cases as $case) {
                $asserted[$this->refused($case[0])] = true;
            }
        }
        foreach ([
            self::provideAcceptedResponses(),
            self::provideAcceptedAuthnRequests(),
            self::provideAcceptedLogoutRequests(),
            self::provideAcceptedLogoutResponses(),
            self::provideAcceptedMetadata(),
        ] as $cases) {
            foreach ($cases as $case) {
                $asserted[self::accepted($case[0])] = true;
            }
        }
        ksort($asserted);

        // When
        $written = array_map(static fn (): bool => true, AdversarialFixtureBuilder::fixtures());
        foreach (self::WRITTEN_BY_HAND as $path) {
            $written[$path] = true;
        }
        ksort($written);

        // Then
        static::assertSame($written, $asserted);
    }

    /**
     * Section 9.8, section 3 rows 1, 2, 3, 5 to 7, 10, 11, 13 to 16, M-1 to M-8, M-10, M-12, M-13, M-14, M-17: every
     * response attempt that is refused, with the exception and the message it got.
     *
     * @param class-string<RefusedXml> $exception
     */
    #[Test]
    #[DataProvider('provideRefusedResponses')]
    public function itRefusesAResponseAttemptWithTheRuleNamed(
        string $attempt,
        string $exception,
        string $message,
        string $requestId = '_request',
    ): void {
        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        $this->validateResponse($this->refused($attempt), $requestId);
    }

    /**
     * @return iterable<string, array{0: string, 1: class-string<RefusedXml>, 2: string, 3?: string}>
     */
    public static function provideRefusedResponses(): iterable
    {
        yield 'assertion in status' => [
            'response-assertion-in-status',
            MalformedMessage::class,
            'The samlp:Status holds a child out of the order of the schema, or one it does not allow there (M-5).',
        ];
        yield 'assertion in status code' => [
            'response-assertion-in-status-code',
            MalformedMessage::class,
            'The samlp:StatusCode holds a child out of the order of the schema, or one it does not allow there (M-5).',
        ];
        yield 'assertion in status message' => [
            'response-assertion-in-status-message',
            SignatureRequired::class,
            'Neither the response nor its assertion carries a ds:Signature, one of which the profile requires (M-2).',
        ];
        yield 'assertion in status detail' => [
            'response-assertion-in-status-detail',
            SignatureRequired::class,
            'Neither the response nor its assertion carries a ds:Signature, one of which the profile requires (M-2).',
        ];
        yield 'assertion in status detail signature copied' => [
            'response-assertion-in-status-detail-signature-copied',
            WrongReference::class,
            'The reference does not name the claimed element (D-2).',
        ];
        yield 'assertion in status detail signed response' => [
            'response-assertion-in-status-detail-signed-response',
            DigestMismatch::class,
            'The claimed element is not what was signed (D-8).',
        ];
        yield 'assertion in subject confirmation data' => [
            'response-assertion-in-subject-confirmation-data',
            SignatureRequired::class,
            'Neither the response nor its assertion carries a ds:Signature, one of which the profile requires (M-2).',
        ];
        yield 'assertion in subject confirmation data signature copied' => [
            'response-assertion-in-subject-confirmation-data-signature-copied',
            WrongReference::class,
            'The reference does not name the claimed element (D-2).',
        ];
        yield 'assertion in conditions' => [
            'response-assertion-in-conditions',
            SignatureRequired::class,
            'Neither the response nor its assertion carries a ds:Signature, one of which the profile requires (M-2).',
        ];
        yield 'assertion in attribute' => [
            'response-assertion-in-attribute',
            SignatureRequired::class,
            'Neither the response nor its assertion carries a ds:Signature, one of which the profile requires (M-2).',
        ];
        yield 'assertion in attribute value' => [
            'response-assertion-in-attribute-value',
            SignatureRequired::class,
            'Neither the response nor its assertion carries a ds:Signature, one of which the profile requires (M-2).',
        ];
        yield 'assertion in extensions under another prefix' => [
            'response-assertion-in-extensions-under-another-prefix',
            SignatureRequired::class,
            'Neither the response nor its assertion carries a ds:Signature, one of which the profile requires (M-2).',
        ];
        yield 'assertion in extensions in the default namespace' => [
            'response-assertion-in-extensions-in-the-default-namespace',
            SignatureRequired::class,
            'Neither the response nor its assertion carries a ds:Signature, one of which the profile requires (M-2).',
        ];
        yield 'assertion in the issuer of the response' => [
            'response-assertion-in-the-issuer-of-the-response',
            MixedContent::class,
            'The element has a child that is neither text, CDATA, comment nor processing instruction (I-12).',
        ];
        yield 'unsigned assertion before the status' => [
            'response-unsigned-assertion-before-the-status',
            MalformedMessage::class,
            'The samlp:Response holds a child out of the order of the schema, or one it does not allow there (M-5).',
        ];
        yield 'prefix rebound on the subject' => [
            'response-prefix-rebound-on-the-subject',
            MalformedMessage::class,
            'The saml:Assertion holds a child out of the order of the schema, or one it does not allow there (M-5).',
        ];
        yield 'prefix rebound on the name id' => [
            'response-prefix-rebound-on-the-name-id',
            MalformedMessage::class,
            'The saml:Subject holds a child out of the order of the schema, or one it does not allow there (M-5).',
        ];
        yield 'prefix rebound on the audience restriction' => [
            'response-prefix-rebound-on-the-audience-restriction',
            IndeterminateCondition::class,
            'The Conditions hold a condition the package does not understand, and the assertion is Indeterminate (M-13).',
        ];
        yield 'assertion in the saml 1 namespace' => [
            'response-assertion-in-the-saml-1-namespace',
            MalformedMessage::class,
            'The samlp:Response holds a child out of the order of the schema, or one it does not allow there (M-5).',
        ];
        yield 'assertion namespace in upper case' => [
            'response-assertion-namespace-in-upper-case',
            MalformedMessage::class,
            'The samlp:Response holds a child out of the order of the schema, or one it does not allow there (M-5).',
        ];
        yield 'assertion in no namespace' => [
            'response-assertion-in-no-namespace',
            MalformedMessage::class,
            'The samlp:Response holds a child out of the order of the schema, or one it does not allow there (M-5).',
        ];
        yield 'status in the assertion namespace' => [
            'response-status-in-the-assertion-namespace',
            MalformedMessage::class,
            'The samlp:Response holds a child out of the order of the schema, or one it does not allow there (M-5).',
        ];
        yield 'issuer in the protocol namespace' => [
            'response-issuer-in-the-protocol-namespace',
            MalformedMessage::class,
            'The samlp:Response holds a child out of the order of the schema, or one it does not allow there (M-5).',
        ];
        yield 'recipient in a namespace' => [
            'response-recipient-in-a-namespace',
            MalformedMessage::class,
            'The bearer confirmation has no Recipient (M-8).',
        ];
        yield 'relative destination under an xml base' => [
            'response-relative-destination-under-an-xml-base',
            MalformedMessage::class,
            'A URI is not absolute (M-6).',
        ];
        yield 'relative recipient under an xml base' => [
            'response-relative-recipient-under-an-xml-base',
            MalformedMessage::class,
            'A URI is not absolute (M-6).',
        ];
        yield 'relative audience under an xml base' => [
            'response-relative-audience-under-an-xml-base',
            AudienceMismatch::class,
            'An AudienceRestriction does not hold our entity ID among its audiences (M-8).',
        ];
        yield 'relative issuer under an xml base' => [
            'response-relative-issuer-under-an-xml-base',
            MalformedMessage::class,
            'A URI is not absolute (M-6).',
        ];
        yield 'wrapped id in another case' => [
            'response-wrapped-id-in-another-case',
            WrongReference::class,
            'The reference does not name the claimed element (D-2).',
        ];
        yield 'wrapped id in another unicode composition' => [
            'response-wrapped-id-in-another-unicode-composition',
            WrongReference::class,
            'The reference does not name the claimed element (D-2).',
        ];
        yield 'wrapped id with a full width low line' => [
            'response-wrapped-id-with-a-full-width-low-line',
            WrongReference::class,
            'The reference does not name the claimed element (D-2).',
        ];
        yield 'wrapped id with a trailing space' => [
            'response-wrapped-id-with-a-trailing-space',
            InvalidId::class,
            'An ID is not an NCName (I-8).',
        ];
        yield 'wrapped id as an xml id' => [
            'response-wrapped-id-as-an-xml-id',
            WrongReference::class,
            'The reference does not name the claimed element (D-2).',
        ];
        yield 'in response to in another case' => [
            'response-in-response-to-in-another-case',
            InResponseToMismatch::class,
            'The InResponseTo of the response is not the one the consumer expects (M-10).',
        ];
        yield 'in response to in another unicode composition' => [
            'response-in-response-to-in-another-unicode-composition',
            InResponseToMismatch::class,
            'The InResponseTo of the response is not the one the consumer expects (M-10).',
            "_request\u{E9}",
        ];
        yield 'in response to with a trailing space' => [
            'response-in-response-to-with-a-trailing-space',
            MalformedMessage::class,
            'An ID is not an NCName (M-6).',
        ];
        yield 'id equal to the assertion id' => [
            'response-id-equal-to-the-assertion-id',
            DuplicateId::class,
            'An ID value appears twice in the document (I-8).',
        ];
        yield 'destination scheme in upper case' => [
            'response-destination-scheme-in-upper-case',
            DestinationMismatch::class,
            'The Destination of the response is not the URL at which it arrived (M-8).',
        ];
        yield 'destination with the default port' => [
            'response-destination-with-the-default-port',
            DestinationMismatch::class,
            'The Destination of the response is not the URL at which it arrived (M-8).',
        ];
        yield 'destination with an empty port' => [
            'response-destination-with-an-empty-port',
            DestinationMismatch::class,
            'The Destination of the response is not the URL at which it arrived (M-8).',
        ];
        yield 'destination host with a trailing dot' => [
            'response-destination-host-with-a-trailing-dot',
            DestinationMismatch::class,
            'The Destination of the response is not the URL at which it arrived (M-8).',
        ];
        yield 'destination with a dot segment' => [
            'response-destination-with-a-dot-segment',
            DestinationMismatch::class,
            'The Destination of the response is not the URL at which it arrived (M-8).',
        ];
        yield 'destination with a dot dot segment' => [
            'response-destination-with-a-dot-dot-segment',
            DestinationMismatch::class,
            'The Destination of the response is not the URL at which it arrived (M-8).',
        ];
        yield 'destination with a percent encoded slash' => [
            'response-destination-with-a-percent-encoded-slash',
            DestinationMismatch::class,
            'The Destination of the response is not the URL at which it arrived (M-8).',
        ];
        yield 'destination with user information' => [
            'response-destination-with-user-information',
            DestinationMismatch::class,
            'The Destination of the response is not the URL at which it arrived (M-8).',
        ];
        yield 'destination with an empty query' => [
            'response-destination-with-an-empty-query',
            DestinationMismatch::class,
            'The Destination of the response is not the URL at which it arrived (M-8).',
        ];
        yield 'destination with an empty fragment' => [
            'response-destination-with-an-empty-fragment',
            DestinationMismatch::class,
            'The Destination of the response is not the URL at which it arrived (M-8).',
        ];
        yield 'destination with a homograph host' => [
            'response-destination-with-a-homograph-host',
            DestinationMismatch::class,
            'The Destination of the response is not the URL at which it arrived (M-8).',
        ];
        yield 'destination with a zero width space' => [
            'response-destination-with-a-zero-width-space',
            MalformedMessage::class,
            'A URI holds whitespace, a control, format or invisible character, or bytes that are not UTF-8 (M-6).',
        ];
        yield 'name id with a right to left override' => [
            'response-name-id-with-a-right-to-left-override',
            InvalidNameId::class,
            'The NameID holds a format or invisible character, invisible or reordering (M-12).',
        ];
        yield 'assertion issued a year ago within its bearer window' => [
            'response-assertion-issued-a-year-ago-within-its-bearer-window',
            OutsideValidityWindow::class,
            'The IssueInstant of the assertion is older than maxMessageAge (M-7).',
        ];
        yield 'recipient scheme in upper case' => [
            'response-recipient-scheme-in-upper-case',
            RecipientMismatch::class,
            'The Recipient of the bearer confirmation is not the URL at which the response arrived (M-8).',
        ];
        yield 'recipient with the default port' => [
            'response-recipient-with-the-default-port',
            RecipientMismatch::class,
            'The Recipient of the bearer confirmation is not the URL at which the response arrived (M-8).',
        ];
        yield 'recipient with a dot segment' => [
            'response-recipient-with-a-dot-segment',
            RecipientMismatch::class,
            'The Recipient of the bearer confirmation is not the URL at which the response arrived (M-8).',
        ];
        yield 'audience scheme in upper case' => [
            'response-audience-scheme-in-upper-case',
            AudienceMismatch::class,
            'An AudienceRestriction does not hold our entity ID among its audiences (M-8).',
        ];
        yield 'audience with a trailing slash' => [
            'response-audience-with-a-trailing-slash',
            AudienceMismatch::class,
            'An AudienceRestriction does not hold our entity ID among its audiences (M-8).',
        ];
        yield 'audience host with a trailing dot' => [
            'response-audience-host-with-a-trailing-dot',
            AudienceMismatch::class,
            'An AudienceRestriction does not hold our entity ID among its audiences (M-8).',
        ];
        yield 'assertion issuer host in upper case' => [
            'response-assertion-issuer-host-in-upper-case',
            IssuerMismatch::class,
            'The Issuer is not the entity ID of the peer (M-8).',
        ];
        yield 'assertion issuer with a trailing slash' => [
            'response-assertion-issuer-with-a-trailing-slash',
            IssuerMismatch::class,
            'The Issuer is not the entity ID of the peer (M-8).',
        ];
        yield 'audience of 1025 characters' => [
            'response-audience-of-1025-characters',
            MalformedMessage::class,
            'A URI is longer than 1024 characters (M-6).',
        ];
        yield 'audience of 1025 two byte characters' => [
            'response-audience-of-1025-two-byte-characters',
            MalformedMessage::class,
            'A URI is longer than 1024 characters (M-6).',
        ];
        yield 'persistent name id of 257 two byte characters' => [
            'response-persistent-name-id-of-257-two-byte-characters',
            InvalidNameId::class,
            'A persistent or transient NameID is longer than 256 characters (M-12).',
        ];
        yield 'transient name id of 257 characters' => [
            'response-transient-name-id-of-257-characters',
            InvalidNameId::class,
            'A persistent or transient NameID is longer than 256 characters (M-12).',
        ];
        yield 'unspecified name id of 1025 characters' => [
            'response-unspecified-name-id-of-1025-characters',
            InvalidNameId::class,
            'A NameID is longer than 1024 characters (M-12).',
        ];
        yield 'assertion id of 129 bytes' => [
            'response-assertion-id-of-129-bytes',
            InvalidId::class,
            'An ID is longer than maxIdLength, 128 bytes (I-8).',
        ];
        yield 'in response to of 129 bytes' => [
            'response-in-response-to-of-129-bytes',
            MalformedMessage::class,
            'An ID is longer than 128 bytes (M-6).',
            '_' . str_repeat('r', 128),
        ];
        yield 'processing instructions inserted after signing' => [
            'response-processing-instructions-inserted-after-signing',
            DigestMismatch::class,
            'The claimed element is not what was signed (D-8).',
        ];
        yield 'processing instruction in signed info after signing' => [
            'response-processing-instruction-in-signed-info-after-signing',
            SignatureMismatch::class,
            'No trusted key verifies the signature over SignedInfo (D-7, D-8).',
        ];
        yield 'processing instruction in the status of a signed response' => [
            'response-processing-instruction-in-the-status-of-a-signed-response',
            DigestMismatch::class,
            'The claimed element is not what was signed (D-8).',
        ];
        yield 'name id behind a space character reference' => [
            'response-name-id-behind-a-space-character-reference',
            InvalidNameId::class,
            'The NameID starts or ends with whitespace or a control character, or is not UTF-8 (M-12).',
        ];
        yield 'assertion signed by another key with the identity provider certificate' => [
            'response-assertion-signed-by-another-key-with-the-identity-provider-certificate',
            SignatureMismatch::class,
            'No trusted key verifies the signature over SignedInfo (D-7, D-8).',
        ];
        yield 'signature moved into the extensions' => [
            'response-signature-moved-into-the-extensions',
            SignatureRequired::class,
            'Neither the response nor its assertion carries a ds:Signature, one of which the profile requires (M-2).',
        ];
        yield 'condition in another namespace' => [
            'response-condition-in-another-namespace',
            IndeterminateCondition::class,
            'The Conditions hold a condition the package does not understand, and the assertion is Indeterminate (M-13).',
        ];
        yield 'empty audience next to ours' => [
            'response-empty-audience-next-to-ours',
            MalformedMessage::class,
            'A URI is not absolute (M-6).',
        ];
        yield 'status code success in lower case' => [
            'response-status-code-success-in-lower-case',
            MalformedMessage::class,
            'The top-level status code is not one of the four of SAML Core (M-5).',
        ];
        yield 'confirmation method bearer capitalised' => [
            'response-confirmation-method-bearer-capitalised',
            Unsupported::class,
            'The confirmation method is not bearer, the one the package supports (section 8).',
        ];
        yield 'name id format in another case' => [
            'response-name-id-format-in-another-case',
            InvalidNameId::class,
            'The NameID format is not one of the eight of SAML Core (M-12).',
        ];
        yield 'version 2.00' => ['response-version-2.00', MalformedMessage::class, 'The version is not 2.0 (M-6).'];
    }

    /**
     * Section 9.8, M-1, M-4, M-5, M-6, M-8, M-12: every response attempt that is accepted, with the values read, the
     * ones the attempt tried to change among them.
     *
     * @param array<string, mixed> $values the values read that differ from those of the valid response
     */
    #[Test]
    #[DataProvider('provideAcceptedResponses')]
    public function itAcceptsAResponseAttemptWithTheValuesRead(
        string $attempt,
        array $values,
        string $requestId = '_request',
    ): void {
        // When
        $accepted = $this->validateResponse(self::accepted($attempt), $requestId);

        // Then
        static::assertSame(array_replace($this->responseValues(), $values), $this->valuesOfTheResponse($accepted));
    }

    /**
     * @return iterable<string, array{0: string, 1: array<string, mixed>, 2?: string}>
     */
    public static function provideAcceptedResponses(): iterable
    {
        $both = SignatureCoverage::AssertionAndResponse;
        yield 'unsigned assertion in status detail' => ['response-unsigned-assertion-in-status-detail', []];
        yield 'unsigned assertion in extensions next to the signed one' => [
            'response-unsigned-assertion-in-extensions-next-to-the-signed-one',
            [],
        ];
        yield 'unsigned assertion in the key info of the signature' => [
            'response-unsigned-assertion-in-the-key-info-of-the-signature',
            [],
        ];
        yield 'default namespaces' => ['response-default-namespaces', []];
        yield 'assertion namespace under another prefix' => ['response-assertion-namespace-under-another-prefix', []];
        yield 'prefixes swapped' => ['response-prefixes-swapped', []];
        yield 'namespaces declared again on every element' => [
            'response-namespaces-declared-again-on-every-element',
            [],
        ];
        yield 'attributes in a namespace next to the real ones' => [
            'response-attributes-in-a-namespace-next-to-the-real-ones',
            [],
        ];
        yield 'xml base and lang on every element' => ['response-xml-base-and-lang-on-every-element', []];
        yield 'signed both xml base and lang on every element' => [
            'response-signed-both-xml-base-and-lang-on-every-element',
            ['coverage' => $both],
        ];
        yield 'in response to precomposed' => [
            'response-in-response-to-precomposed',
            ['inResponseTo' => "_request\u{E9}", 'coverage' => $both],
            "_request\u{E9}",
        ];
        yield 'assertion id in another case' => ['response-assertion-id-in-another-case', ['id' => '_ASSERTION']];
        yield 'assertion id precomposed' => ['response-assertion-id-precomposed', ['id' => "_assertion\u{E9}"]];
        yield 'assertion id decomposed' => ['response-assertion-id-decomposed', ['id' => "_assertione\u{301}"]];
        yield 'id equal to the assertion id in another case' => [
            'response-id-equal-to-the-assertion-id-in-another-case',
            ['responseId' => '_Assertion'],
        ];
        yield 'not before 100 nanoseconds after now plus the skew' => [
            'response-not-before-100-nanoseconds-after-now-plus-the-skew',
            [],
        ];
        yield 'audience of 1024 characters' => [
            'response-audience-of-1024-characters',
            ['audiences' => [['https://sp.example.com/saml', 'https://' . str_repeat('a', 1016)]]],
        ];
        yield 'audience of 1024 two byte characters' => [
            'response-audience-of-1024-two-byte-characters',
            ['audiences' => [['https://sp.example.com/saml', 'https://' . str_repeat("\u{E9}", 1016)]]],
        ];
        yield 'persistent name id of 256 characters' => [
            'response-persistent-name-id-of-256-characters',
            ['nameId' => str_repeat('a', 256)],
        ];
        yield 'persistent name id of 256 two byte characters' => [
            'response-persistent-name-id-of-256-two-byte-characters',
            ['nameId' => str_repeat("\u{E9}", 256)],
        ];
        yield 'transient name id of 256 characters' => [
            'response-transient-name-id-of-256-characters',
            ['nameId' => str_repeat('a', 256)],
        ];
        yield 'unspecified name id of 1024 characters' => [
            'response-unspecified-name-id-of-1024-characters',
            ['nameId' => str_repeat('a', 1024)],
        ];
        yield 'assertion id of 128 bytes' => [
            'response-assertion-id-of-128-bytes',
            ['id' => '_' . str_repeat('a', 127)],
        ];
        yield 'assertion id of 128 bytes in two byte characters' => [
            'response-assertion-id-of-128-bytes-in-two-byte-characters',
            ['id' => '_' . str_repeat("\u{E9}", 63) . 'a'],
        ];
        yield 'in response to of 128 bytes' => [
            'response-in-response-to-of-128-bytes',
            ['inResponseTo' => '_' . str_repeat('r', 127), 'coverage' => $both],
            '_' . str_repeat('r', 127),
        ];
        yield 'issued exactly max message age ago' => ['response-issued-exactly-max-message-age-ago', []];
        yield 'comments inserted after signing' => ['response-comments-inserted-after-signing', []];
        yield 'signed both comments inserted after signing' => [
            'response-signed-both-comments-inserted-after-signing',
            ['coverage' => $both],
        ];
        yield 'comments and processing instructions before signing' => [
            'response-comments-and-processing-instructions-before-signing',
            [],
        ];
        yield 'name id in a cdata section' => ['response-name-id-in-a-cdata-section', []];
        yield 'failing signature in the extensions' => ['response-failing-signature-in-the-extensions', []];
    }

    /**
     * Section 9.8, M-11: the replay store remembers the exact pair of the issuer and the ID; an ID that differs by
     * case or by Unicode composition only is another assertion, accepted after the first.
     */
    #[Test]
    #[DataProvider('provideAssertionsOfAnotherId')]
    public function itRemembersTheExactId(string $first, string $second, string $id): void
    {
        // Given
        $replay = new InMemoryReplayGuard();
        $this->validateResponse($first, '_request', $replay);

        // When
        $accepted = $this->validateResponse($second, '_request', $replay);

        // Then
        static::assertSame($id, $accepted->assertion->id);
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function provideAssertionsOfAnotherId(): iterable
    {
        yield 'in another case' => [
            'behaviour/response-signed-assertion-accepted.xml',
            self::accepted('response-assertion-id-in-another-case'),
            '_ASSERTION',
        ];
        yield 'in another Unicode composition' => [
            self::accepted('response-assertion-id-precomposed'),
            self::accepted('response-assertion-id-decomposed'),
            "_assertione\u{301}",
        ];
    }

    /**
     * Section 9.8, M-11: the signed assertion of an accepted response, in another response of another ID, is the same
     * pair of issuer and ID, and is refused.
     */
    #[Test]
    public function itRefusesTheSameAssertionInAnotherResponse(): void
    {
        // Given
        $replay = new InMemoryReplayGuard();
        $this->validateResponse('behaviour/response-signed-assertion-accepted.xml', '_request', $replay);

        // Then
        $this->expectException(Replayed::class);
        $this->expectExceptionMessageIs('The assertion was already accepted from its issuer (M-11).');

        // When
        $this->validateResponse(
            $this->refused('response-same-signed-assertion-in-another-response'),
            '_request',
            $replay,
        );
    }

    /**
     * Section 9.8, section 3 rows 5, 6, 7 and 11, M-2, M-5, M-6, M-7, M-8, M-9, M-17: every AuthnRequest attempt that
     * is refused, with the exception and the message it got.
     *
     * @param class-string<RefusedXml> $exception
     */
    #[Test]
    #[DataProvider('provideRefusedAuthnRequests')]
    public function itRefusesAnAuthnRequestAttemptWithTheRuleNamed(
        string $attempt,
        string $exception,
        string $message,
        string $now = self::NOW,
    ): void {
        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        $this->validateAuthnRequest($this->refused($attempt), $now);
    }

    /**
     * @return iterable<string, array{0: string, 1: class-string<RefusedXml>, 2: string, 3?: string}>
     */
    public static function provideRefusedAuthnRequests(): iterable
    {
        yield 'issuer in the protocol namespace' => [
            'authn-request-issuer-in-the-protocol-namespace',
            MalformedMessage::class,
            'The samlp:AuthnRequest holds a child out of the order of the schema, or one it does not allow there (M-5).',
        ];
        yield 'relative assertion consumer service url under an xml base' => [
            'authn-request-relative-assertion-consumer-service-url-under-an-xml-base',
            MalformedMessage::class,
            'A URI is not absolute (M-6).',
        ];
        yield 'issue instant with ten fractional digits' => [
            'authn-request-issue-instant-with-ten-fractional-digits',
            MalformedMessage::class,
            'A time is not an xs:dateTime in UTC with the Z designator (M-6).',
        ];
        yield 'issue instant with a dot and no digit' => [
            'authn-request-issue-instant-with-a-dot-and-no-digit',
            MalformedMessage::class,
            'A time is not an xs:dateTime in UTC with the Z designator (M-6).',
        ];
        yield 'issue instant with a lower case z' => [
            'authn-request-issue-instant-with-a-lower-case-z',
            MalformedMessage::class,
            'A time is not an xs:dateTime in UTC with the Z designator (M-6).',
        ];
        yield 'issue instant with a lower case t' => [
            'authn-request-issue-instant-with-a-lower-case-t',
            MalformedMessage::class,
            'A time is not an xs:dateTime in UTC with the Z designator (M-6).',
        ];
        yield 'issue instant with a space for the t' => [
            'authn-request-issue-instant-with-a-space-for-the-t',
            MalformedMessage::class,
            'A time is not an xs:dateTime in UTC with the Z designator (M-6).',
        ];
        yield 'issue instant with a plus sign' => [
            'authn-request-issue-instant-with-a-plus-sign',
            MalformedMessage::class,
            'A time is not an xs:dateTime in UTC with the Z designator (M-6).',
        ];
        yield 'issue instant with a five digit year' => [
            'authn-request-issue-instant-with-a-five-digit-year',
            MalformedMessage::class,
            'A time is not an xs:dateTime in UTC with the Z designator (M-6).',
        ];
        yield 'issue instant with a negative year' => [
            'authn-request-issue-instant-with-a-negative-year',
            MalformedMessage::class,
            'A time is not an xs:dateTime in UTC with the Z designator (M-6).',
        ];
        yield 'issue instant with minus zero' => [
            'authn-request-issue-instant-with-minus-zero',
            MalformedMessage::class,
            'A time is not an xs:dateTime in UTC with the Z designator (M-6).',
        ];
        yield 'issue instant with z and an offset' => [
            'authn-request-issue-instant-with-z-and-an-offset',
            MalformedMessage::class,
            'A time is not an xs:dateTime in UTC with the Z designator (M-6).',
        ];
        yield 'issue instant in full width digits' => [
            'authn-request-issue-instant-in-full-width-digits',
            MalformedMessage::class,
            'A time is not an xs:dateTime in UTC with the Z designator (M-6).',
        ];
        yield 'issue instant in arabic indic digits' => [
            'authn-request-issue-instant-in-arabic-indic-digits',
            MalformedMessage::class,
            'A time is not an xs:dateTime in UTC with the Z designator (M-6).',
        ];
        yield 'issue instant with a one digit month' => [
            'authn-request-issue-instant-with-a-one-digit-month',
            MalformedMessage::class,
            'A time is not an xs:dateTime in UTC with the Z designator (M-6).',
        ];
        yield 'issue instant without seconds' => [
            'authn-request-issue-instant-without-seconds',
            MalformedMessage::class,
            'A time is not an xs:dateTime in UTC with the Z designator (M-6).',
        ];
        yield 'issue instant with a tab character reference' => [
            'authn-request-issue-instant-with-a-tab-character-reference',
            MalformedMessage::class,
            'A time is not an xs:dateTime in UTC with the Z designator (M-6).',
        ];
        yield 'issue instant a microsecond after now plus the skew' => [
            'authn-request-issue-instant-a-microsecond-after-now-plus-the-skew',
            OutsideValidityWindow::class,
            'The IssueInstant of the request is later than now plus the clock skew (M-7).',
        ];
        yield 'is passive capitalised' => [
            'authn-request-is-passive-capitalised',
            MalformedMessage::class,
            'A boolean is not one of true, false, 1 and 0 (M-6).',
        ];
        yield 'is passive in upper case' => [
            'authn-request-is-passive-in-upper-case',
            MalformedMessage::class,
            'A boolean is not one of true, false, 1 and 0 (M-6).',
        ];
        yield 'is passive 01' => [
            'authn-request-is-passive-01',
            MalformedMessage::class,
            'A boolean is not one of true, false, 1 and 0 (M-6).',
        ];
        yield 'is passive plus 1' => [
            'authn-request-is-passive-plus-1',
            MalformedMessage::class,
            'A boolean is not one of true, false, 1 and 0 (M-6).',
        ];
        yield 'is passive 1.0' => [
            'authn-request-is-passive-1.0',
            MalformedMessage::class,
            'A boolean is not one of true, false, 1 and 0 (M-6).',
        ];
        yield 'is passive empty' => [
            'authn-request-is-passive-empty',
            MalformedMessage::class,
            'A boolean is not one of true, false, 1 and 0 (M-6).',
        ];
        yield 'is passive yes' => [
            'authn-request-is-passive-yes',
            MalformedMessage::class,
            'A boolean is not one of true, false, 1 and 0 (M-6).',
        ];
        yield 'is passive in full width letters' => [
            'authn-request-is-passive-in-full-width-letters',
            MalformedMessage::class,
            'A boolean is not one of true, false, 1 and 0 (M-6).',
        ];
        yield 'is passive with a zero width space' => [
            'authn-request-is-passive-with-a-zero-width-space',
            MalformedMessage::class,
            'A boolean is not one of true, false, 1 and 0 (M-6).',
        ];
        yield 'is passive with a tab character reference' => [
            'authn-request-is-passive-with-a-tab-character-reference',
            MalformedMessage::class,
            'A boolean is not one of true, false, 1 and 0 (M-6).',
        ];
        yield 'allow create on' => [
            'authn-request-allow-create-on',
            MalformedMessage::class,
            'A boolean is not one of true, false, 1 and 0 (M-6).',
        ];
        yield 'assertion consumer service url scheme in upper case' => [
            'authn-request-assertion-consumer-service-url-scheme-in-upper-case',
            UnknownEndpoint::class,
            'No assertion consumer service of the metadata has that location (M-9).',
        ];
        yield 'assertion consumer service url host in upper case' => [
            'authn-request-assertion-consumer-service-url-host-in-upper-case',
            UnknownEndpoint::class,
            'No assertion consumer service of the metadata has that location (M-9).',
        ];
        yield 'assertion consumer service url with the default port' => [
            'authn-request-assertion-consumer-service-url-with-the-default-port',
            UnknownEndpoint::class,
            'No assertion consumer service of the metadata has that location (M-9).',
        ];
        yield 'assertion consumer service url with a trailing slash' => [
            'authn-request-assertion-consumer-service-url-with-a-trailing-slash',
            UnknownEndpoint::class,
            'No assertion consumer service of the metadata has that location (M-9).',
        ];
        yield 'assertion consumer service url with a dot segment' => [
            'authn-request-assertion-consumer-service-url-with-a-dot-segment',
            UnknownEndpoint::class,
            'No assertion consumer service of the metadata has that location (M-9).',
        ];
        yield 'assertion consumer service url percent encoded' => [
            'authn-request-assertion-consumer-service-url-percent-encoded',
            UnknownEndpoint::class,
            'No assertion consumer service of the metadata has that location (M-9).',
        ];
        yield 'destination with the default port' => [
            'authn-request-destination-with-the-default-port',
            DestinationMismatch::class,
            'The Destination of the request is not the URL at which it arrived (M-8).',
        ];
        yield 'issuer with a name qualifier, the bypass the pass found (M-8), issued when its original was' => [
            'authn-request-issuer-name-qualifier',
            IssuerMismatch::class,
            'The Issuer carries a NameQualifier, an SPNameQualifier or an SPProvidedID, which an entity identifier omits (M-8).',
            AuthnRequestFixtures::NOW,
        ];
        yield 'issuer with a trailing slash' => [
            'authn-request-issuer-with-a-trailing-slash',
            IssuerMismatch::class,
            'The Issuer is not the entity ID of the peer (M-8).',
        ];
        yield 'seventeen class references' => [
            'authn-request-seventeen-class-references',
            LimitExceeded::class,
            'A samlp:RequestedAuthnContext holds more than 16 saml:AuthnContextClassRef, the bound of section 7 (M-17).',
        ];
        yield 'processing instruction after signing' => [
            'authn-request-processing-instruction-after-signing',
            DigestMismatch::class,
            'The claimed element is not what was signed (D-8).',
        ];
    }

    /**
     * Section 9.8, M-5, M-6, M-7, M-17: every AuthnRequest attempt that is accepted, with the values read.
     *
     * @param array<string, mixed> $values the values read that differ from those of the valid request
     */
    #[Test]
    #[DataProvider('provideAcceptedAuthnRequests')]
    public function itAcceptsAnAuthnRequestAttemptWithTheValuesRead(string $attempt, array $values): void
    {
        // When
        $accepted = $this->validateAuthnRequest(self::accepted($attempt));

        // Then
        static::assertSame(
            array_replace($this->authnRequestValues(), $values),
            $this->valuesOfTheAuthnRequest($accepted),
        );
    }

    /**
     * @return iterable<string, array{string, array<string, mixed>}>
     */
    public static function provideAcceptedAuthnRequests(): iterable
    {
        yield 'default namespaces' => ['authn-request-default-namespaces', []];
        yield 'xml base and lang on every element' => ['authn-request-xml-base-and-lang-on-every-element', []];
        yield 'issue instant with nine fractional digits, kept to the microsecond' => [
            'authn-request-issue-instant-with-nine-fractional-digits',
            ['issueInstant' => '2026-09-30T11:59:59.123456Z'],
        ];
        yield 'issue instant 100 nanoseconds after now plus the skew, on the bound (M-6)' => [
            'authn-request-issue-instant-100-nanoseconds-after-now-plus-the-skew',
            ['issueInstant' => '2026-09-30T12:03:00.000000Z'],
        ];
        yield 'is passive 1' => ['authn-request-is-passive-1', ['isPassive' => true]];
        yield 'force authn 0' => ['authn-request-force-authn-0', ['forceAuthn' => false]];
        yield 'sixteen class references' => ['authn-request-sixteen-class-references', ['classRefs' => 16]];
        yield 'comments inserted after signing' => [
            'authn-request-comments-inserted-after-signing',
            ['authentication' => Authentication::XmlSignature],
        ];
    }

    /**
     * Section 9.8, M-2, M-8: every LogoutRequest attempt that is refused, with the exception and the message it got;
     * a signed one is given to validate(), the others to validateAuthenticatedByBinding().
     *
     * @param class-string<RefusedXml> $exception
     */
    #[Test]
    #[DataProvider('provideRefusedLogoutRequests')]
    public function itRefusesALogoutRequestAttemptWithTheRuleNamed(
        string $attempt,
        string $exception,
        string $message,
    ): void {
        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        $this->validateLogoutRequest($this->refused($attempt));
    }

    /**
     * @return iterable<string, array{string, class-string<RefusedXml>, string}>
     */
    public static function provideRefusedLogoutRequests(): iterable
    {
        yield 'issuer with an sp name qualifier, the bypass the pass found (M-8)' => [
            'logout-request-issuer-sp-name-qualifier',
            IssuerMismatch::class,
            'The Issuer carries a NameQualifier, an SPNameQualifier or an SPProvidedID, which an entity identifier omits (M-8).',
        ];
        yield 'destination with a trailing slash' => [
            'logout-request-destination-with-a-trailing-slash',
            DestinationMismatch::class,
            'The Destination of the message is not the URL at which it arrived (M-8).',
        ];
        yield 'signed name id moved into the extensions' => [
            'logout-request-signed-name-id-moved-into-the-extensions',
            DigestMismatch::class,
            'The claimed element is not what was signed (D-8).',
        ];
    }

    /**
     * Section 9.8, M-12, M-17: every LogoutRequest attempt that is accepted, with the values read.
     *
     * @param array<string, mixed> $values the values read that differ from those of the valid request
     */
    #[Test]
    #[DataProvider('provideAcceptedLogoutRequests')]
    public function itAcceptsALogoutRequestAttemptWithTheValuesRead(string $attempt, array $values): void
    {
        // When
        $accepted = $this->validateLogoutRequest(self::accepted($attempt));

        // Then
        static::assertSame(
            array_replace($this->logoutRequestValues(), $values),
            $this->valuesOfTheLogoutRequest($accepted),
        );
    }

    /**
     * @return iterable<string, array{string, array<string, mixed>}>
     */
    public static function provideAcceptedLogoutRequests(): iterable
    {
        yield 'xml base and lang on every element' => ['logout-request-xml-base-and-lang-on-every-element', []];
        yield 'sixteen session indexes' => ['logout-request-sixteen-session-indexes', ['sessionIndexes' => 16]];
        yield 'comments inserted after signing' => [
            'logout-request-comments-inserted-after-signing',
            ['authentication' => Authentication::XmlSignature],
        ];
    }

    /**
     * Section 9.8, M-8, M-10: every LogoutResponse attempt that is refused, with the exception and the message it got.
     *
     * @param class-string<RefusedXml> $exception
     */
    #[Test]
    #[DataProvider('provideRefusedLogoutResponses')]
    public function itRefusesALogoutResponseAttemptWithTheRuleNamed(
        string $attempt,
        string $exception,
        string $message,
    ): void {
        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        $this->validateLogoutResponse($this->refused($attempt));
    }

    /**
     * @return iterable<string, array{string, class-string<RefusedXml>, string}>
     */
    public static function provideRefusedLogoutResponses(): iterable
    {
        yield 'issuer with an sp provided id, the bypass the pass found (M-8)' => [
            'logout-response-issuer-sp-provided-id',
            IssuerMismatch::class,
            'The Issuer carries a NameQualifier, an SPNameQualifier or an SPProvidedID, which an entity identifier omits (M-8).',
        ];
        yield 'in response to in another case' => [
            'logout-response-in-response-to-in-another-case',
            InResponseToMismatch::class,
            'The InResponseTo of the LogoutResponse is not the ID of the LogoutRequest the consumer names (M-10).',
        ];
        yield 'destination host in upper case' => [
            'logout-response-destination-host-in-upper-case',
            DestinationMismatch::class,
            'The Destination of the message is not the URL at which it arrived (M-8).',
        ];
    }

    /**
     * Section 9.8: every LogoutResponse attempt that is accepted, with the values read.
     *
     * @param array<string, mixed> $values the values read that differ from those of the valid response
     */
    #[Test]
    #[DataProvider('provideAcceptedLogoutResponses')]
    public function itAcceptsALogoutResponseAttemptWithTheValuesRead(string $attempt, array $values): void
    {
        // When
        $accepted = $this->validateLogoutResponse(self::accepted($attempt));

        // Then
        static::assertSame(
            array_replace($this->logoutResponseValues(), $values),
            $this->valuesOfTheLogoutResponse($accepted),
        );
    }

    /**
     * @return iterable<string, array{string, array<string, mixed>}>
     */
    public static function provideAcceptedLogoutResponses(): iterable
    {
        yield 'xml base and lang on every element' => ['logout-response-xml-base-and-lang-on-every-element', []];
    }

    /**
     * Section 9.8, section 3 rows 3 and 16, M-3, M-5, M-6, M-7, M-13: every metadata attempt that is refused, with the
     * exception and the message it got.
     *
     * @param class-string<RefusedXml> $exception
     */
    #[Test]
    #[DataProvider('provideRefusedMetadata')]
    public function itRefusesAMetadataAttemptWithTheRuleNamed(string $attempt, string $exception, string $message): void
    {
        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        $this->readMetadata($this->refused($attempt));
    }

    /**
     * @return iterable<string, array{string, class-string<RefusedXml>, string}>
     */
    public static function provideRefusedMetadata(): iterable
    {
        yield 'key info in a namespace one character off' => [
            'metadata-key-info-in-a-namespace-one-character-off',
            MalformedMessage::class,
            'The md:KeyDescriptor holds a child out of the order of the schema, or one it does not allow there (M-5).',
        ];
        yield 'relative location under an xml base' => [
            'metadata-relative-location-under-an-xml-base',
            MalformedMessage::class,
            'A URI is not absolute (M-6).',
        ];
        yield 'valid until on 29 february 2100' => [
            'metadata-valid-until-on-29-february-2100',
            MalformedMessage::class,
            'A time is not a date of the calendar (M-6).',
        ];
        yield 'valid until on 29 february 2027' => [
            'metadata-valid-until-on-29-february-2027',
            MalformedMessage::class,
            'A time is not a date of the calendar (M-6).',
        ];
        yield 'valid until on 31 april' => [
            'metadata-valid-until-on-31-april',
            MalformedMessage::class,
            'A time is not a date of the calendar (M-6).',
        ];
        yield 'valid until in year 0000' => [
            'metadata-valid-until-in-year-0000',
            MalformedMessage::class,
            'A time is not a date of the calendar (M-6).',
        ];
        yield 'is default in upper case' => [
            'metadata-is-default-in-upper-case',
            MalformedMessage::class,
            'A boolean is not one of true, false, 1 and 0 (M-6).',
        ];
        yield 'key descriptor use with a trailing space' => [
            'metadata-key-descriptor-use-with-a-trailing-space',
            MalformedMessage::class,
            'An md:KeyDescriptor use is not signing or encryption (M-5).',
        ];
        yield 'key descriptor use capitalised' => [
            'metadata-key-descriptor-use-capitalised',
            MalformedMessage::class,
            'An md:KeyDescriptor use is not signing or encryption (M-5).',
        ];
        yield 'protocol support enumeration in upper case' => [
            'metadata-protocol-support-enumeration-in-upper-case',
            MalformedMessage::class,
            'An md:EntityDescriptor holds no md:IDPSSODescriptor and no md:SPSSODescriptor for SAML 2.0 (M-13).',
        ];
        yield 'bindings in another case' => [
            'metadata-bindings-in-another-case',
            MalformedMessage::class,
            'The md:IDPSSODescriptor lists no md:SingleSignOnService on HTTP-Redirect or HTTP-POST (section 6.5).',
        ];
    }

    /**
     * Section 9.8, M-5, M-6, M-7, M-17: every metadata attempt that is accepted, with the values read.
     *
     * @param array<string, mixed> $values the values read that differ from those of the valid metadata
     */
    #[Test]
    #[DataProvider('provideAcceptedMetadata')]
    public function itAcceptsAMetadataAttemptWithTheValuesRead(string $attempt, array $values): void
    {
        // When
        $descriptor = $this->readMetadata(self::accepted($attempt));

        // Then
        static::assertSame(array_replace($this->metadataValues(), $values), $this->valuesOfTheMetadata($descriptor));
    }

    /**
     * @return iterable<string, array{string, array<string, mixed>}>
     */
    public static function provideAcceptedMetadata(): iterable
    {
        yield 'default namespace' => ['metadata-default-namespace', []];
        yield 'xml base and lang on every element' => ['metadata-xml-base-and-lang-on-every-element', []];
        yield 'valid until on a leap day' => [
            'metadata-valid-until-on-a-leap-day',
            ['validUntil' => '2028-02-29T00:00:00.000000Z'],
        ];
        yield 'valid until at the end of year 9999' => [
            'metadata-valid-until-at-the-end-of-year-9999',
            ['validUntil' => '9999-12-31T23:59:59.999999Z'],
        ];
        yield 'want authn requests signed 1' => [
            'metadata-want-authn-requests-signed-1',
            ['wantAuthnRequestsSigned' => true],
        ];
        yield 'sixteen signing certificates' => [
            'metadata-sixteen-signing-certificates',
            ['signingCertificates' => 16],
        ];
        yield 'sixteen encryption certificates' => [
            'metadata-sixteen-encryption-certificates',
            ['encryptionCertificates' => 16],
        ];
        yield 'sixty four single sign on services' => [
            'metadata-sixty-four-single-sign-on-services',
            ['singleSignOnServices' => 64],
        ];
        yield 'sixty four single logout services' => [
            'metadata-sixty-four-single-logout-services',
            ['singleLogoutServices' => 64],
        ];
        yield 'sixty four assertion consumer services' => [
            'metadata-sixty-four-assertion-consumer-services',
            [
                'entityId' => 'https://sp.example.com/saml',
                'singleSignOnServices' => 0,
                'assertionConsumerServices' => 64,
                'wantAuthnRequestsSigned' => null,
            ],
        ];
        yield 'sixteen name id formats' => ['metadata-sixteen-name-id-formats', ['nameIdFormats' => 16]];
        yield 'entity id of 1024 characters' => [
            'metadata-entity-id-of-1024-characters',
            ['entityId' => 'https://' . str_repeat('a', 1016)],
        ];
        yield 'certificate split by a comment and a processing instruction' => [
            'metadata-certificate-split-by-a-comment-and-a-processing-instruction',
            [],
        ];
        yield 'comments and processing instructions everywhere' => [
            'metadata-comments-and-processing-instructions-everywhere',
            [],
        ];
    }

    /**
     * The response of $path, loaded, read before verification and validated as the service provider's, a response to
     * $requestId received at its assertion consumer service.
     */
    private function validateResponse(
        string $path,
        string $requestId,
        InMemoryReplayGuard $replay = new InMemoryReplayGuard(),
    ): AcceptedAssertion {
        return new ResponseValidator(SamlLoader::create(), $this->clock(), $replay)->validate(
            UnverifiedResponse::of($this->load($path)),
            new IdentityProvider(
                'https://idp.example.com/saml',
                [MetadataFixtures::certificate('idp')],
                [],
                [new Endpoint(Binding::HttpRedirect, 'https://idp.example.com/saml/sso')],
            ),
            ExpectedResponse::toRequest($requestId, 'https://sp.example.com/saml/acs', 'https://sp.example.com/saml'),
        );
    }

    /**
     * The AuthnRequest of $path, validated by the identity provider at its single sign-on service at $now, neither
     * party asking for signed requests: a signature present is verified all the same (M-2).
     */
    private function validateAuthnRequest(string $path, string $now = self::NOW): AcceptedAuthnRequest
    {
        return new AuthnRequestValidator(SamlLoader::create(), new FrozenClock(new DateTimeImmutable($now)))->validate(
            UnverifiedAuthnRequest::of($this->load($path)),
            AuthnRequestFixtures::serviceProvider(),
            AuthnRequestFixtures::identityProvider(),
            AuthnRequestFixtures::SINGLE_SIGN_ON,
        );
    }

    /**
     * The LogoutRequest of $path, from the identity provider to the service provider's single logout service: given
     * to validate() when it carries a ds:Signature, to validateAuthenticatedByBinding() otherwise.
     */
    private function validateLogoutRequest(string $path): AcceptedLogoutRequest
    {
        $document = $this->load($path);
        $request = UnverifiedLogoutRequest::of($document);
        $validator = LogoutFixtures::requestValidator();

        return $this->signed($document)
            ? $validator->validate(
                $request,
                LogoutFixtures::identityProvider(),
                LogoutFixtures::serviceProvider(),
                LogoutFixtures::SP_SLO,
            )
            : $validator->validateAuthenticatedByBinding(
                $request,
                LogoutFixtures::identityProvider(),
                LogoutFixtures::serviceProvider(),
                LogoutFixtures::SP_SLO,
            );
    }

    /**
     * The LogoutResponse of $path, from the service provider to the identity provider's single logout service, which
     * the binding authenticated, answering _logout-request.
     */
    private function validateLogoutResponse(string $path): AcceptedLogoutResponse
    {
        return LogoutFixtures::responseValidator()->validateAuthenticatedByBinding(
            UnverifiedLogoutResponse::of($this->load($path)),
            LogoutFixtures::serviceProvider(),
            LogoutFixtures::identityProvider(),
            LogoutFixtures::IDP_SLO,
            '_logout-request',
        );
    }

    /**
     * The metadata of $path, read as trusted by its channel.
     */
    private function readMetadata(string $path): EntityDescriptor
    {
        return new MetadataReader(SamlLoader::create(), $this->clock())->readTrusted($this->load($path));
    }

    /**
     * @return array<string, mixed> the values of the valid response, as the service provider reads them
     */
    private function responseValues(): array
    {
        return [
            'responseId' => '_response',
            'id' => '_assertion',
            'issuer' => 'https://idp.example.com/saml',
            'nameId' => '_7a2f4c1d9e',
            'recipient' => 'https://sp.example.com/saml/acs',
            'inResponseTo' => '_request',
            'audiences' => [['https://sp.example.com/saml']],
            'attributes' => [['jdoe@example.com']],
            'coverage' => SignatureCoverage::Assertion,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function valuesOfTheResponse(AcceptedAssertion $accepted): array
    {
        $assertion = $accepted->assertion;

        return [
            'responseId' => $accepted->responseId,
            'id' => $assertion->id,
            'issuer' => $assertion->issuer->entityId,
            'nameId' => $assertion->nameId->value,
            'recipient' => $assertion->confirmation->recipient,
            'inResponseTo' => $assertion->confirmation->inResponseTo,
            'audiences' => $assertion->conditions->audiences,
            'attributes' => array_map(
                static fn (Attribute $attribute): array => $attribute->values,
                $assertion->attributes,
            ),
            'coverage' => $accepted->coverage,
        ];
    }

    /**
     * @return array<string, mixed> the values of the valid AuthnRequest, as the identity provider reads them
     */
    private function authnRequestValues(): array
    {
        return [
            'id' => '_authn-request',
            'issueInstant' => '2026-09-30T11:59:59.000000Z',
            'issuer' => 'https://sp.example.com/saml',
            'assertionConsumerService' => 'https://sp.example.com/saml/acs',
            'isPassive' => false,
            'forceAuthn' => false,
            'allowCreate' => true,
            'classRefs' => 0,
            'authentication' => Authentication::None,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function valuesOfTheAuthnRequest(AcceptedAuthnRequest $accepted): array
    {
        $request = $accepted->request;

        return [
            'id' => $request->id,
            'issueInstant' => $request->issueInstant->format('Y-m-d\TH:i:s.u\Z'),
            'issuer' => $request->issuer->entityId,
            'assertionConsumerService' => $accepted->assertionConsumerService->location,
            'isPassive' => $request->isPassive,
            'forceAuthn' => $request->forceAuthn,
            'allowCreate' => $request->nameIdPolicy?->allowCreate,
            'classRefs' => count($request->requestedAuthnContext->authnContextClassRefs ?? []),
            'authentication' => $accepted->authentication,
        ];
    }

    /**
     * @return array<string, mixed> the values of the valid LogoutRequest, as the service provider reads them
     */
    private function logoutRequestValues(): array
    {
        return [
            'id' => '_logout-request',
            'issuer' => 'https://idp.example.com/saml',
            'nameId' => '_7a2f4c1d9e',
            'sessionIndexes' => 1,
            'authentication' => Authentication::Binding,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function valuesOfTheLogoutRequest(AcceptedLogoutRequest $accepted): array
    {
        return [
            'id' => $accepted->request->id,
            'issuer' => $accepted->request->issuer->entityId,
            'nameId' => $accepted->request->nameId->value,
            'sessionIndexes' => count($accepted->request->sessionIndexes),
            'authentication' => $accepted->authentication,
        ];
    }

    /**
     * @return array<string, mixed> the values of the valid LogoutResponse, as the identity provider reads them
     */
    private function logoutResponseValues(): array
    {
        return [
            'id' => '_logout-response',
            'issuer' => 'https://sp.example.com/saml',
            'inResponseTo' => '_logout-request',
            'status' => StatusCode::Success,
            'authentication' => Authentication::Binding,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function valuesOfTheLogoutResponse(AcceptedLogoutResponse $accepted): array
    {
        return [
            'id' => $accepted->response->id,
            'issuer' => $accepted->response->issuer->entityId,
            'inResponseTo' => $accepted->response->inResponseTo,
            'status' => $accepted->response->status->code,
            'authentication' => $accepted->authentication,
        ];
    }

    /**
     * @return array<string, mixed> the values of the identity provider's valid metadata
     */
    private function metadataValues(): array
    {
        return [
            'entityId' => 'https://idp.example.com/saml',
            'validUntil' => null,
            'signingCertificates' => 1,
            'encryptionCertificates' => 0,
            'singleSignOnServices' => 2,
            'singleLogoutServices' => 1,
            'assertionConsumerServices' => 0,
            'nameIdFormats' => 1,
            'wantAuthnRequestsSigned' => true,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function valuesOfTheMetadata(EntityDescriptor $descriptor): array
    {
        $identityProvider = $descriptor->identityProvider;
        $role = $identityProvider ?? $descriptor->serviceProvider;

        return [
            'entityId' => $descriptor->entityId,
            'validUntil' => $descriptor->validUntil?->format('Y-m-d\TH:i:s.u\Z'),
            'signingCertificates' => count($role->signingCertificates ?? []),
            'encryptionCertificates' => count($role->encryptionCertificates ?? []),
            'singleSignOnServices' => count($identityProvider->singleSignOnServices ?? []),
            'singleLogoutServices' => count($role->singleLogoutServices ?? []),
            'assertionConsumerServices' => count(
                $descriptor->serviceProvider->assertionConsumerServices->endpoints ?? [],
            ),
            'nameIdFormats' => count($role->nameIdFormats ?? []),
            'wantAuthnRequestsSigned' => $identityProvider?->wantAuthnRequestsSigned,
        ];
    }

    /**
     * Whether the root of $document carries a ds:Signature as a direct child.
     */
    private function signed(Document $document): bool
    {
        return Children::named($document->root(), new Name('http://www.w3.org/2000/09/xmldsig#', 'Signature')) !== [];
    }

    private function load(string $path): Document
    {
        return SamlLoader::create()->load(MetadataFixtures::bytes($path));
    }

    private function clock(): FrozenClock
    {
        return new FrozenClock(new DateTimeImmutable(self::NOW));
    }

    private function refused(string $attempt): string
    {
        return sprintf('hostile/adversarial-%s-refused.xml', $attempt);
    }

    private static function accepted(string $attempt): string
    {
        return sprintf('behaviour/adversarial-%s-accepted.xml', $attempt);
    }
}
