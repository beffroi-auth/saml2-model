<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Writing;

use Beffroi\Saml2\Model\Assertion\Assertion;
use Beffroi\Saml2\Model\Exception\UnsuccessfulResponse;
use Beffroi\Saml2\Model\Protocol\Response;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Tests\Unit\Writing\ResponseWriterFixtures as Fixtures;
use Beffroi\Saml2\Model\Validation\SignatureCoverage;
use Beffroi\Saml2\Model\Writing\ResponseWriter;
use Beffroi\Saml2\Model\Writing\SignedParts;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use Beffroi\Xml\Dsig\Exception\DigestMismatch;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Dom\Element;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Sections 5.7 and 6.6, M-2, M-15: a samlp:Response and its assertion written and signed by the identity provider,
 * and read back by the validator of the service provider; the response rows of section 9.1.
 */
final class ResponseWriterTest extends TestCase
{
    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    private const string ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';

    /**
     * Section 9.1 rows "a response with its signed assertion" and "with the response signed too", M-2, M-15, SAML
     * Profiles §4.1.4.5: written and signed with the identity provider's test key, serialized with Core, loaded again
     * with SamlLoader::create(), accepted by the validator with its clock frozen at the IssueInstant, the assertion as
     * it was written, under the coverage asked.
     */
    #[Test]
    #[DataProvider('provideResponses')]
    public function itWritesWhatTheValidatorAccepts(
        Assertion $assertion,
        ?string $inResponseTo,
        SignedParts $parts,
        SignatureCoverage $coverage,
    ): void {
        // Given
        $response = Fixtures::response($assertion, $inResponseTo);
        $document = new ResponseWriter()->write($response, $this->signing(), $parts);

        // When
        $accepted = Fixtures::validator()->validate(
            Fixtures::reload($document),
            Fixtures::identityProvider(),
            Fixtures::expected($inResponseTo),
        );

        // Then
        static::assertEquals([$assertion, $response->id, $coverage], [
            $accepted->assertion,
            $accepted->responseId,
            $accepted->coverage,
        ]);
    }

    /**
     * @return iterable<string, array{Assertion, ?string, SignedParts, SignatureCoverage}>
     */
    public static function provideResponses(): iterable
    {
        yield 'the assertion signed, to the request' => [
            Fixtures::assertion(),
            Fixtures::REQUEST,
            SignedParts::Assertion,
            SignatureCoverage::Assertion,
        ];
        yield 'the assertion signed, unsolicited' => [
            Fixtures::assertion(inResponseTo: null),
            null,
            SignedParts::Assertion,
            SignatureCoverage::Assertion,
        ];
        yield 'both signed, to the request' => [
            Fixtures::assertion(),
            Fixtures::REQUEST,
            SignedParts::AssertionAndResponse,
            SignatureCoverage::AssertionAndResponse,
        ];
        yield 'both signed, unsolicited' => [
            Fixtures::assertion(inResponseTo: null),
            null,
            SignedParts::AssertionAndResponse,
            SignatureCoverage::AssertionAndResponse,
        ];
        yield 'the assertion with everything it holds signed' => [
            Fixtures::everything(),
            Fixtures::REQUEST,
            SignedParts::Assertion,
            SignatureCoverage::Assertion,
        ];
        yield 'the assertion with everything it holds and the response signed, unsolicited' => [
            Fixtures::everything(null),
            null,
            SignedParts::AssertionAndResponse,
            SignatureCoverage::AssertionAndResponse,
        ];
    }

    /**
     * Section 5.7, section 6.6 step 3, SAML Core §2.3.3, §5.4.1, dsig.md section 6.2: by default the assertion alone
     * is signed, its Signature the child after its Issuer, over its ID, with no InclusiveNamespaces, the certificate
     * of the key in its KeyInfo when given; the response carries none.
     */
    #[Test]
    public function itSignsTheAssertionAloneByDefault(): void
    {
        // Given
        $response = Fixtures::response();
        $signing = new Signing(
            MetadataFixtures::signingKey('idp'),
            certificatePem: MetadataFixtures::certificatePem('idp'),
        );

        // When
        $root = new ResponseWriter()
            ->write($response, $signing)
            ->root();

        // Then
        $assertion = Children::one($root, new Name(self::ASSERTION, 'Assertion'));
        $signature = Children::one($assertion, new Name(self::DSIG, 'Signature'));
        static::assertSame(
            [
                ['saml:Issuer', 'samlp:Status', 'saml:Assertion'],
                ['saml:Issuer', 'ds:Signature', 'saml:Subject', 'saml:Conditions', 'saml:AuthnStatement'],
                '#' . $response->assertion?->id,
                [],
                MetadataFixtures::certificate('idp'),
            ],
            [
                Fixtures::names(Children::all($root)),
                Fixtures::names(Children::all($assertion)),
                $this->reference($signature),
                $this->descendantsNamed($signature, 'InclusiveNamespaces'),
                Text::of($this->path($signature, ['KeyInfo', 'X509Data', 'X509Certificate'])),
            ],
        );
    }

    /**
     * Section 6.6 step 3, dsig.md section 5.5, SAML Core §3.2.1: for SignedParts::AssertionAndResponse, the response is
     * signed too, its Signature the child after its Issuer, over its ID, without KeyInfo when the Signing carries no
     * certificate, and the assertion keeps its own.
     */
    #[Test]
    public function itSignsTheResponseOnRequest(): void
    {
        // Given
        $response = Fixtures::response();

        // When
        $root = new ResponseWriter()
            ->write($response, $this->signing(), SignedParts::AssertionAndResponse)
            ->root();

        // Then
        $signature = Children::one($root, new Name(self::DSIG, 'Signature'));
        $assertion = Children::one($root, new Name(self::ASSERTION, 'Assertion'));
        static::assertSame(
            [
                ['saml:Issuer', 'ds:Signature', 'samlp:Status', 'saml:Assertion'],
                '#' . $response->id,
                '#' . $response->assertion?->id,
                ['ds:SignedInfo', 'ds:SignatureValue'],
            ],
            [
                Fixtures::names(Children::all($root)),
                $this->reference($signature),
                $this->reference(Children::one($assertion, new Name(self::DSIG, 'Signature'))),
                Fixtures::names(Children::all($signature)),
            ],
        );
    }

    /**
     * dsig.md section 5.5, M-2: the response is signed over the document the assertion's signing returned, so that its
     * digest covers the assertion's Signature: without it, the response's signature no longer holds.
     */
    #[Test]
    public function itSignsTheResponseOverTheSignatureOfItsAssertion(): void
    {
        // Given
        $document = new ResponseWriter()->write(
            Fixtures::response(),
            $this->signing(),
            SignedParts::AssertionAndResponse,
        );
        Children::one(
            Children::one($document->root(), new Name(self::ASSERTION, 'Assertion')),
            new Name(self::DSIG, 'Signature'),
        )->remove();
        $response = Fixtures::reload($document);

        // Then
        $this->expectException(DigestMismatch::class);
        $this->expectExceptionMessageIs('The claimed element is not what was signed (D-8).');

        // When
        Fixtures::validator()->validate($response, Fixtures::identityProvider(), Fixtures::expected());
    }

    /**
     * Section 5.7: both signatures are made with the algorithm of the Signing.
     */
    #[Test]
    public function itSignsWithTheAlgorithmItIsGiven(): void
    {
        // Given
        $signing = new Signing(MetadataFixtures::signingKey('idp'), SignatureAlgorithm::RsaSha512);

        // When
        $root = new ResponseWriter()
            ->write(Fixtures::response(), $signing, SignedParts::AssertionAndResponse)
            ->root();

        // Then
        $assertion = Children::one($root, new Name(self::ASSERTION, 'Assertion'));
        static::assertSame(
            [SignatureAlgorithm::RsaSha512->value, SignatureAlgorithm::RsaSha512->value],
            [
                $this->signatureMethod(Children::one($root, new Name(self::DSIG, 'Signature'))),
                $this->signatureMethod(Children::one($assertion, new Name(self::DSIG, 'Signature'))),
            ],
        );
    }

    /**
     * Section 9.1 row "a failure", M-13, SAML Profiles §4.1.4.1: a failure Responder / AuthnFailed written without
     * assertion, unsigned or signed, is reported by the validator as UnsuccessfulResponse carrying both codes.
     */
    #[Test]
    #[DataProvider('provideFailureSignings')]
    public function itWritesAFailureTheValidatorReports(?Signing $signing): void
    {
        // Given
        $response = Fixtures::reload(new ResponseWriter()->writeFailure(Fixtures::failure(), $signing));

        // When
        try {
            Fixtures::validator()->validate($response, Fixtures::identityProvider(), Fixtures::expected());
            static::fail('The failure is not reported.');
        } catch (UnsuccessfulResponse $failure) {
            // Then
            static::assertSame(
                [StatusCode::Responder, SecondLevelStatusCode::AuthnFailed],
                [$failure->status->code, $failure->status->secondLevel],
            );
        }
    }

    /**
     * @return iterable<string, array{?Signing}>
     */
    public static function provideFailureSignings(): iterable
    {
        yield 'unsigned' => [null];
        yield 'signed' => [new Signing(MetadataFixtures::signingKey('idp'))];
    }

    /**
     * Section 5.7, SAML Core §3.2.1: a failure is signed when a Signing is given, its Signature the child after its
     * Issuer, over its ID; unsigned otherwise.
     */
    #[Test]
    public function itSignsAFailureOnRequest(): void
    {
        // Given
        $failure = Fixtures::failure();

        // When
        $root = new ResponseWriter()
            ->writeFailure($failure, $this->signing())
            ->root();

        // Then
        static::assertSame(
            [['saml:Issuer', 'ds:Signature', 'samlp:Status'], '#' . $failure->id],
            [
                Fixtures::names(Children::all($root)),
                $this->reference(Children::one($root, new Name(self::DSIG, 'Signature'))),
            ],
        );
    }

    /**
     * Section 5.7: a failure written without Signing carries no Signature.
     */
    #[Test]
    public function itWritesAFailureUnsignedWithoutSigning(): void
    {
        // When
        $root = new ResponseWriter()
            ->writeFailure(Fixtures::failure(), null)
            ->root();

        // Then
        static::assertSame(['saml:Issuer', 'samlp:Status'], Fixtures::names(Children::all($root)));
    }

    /**
     * Section 6.6 step 1, section 5.8, M-15: what the validator of the service provider would refuse of the response
     * and its assertion together is a programming error of the caller, refused before anything is built.
     */
    #[Test]
    #[DataProvider('provideResponsesTheValidatorRefuses')]
    public function itRefusesToWriteWhatTheValidatorRefuses(Response $response, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        new ResponseWriter()->write($response, $this->signing());
    }

    /**
     * @return iterable<string, array{Response, string}>
     */
    public static function provideResponsesTheValidatorRefuses(): iterable
    {
        yield 'a failure' => [
            Fixtures::failure(),
            'The response carries no assertion: a failure is written by writeFailure() (section 6.6).',
        ];
        yield 'no Destination' => [
            Fixtures::response(destination: null),
            'The response holds no Destination, which the writer always writes and the service provider requires of a signed response (section 6.6).',
        ];
        yield 'the ID of the assertion' => [
            Fixtures::response(Fixtures::assertion(id: '_same'), id: '_same'),
            'The response and its assertion carry the same ID, which one ID space refuses (M-14).',
        ];
        yield 'another issuer for the assertion' => [
            Fixtures::response(Fixtures::assertion(issuer: 'https://other-idp.example.com/saml')),
            'The response and its assertion name different issuers, which the service provider compares with one entity ID (M-8).',
        ];
        yield 'a Recipient other than the Destination' => [
            Fixtures::response(Fixtures::assertion(recipient: 'https://sp.example.com/saml/acs/')),
            'The Recipient of the bearer confirmation is not the Destination of the response, which the service provider compares with one URL (M-8).',
        ];
        yield 'an InResponseTo on the confirmation only' => [
            Fixtures::response(Fixtures::assertion(), null),
            'The InResponseTo of the bearer confirmation is not the one of the response, which the service provider compares with one request (M-10).',
        ];
        yield 'an InResponseTo on the response only' => [
            Fixtures::response(Fixtures::assertion(inResponseTo: null)),
            'The InResponseTo of the bearer confirmation is not the one of the response, which the service provider compares with one request (M-10).',
        ];
        yield 'no SessionIndex' => [
            Fixtures::response(Fixtures::assertion(sessionIndex: null)),
            'The authentication statement holds no SessionIndex, which the Single Logout profile needs (section 6.6).',
        ];
    }

    /**
     * Section 6.6 step 1, section 5.8, SAML Profiles §4.1.4.1: a response whose status is Success, or one without
     * Destination, is not a failure writeFailure() writes: a programming error of the caller.
     */
    #[Test]
    #[DataProvider('provideFailuresTheWriterRefuses')]
    public function itRefusesToWriteAFailureThatIsNotOne(Response $response, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        new ResponseWriter()->writeFailure($response, null);
    }

    /**
     * @return iterable<string, array{Response, string}>
     */
    public static function provideFailuresTheWriterRefuses(): iterable
    {
        yield 'a response whose status is Success' => [
            Fixtures::response(),
            'The response carries an assertion: a response whose status is Success is written by write() (section 6.6).',
        ];
        yield 'no Destination' => [
            Fixtures::failure(destination: null),
            'The response holds no Destination, which the writer always writes and the service provider requires of a signed response (section 6.6).',
        ];
    }

    /**
     * The identity provider's test key, without certificate.
     */
    private function signing(): Signing
    {
        return new Signing(MetadataFixtures::signingKey('idp'));
    }

    /**
     * The URI of the one Reference of a ds:Signature.
     */
    private function reference(Element $signature): string
    {
        return Attributes::required($this->path($signature, ['SignedInfo', 'Reference']), new Name(null, 'URI'));
    }

    /**
     * The Algorithm of the SignatureMethod of a ds:Signature.
     */
    private function signatureMethod(Element $signature): string
    {
        return Attributes::required(
            $this->path($signature, ['SignedInfo', 'SignatureMethod']),
            new Name(null, 'Algorithm'),
        );
    }

    /**
     * @param list<string> $path the local names of XML Signature from $element down
     */
    private function path(Element $element, array $path): Element
    {
        foreach ($path as $local) {
            $element = Children::one($element, new Name(self::DSIG, $local));
        }

        return $element;
    }

    /**
     * @return list<Element> the elements under $element whose local name is $local
     */
    private function descendantsNamed(Element $element, string $local): array
    {
        $found = [];
        foreach (Children::all($element) as $child) {
            if ($child->localName === $local) {
                $found[] = $child;
            }
            $found = [...$found, ...$this->descendantsNamed($child, $local)];
        }

        return $found;
    }
}
