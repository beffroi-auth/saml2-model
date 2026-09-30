<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Writing;

use function array_map;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Protocol\AuthnContextComparison;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\Protocol\NameIdPolicy;
use Beffroi\Saml2\Model\Protocol\RequestedAuthnContext;
use Beffroi\Saml2\Model\Protocol\UnverifiedAuthnRequest;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Tests\Unit\Validation\AuthnRequestFixtures;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Saml2\Model\Writing\AuthnRequestWriter;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Core\Text;
use DateTimeImmutable;
use DateTimeZone;
use Dom\Element;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Sections 5.7 and 6.6, M-15: a samlp:AuthnRequest written by the service provider, and read back by the validator
 * of the identity provider; the AuthnRequest rows of section 9.1.
 */
final class AuthnRequestWriterTest extends TestCase
{
    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    private const string PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';

    /**
     * Section 9.1 row "an AuthnRequest signed", M-2, M-15: written and signed with the service provider's test key,
     * serialized with Core, loaded again with SamlLoader::create(), accepted by validate() as it was written.
     */
    #[Test]
    #[DataProvider('provideRequests')]
    public function itSignsWhatTheValidatorVerifies(AuthnRequest $request): void
    {
        // Given
        $document = new AuthnRequestWriter()->write($request, new Signing(MetadataFixtures::signingKey('sp')));

        // When
        $accepted = AuthnRequestFixtures::validator()->validate(
            $this->reload($document),
            AuthnRequestFixtures::serviceProvider(true),
            AuthnRequestFixtures::identityProvider(true),
            AuthnRequestFixtures::SINGLE_SIGN_ON,
        );

        // Then
        static::assertEquals([$request, Authentication::XmlSignature], [
            $accepted->request,
            $accepted->authentication,
        ]);
    }

    /**
     * Section 9.1 row "an AuthnRequest unsigned", M-15: written without signature, accepted by validate() when
     * neither party's metadata asks for signed requests.
     */
    #[Test]
    #[DataProvider('provideRequests')]
    public function itWritesWhatTheValidatorReads(AuthnRequest $request): void
    {
        // Given
        $document = new AuthnRequestWriter()->write($request, null);

        // When
        $accepted = AuthnRequestFixtures::validator()->validate(
            $this->reload($document),
            AuthnRequestFixtures::serviceProvider(),
            AuthnRequestFixtures::identityProvider(),
            AuthnRequestFixtures::SINGLE_SIGN_ON,
        );

        // Then
        static::assertEquals([$request, Authentication::None], [$accepted->request, $accepted->authentication]);
    }

    /**
     * Section 9.1 row "an AuthnRequest for HTTP-Redirect", section 6.8, M-15: written without signature, the binding
     * signing the query string, accepted by validateAuthenticatedByBinding() although both parties ask for signed
     * requests.
     */
    #[Test]
    #[DataProvider('provideRequests')]
    public function itWritesWhatTheRedirectBindingCarries(AuthnRequest $request): void
    {
        // Given
        $document = new AuthnRequestWriter()->write($request, null);

        // When
        $accepted = AuthnRequestFixtures::validator()->validateAuthenticatedByBinding(
            $this->reload($document),
            AuthnRequestFixtures::serviceProvider(true),
            AuthnRequestFixtures::identityProvider(true),
            AuthnRequestFixtures::SINGLE_SIGN_ON,
        );

        // Then
        static::assertEquals([$request, Authentication::Binding], [$accepted->request, $accepted->authentication]);
    }

    /**
     * @return iterable<string, array{AuthnRequest}>
     */
    public static function provideRequests(): iterable
    {
        yield 'to the service of a URL, over HTTP-POST' => [self::request()];
        yield 'to the service of an index' => [self::request(url: null, index: 1, binding: null)];
        yield 'to the default service' => [self::request(url: null, binding: null)];
        yield 'with everything a request asks' => [new AuthnRequest(
            SamlId::generate(),
            new DateTimeImmutable(AuthnRequestFixtures::NOW),
            new Issuer(AuthnRequestFixtures::SERVICE_PROVIDER),
            AuthnRequestFixtures::SINGLE_SIGN_ON,
            AuthnRequestFixtures::ASSERTION_CONSUMER,
            null,
            AuthnRequestFixtures::POST,
            new NameIdPolicy(NameIdFormat::Persistent->value, 'https://affiliation.example.com', true),
            true,
            true,
            new RequestedAuthnContext(AuthnContextComparison::Minimum, [
                'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
                'urn:oasis:names:tc:SAML:2.0:ac:classes:X509',
            ]),
        )];
        yield 'with an empty NameIDPolicy and an exact context' => [new AuthnRequest(
            SamlId::generate(),
            new DateTimeImmutable(AuthnRequestFixtures::NOW),
            new Issuer(AuthnRequestFixtures::SERVICE_PROVIDER),
            AuthnRequestFixtures::SINGLE_SIGN_ON,
            nameIdPolicy: new NameIdPolicy(),
            requestedAuthnContext: new RequestedAuthnContext(AuthnContextComparison::Exact, [
                'urn:oasis:names:tc:SAML:2.0:ac:classes:X509',
            ]),
        )];
    }

    /**
     * Section 6.6 step 3, SAML Core §3.2.1, §5.4.1, dsig.md section 6.2: the Signature is the child after the Issuer,
     * over the ID of the request, with no InclusiveNamespaces, the certificate of the key in its KeyInfo when given.
     */
    #[Test]
    public function itSignsTheRequestWithTheSignatureAfterTheIssuer(): void
    {
        // Given
        $request = self::request();
        $signing = new Signing(
            MetadataFixtures::signingKey('sp'),
            certificatePem: MetadataFixtures::certificatePem('sp'),
        );

        // When
        $root = new AuthnRequestWriter()
            ->write($request, $signing)
            ->root();

        // Then
        $signature = Children::all($root)[1];
        $signedInfo = Children::one($signature, new Name(self::DSIG, 'SignedInfo'));
        static::assertSame(
            [
                ['Issuer', 'Signature'],
                '#' . $request->id,
                [],
                MetadataFixtures::certificate('sp'),
            ],
            [
                $this->localNames($root),
                Attributes::required(
                    Children::one($signedInfo, new Name(self::DSIG, 'Reference')),
                    new Name(null, 'URI'),
                ),
                $this->descendantsNamed($signature, 'InclusiveNamespaces'),
                Text::of($this->path($signature, ['KeyInfo', 'X509Data', 'X509Certificate'])),
            ],
        );
    }

    /**
     * Section 6.6 step 2, core.md section 6.5, SAML Core §3.4.1: one prefix per namespace, samlp and saml; the
     * attributes of the request, its IssueInstant in UTC to the second whatever the zone it was given in, the
     * children in the order of the schema.
     */
    #[Test]
    public function itWritesTheRequestWithOnePrefixPerNamespace(): void
    {
        // Given
        $request = new AuthnRequest(
            SamlId::generate(),
            new DateTimeImmutable('2026-10-01T12:00:00.750Z')->setTimezone(new DateTimeZone('Europe/Paris')),
            new Issuer(AuthnRequestFixtures::SERVICE_PROVIDER),
            AuthnRequestFixtures::SINGLE_SIGN_ON,
            AuthnRequestFixtures::ASSERTION_CONSUMER,
            null,
            AuthnRequestFixtures::POST,
            new NameIdPolicy(NameIdFormat::Transient->value, null, true),
            true,
            true,
            new RequestedAuthnContext(AuthnContextComparison::Better, ['urn:oasis:names:tc:SAML:2.0:ac:classes:X509']),
        );

        // When
        $root = new AuthnRequestWriter()
            ->write($request, null)
            ->root();

        // Then
        $context = Children::one($root, new Name(self::PROTOCOL, 'RequestedAuthnContext'));
        static::assertSame(
            [
                'samlp:AuthnRequest',
                ['saml:Issuer', 'samlp:NameIDPolicy', 'samlp:RequestedAuthnContext'],
                ['saml:AuthnContextClassRef'],
                [
                    'ID' => $request->id,
                    'Version' => '2.0',
                    'IssueInstant' => '2026-10-01T12:00:00Z',
                    'Destination' => AuthnRequestFixtures::SINGLE_SIGN_ON,
                    'ForceAuthn' => 'true',
                    'IsPassive' => 'true',
                    'ProtocolBinding' => AuthnRequestFixtures::POST,
                    'AssertionConsumerServiceURL' => AuthnRequestFixtures::ASSERTION_CONSUMER,
                ],
                ['Format' => NameIdFormat::Transient->value, 'AllowCreate' => 'true'],
                ['Comparison' => 'better'],
            ],
            [
                $root->nodeName,
                array_map(static fn (Element $child): string => $child->nodeName, Children::all($root)),
                array_map(static fn (Element $child): string => $child->nodeName, Children::all($context)),
                $this->attributes($root),
                $this->attributes(Children::one($root, new Name(self::PROTOCOL, 'NameIDPolicy'))),
                $this->attributes($context),
            ],
        );
    }

    /**
     * Section 6.6 step 2, SAML Core §3.4.1: ForceAuthn, IsPassive and AllowCreate are written only when true, their
     * absence meaning false; an index is written as the decimal of an xs:unsignedShort.
     */
    #[Test]
    public function itWritesNoFlagThatIsFalse(): void
    {
        // Given
        $request = new AuthnRequest(
            SamlId::generate(),
            new DateTimeImmutable(AuthnRequestFixtures::NOW),
            new Issuer(AuthnRequestFixtures::SERVICE_PROVIDER),
            AuthnRequestFixtures::SINGLE_SIGN_ON,
            null,
            65_535,
            nameIdPolicy: new NameIdPolicy(),
        );

        // When
        $root = new AuthnRequestWriter()
            ->write($request, null)
            ->root();

        // Then
        static::assertSame(
            [
                [
                    'ID' => $request->id,
                    'Version' => '2.0',
                    'IssueInstant' => AuthnRequestFixtures::NOW,
                    'Destination' => AuthnRequestFixtures::SINGLE_SIGN_ON,
                    'AssertionConsumerServiceIndex' => '65535',
                ],
                [],
            ],
            [
                $this->attributes($root),
                $this->attributes(Children::one($root, new Name(self::PROTOCOL, 'NameIDPolicy'))),
            ],
        );
    }

    /**
     * Section 6.6 step 1, M-8, M-15: a request without Destination would be refused by the identity provider once
     * signed, by XML or by the binding, which the writer cannot tell apart: a programming error of the caller.
     */
    #[Test]
    public function itRefusesARequestWithoutDestination(): void
    {
        // Given
        $request = self::request(destination: null);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The request holds no Destination, which the identity provider requires of a signed request, by XML or by the binding (section 6.6).');

        // When
        new AuthnRequestWriter()->write($request, null);
    }

    /**
     * Section 9.1: the request the writer signed with the service provider's test key, committed as
     * behaviour/authn-request-written-and-signed-by-the-writer.xml and verified by xmlsec1, is accepted by validate().
     */
    #[Test]
    public function itWroteTheRequestXmlsec1Verified(): void
    {
        // Given
        $request = UnverifiedAuthnRequest::of(MetadataFixtures::load('behaviour/authn-request-written-and-signed-by-the-writer.xml'));

        // When
        $accepted = AuthnRequestFixtures::validator()->validate(
            $request,
            AuthnRequestFixtures::serviceProvider(true),
            AuthnRequestFixtures::identityProvider(true),
            AuthnRequestFixtures::SINGLE_SIGN_ON,
        );

        // Then
        static::assertSame(
            [Authentication::XmlSignature, AuthnRequestFixtures::SERVICE_PROVIDER, 0],
            [
                $accepted->authentication,
                $accepted->request->issuer->entityId,
                $accepted->assertionConsumerService->index,
            ],
        );
    }

    private static function request(
        ?string $destination = AuthnRequestFixtures::SINGLE_SIGN_ON,
        ?string $url = AuthnRequestFixtures::ASSERTION_CONSUMER,
        ?int $index = null,
        ?string $binding = AuthnRequestFixtures::POST,
    ): AuthnRequest {
        return new AuthnRequest(
            SamlId::generate(),
            new DateTimeImmutable(AuthnRequestFixtures::NOW),
            new Issuer(AuthnRequestFixtures::SERVICE_PROVIDER),
            $destination,
            $url,
            $index,
            $binding,
        );
    }

    private function reload(Document $document): UnverifiedAuthnRequest
    {
        return UnverifiedAuthnRequest::of(SamlLoader::create()->load(new Serializer()->serialize($document)));
    }

    /**
     * @return list<string>
     */
    private function localNames(Element $element): array
    {
        return array_map(static fn (Element $child): string => $child->localName, Children::all($element));
    }

    /**
     * The attributes in no namespace, in document order, the namespace declarations left aside.
     *
     * @return array<string, string>
     */
    private function attributes(Element $element): array
    {
        $attributes = [];
        foreach ($element->attributes as $attribute) {
            if ($attribute->namespaceURI !== null) {
                continue;
            }
            $attributes[$attribute->localName] = $attribute->value;
        }

        return $attributes;
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
