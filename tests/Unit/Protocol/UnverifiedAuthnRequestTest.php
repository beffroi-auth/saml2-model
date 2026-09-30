<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Protocol;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Protocol\UnverifiedAuthnRequest;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\MixedContent;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * Section 5.4, M-1: an AuthnRequest read before anything is verified, its root and its Issuer, what the identity
 * provider needs to choose the service provider.
 */
final class UnverifiedAuthnRequestTest extends TestCase
{
    /**
     * M-1: the document as loaded, and the Issuer of the request.
     */
    #[Test]
    public function itReadsTheIssuerOfTheRequest(): void
    {
        // Given
        $document = MetadataFixtures::load('behaviour/authn-request-unsigned.xml');

        // When
        $request = UnverifiedAuthnRequest::of($document);

        // Then
        static::assertSame([$document, 'https://sp.example.com/saml'], [$request->document, $request->issuer]);
    }

    /**
     * M-1: a request without Issuer is read, its Issuer null; the validator refuses it (section 6.2 step 1).
     */
    #[Test]
    public function itReadsARequestWithoutIssuer(): void
    {
        // Given
        $document = MetadataFixtures::load('hostile/authn-request-without-issuer-refused.xml');

        // When
        $request = UnverifiedAuthnRequest::of($document);

        // Then
        static::assertNull($request->issuer);
    }

    /**
     * Section 6.2 step 1: the root is a samlp:AuthnRequest, compared by namespace and local name.
     */
    #[Test]
    #[DataProvider('provideOtherRoots')]
    public function itRefusesAnotherRoot(string $root): void
    {
        // Given
        $document = SamlLoader::create()->load($root);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The root of the document is not a samlp:AuthnRequest (section 6.2).');

        // When
        UnverifiedAuthnRequest::of($document);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideOtherRoots(): iterable
    {
        yield 'a samlp:LogoutRequest' => ['<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>'];
        yield 'an AuthnRequest of the assertion namespace' => [
            '<saml:AuthnRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>',
        ];
        yield 'an AuthnRequest in no namespace' => ['<AuthnRequest/>'];
    }

    /**
     * M-4: one saml:Issuer, a direct child.
     */
    #[Test]
    public function itRefusesTwoIssuers(): void
    {
        // Given
        $document = $this->request('<saml:Issuer>https://sp.example.com/saml</saml:Issuer><saml:Issuer>https://attacker.example.com/saml</saml:Issuer>');

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The samlp:AuthnRequest holds more than one saml:Issuer (M-4).');

        // When
        UnverifiedAuthnRequest::of($document);
    }

    /**
     * M-6: the Issuer is an entity ID, a URI.
     */
    #[Test]
    public function itRefusesAnIssuerThatIsNotAUri(): void
    {
        // Given
        $document = $this->request('<saml:Issuer> https://sp.example.com/saml</saml:Issuer>');

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A URI holds whitespace, a control or format character, or bytes that are not UTF-8 (M-6).');

        // When
        UnverifiedAuthnRequest::of($document);
    }

    /**
     * I-12: the Issuer is read with Text::of(), comments concatenated, an element refused.
     */
    #[Test]
    public function itReadsTheIssuerAsTheSignerMeantIt(): void
    {
        // Given
        $document = $this->request('<saml:Issuer>https://sp.example.com<!---->/saml</saml:Issuer>');

        // When
        $request = UnverifiedAuthnRequest::of($document);

        // Then
        static::assertSame('https://sp.example.com/saml', $request->issuer);
    }

    /**
     * I-12: an Issuer holding an element is Core's MixedContent.
     */
    #[Test]
    public function itRefusesAnIssuerHoldingAnElement(): void
    {
        // Given
        $document = $this->request('<saml:Issuer>https://sp.example.com<saml:Issuer/>/saml</saml:Issuer>');

        // Then
        $this->expectException(MixedContent::class);
        $this->expectExceptionMessageIs('The element has a child that is neither text, CDATA, comment nor processing instruction (I-12).');

        // When
        UnverifiedAuthnRequest::of($document);
    }

    private function request(string $children): Document
    {
        return SamlLoader::create()->load(sprintf(
            '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">%s</samlp:AuthnRequest>',
            $children,
        ));
    }
}
