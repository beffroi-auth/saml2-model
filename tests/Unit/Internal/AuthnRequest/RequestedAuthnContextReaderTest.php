<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\AuthnRequest;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\AuthnRequest\RequestedAuthnContextReader;
use Beffroi\Saml2\Model\Protocol\AuthnContextComparison;
use Beffroi\Saml2\Model\Protocol\RequestedAuthnContext;
use Beffroi\Saml2\Model\SamlLoader;
use Dom\Element;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * Section 6.2 step 5: a samlp:RequestedAuthnContext read strictly (SAML Core §3.3.2.2.1), section 8 and M-5 on the
 * way.
 */
final class RequestedAuthnContextReaderTest extends TestCase
{
    private const string X509 = 'urn:oasis:names:tc:SAML:2.0:ac:classes:X509';

    private const string KERBEROS = 'urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos';

    /**
     * SAML Core §3.3.2.2.1: the comparison, and the class references in order, each read with Text::of() (I-12).
     */
    #[Test]
    public function itReadsTheComparisonAndTheClassReferences(): void
    {
        // Given
        $context = $this->context(
            'Comparison="better"',
            sprintf(
                '<saml:AuthnContextClassRef>%s</saml:AuthnContextClassRef><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:<!---->Kerberos</saml:AuthnContextClassRef>',
                self::X509,
            ),
        );

        // When
        $read = RequestedAuthnContextReader::read($context);

        // Then
        static::assertEquals(
            new RequestedAuthnContext(AuthnContextComparison::Better, [self::X509, self::KERBEROS]),
            $read,
        );
    }

    /**
     * SAML Core §3.3.2.2.1: without Comparison, exact.
     */
    #[Test]
    public function itReadsAnAbsentComparisonAsExact(): void
    {
        // Given
        $context = $this->context('', sprintf('<saml:AuthnContextClassRef>%s</saml:AuthnContextClassRef>', self::X509));

        // When
        $read = RequestedAuthnContextReader::read($context);

        // Then
        static::assertSame(AuthnContextComparison::Exact, $read->comparison);
    }

    /**
     * Section 8: a saml:AuthnContextDeclRef is refused by name, next to class references or not.
     */
    #[Test]
    public function itRefusesADeclarationReference(): void
    {
        // Given
        $context = $this->context('', sprintf(
            '<saml:AuthnContextClassRef>%s</saml:AuthnContextClassRef><saml:AuthnContextDeclRef>https://sp.example.com/saml/authn-context</saml:AuthnContextDeclRef>',
            self::X509,
        ));

        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs('The samlp:RequestedAuthnContext holds a saml:AuthnContextDeclRef, which the package does not support (section 8).');

        // When
        RequestedAuthnContextReader::read($context);
    }

    /**
     * M-5: a class reference of another namespace is not one.
     */
    #[Test]
    public function itRefusesAClassReferenceOfAnotherNamespace(): void
    {
        // Given
        $context = $this->context('', sprintf(
            '<samlp:AuthnContextClassRef>%s</samlp:AuthnContextClassRef>',
            self::X509,
        ));

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The samlp:RequestedAuthnContext holds a child other than saml:AuthnContextClassRef (M-5).');

        // When
        RequestedAuthnContextReader::read($context);
    }

    private function context(string $attributes, string $children): Element
    {
        return SamlLoader::create()
            ->load(sprintf(
                '<samlp:RequestedAuthnContext xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" %s>%s</samlp:RequestedAuthnContext>',
                $attributes,
                $children,
            ))
            ->root();
    }
}
