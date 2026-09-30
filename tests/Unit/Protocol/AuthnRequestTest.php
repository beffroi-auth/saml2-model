<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Protocol;

use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Protocol\AuthnContextComparison;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\Protocol\NameIdPolicy;
use Beffroi\Saml2\Model\Protocol\RequestedAuthnContext;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3: an AuthnRequest, whoever builds it (SAML Core §3.4.1); the rules of its values, M-6, M-9 and section
 * 8, applied by its constructor as by its reader (M-15).
 */
final class AuthnRequestTest extends TestCase
{
    private const string ID = '_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6';

    private const string ACS = 'https://sp.example.com/saml/acs';

    /**
     * Section 5.3: every field, as given.
     */
    #[Test]
    public function itHoldsItsFields(): void
    {
        // Given
        $issueInstant = new DateTimeImmutable('2026-10-01T12:00:00Z');
        $issuer = new Issuer('https://sp.example.com/saml');
        $policy = new NameIdPolicy(NameIdFormat::Transient->value);
        $context = new RequestedAuthnContext(AuthnContextComparison::Exact, [
            'urn:oasis:names:tc:SAML:2.0:ac:classes:X509',
        ]);

        // When
        $request = new AuthnRequest(
            self::ID,
            $issueInstant,
            $issuer,
            'https://idp.example.com/saml/sso',
            self::ACS,
            null,
            Binding::HttpPost->value,
            $policy,
            true,
            true,
            $context,
        );

        // Then
        static::assertSame(
            [
                self::ID,
                $issueInstant,
                $issuer,
                'https://idp.example.com/saml/sso',
                self::ACS,
                null,
                Binding::HttpPost->value,
                $policy,
                true,
                true,
                $context,
            ],
            [
                $request->id,
                $request->issueInstant,
                $request->issuer,
                $request->destination,
                $request->assertionConsumerServiceUrl,
                $request->assertionConsumerServiceIndex,
                $request->protocolBinding,
                $request->nameIdPolicy,
                $request->forceAuthn,
                $request->isPassive,
                $request->requestedAuthnContext,
            ],
        );
    }

    /**
     * SAML Core §3.4.1: everything but the ID, the IssueInstant and the Issuer is optional, ForceAuthn and IsPassive
     * false when absent.
     */
    #[Test]
    public function itHoldsNothingElseByDefault(): void
    {
        // When
        $request = $this->request();

        // Then
        static::assertSame(
            [null, null, null, null, null, false, false, null],
            [
                $request->destination,
                $request->assertionConsumerServiceUrl,
                $request->assertionConsumerServiceIndex,
                $request->protocolBinding,
                $request->nameIdPolicy,
                $request->forceAuthn,
                $request->isPassive,
                $request->requestedAuthnContext,
            ],
        );
    }

    /**
     * M-6: the ID is an NCName.
     */
    #[Test]
    public function itRefusesAnIdThatIsNotAnNcName(): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('An ID is not an NCName (M-6).');

        // When
        new AuthnRequest(
            '8e8dc5f6',
            new DateTimeImmutable('2026-10-01T12:00:00Z'),
            new Issuer('https://sp.example.com/saml'),
        );
    }

    /**
     * M-6: the Destination and the AssertionConsumerServiceURL are URIs.
     */
    #[Test]
    #[DataProvider('provideRelativeUris')]
    public function itRefusesAUriThatIsNotAbsolute(?string $destination, ?string $url): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A URI is not absolute (M-6).');

        // When
        $this->request($destination, $url);
    }

    /**
     * @return iterable<string, array{?string, ?string}>
     */
    public static function provideRelativeUris(): iterable
    {
        yield 'the Destination' => ['/saml/sso', null];
        yield 'the AssertionConsumerServiceURL' => [null, '/saml/acs'];
    }

    /**
     * M-6: the AssertionConsumerServiceIndex is an xs:unsignedShort, from 0 to 65535, both included.
     */
    #[Test]
    #[DataProvider('provideIndexes')]
    public function itAcceptsAnUnsignedShortIndex(int $index): void
    {
        // When
        $request = $this->request(index: $index);

        // Then
        static::assertSame($index, $request->assertionConsumerServiceIndex);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideIndexes(): iterable
    {
        yield 'zero' => [0];
        yield 'the largest' => [65_535];
    }

    /**
     * M-6: an index under 0 or over 65535 is not an xs:unsignedShort.
     */
    #[Test]
    #[DataProvider('provideIndexesOutOfRange')]
    public function itRefusesAnIndexOutOfRange(int $index): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('An index is not an xs:unsignedShort, digits without sign or leading zero from 0 to 65535 (M-6).');

        // When
        $this->request(index: $index);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideIndexesOutOfRange(): iterable
    {
        yield 'negative' => [-1];
        yield 'over 65535' => [65_536];
    }

    /**
     * M-9, SAML Core §3.4.1, M-15: an index next to a URL or a ProtocolBinding is refused whoever builds the request,
     * so that a writer never writes what the identity provider refuses.
     */
    #[Test]
    #[DataProvider('provideIndexNextToAnother')]
    public function itRefusesAnIndexNextToAUrlOrABinding(?string $url, ?string $binding): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('An AuthnRequest carries an AssertionConsumerServiceIndex next to an AssertionConsumerServiceURL or a ProtocolBinding, which SAML Core §3.4.1 makes mutually exclusive (M-9).');

        // When
        $this->request(url: $url, index: 0, binding: $binding);
    }

    /**
     * @return iterable<string, array{?string, ?string}>
     */
    public static function provideIndexNextToAnother(): iterable
    {
        yield 'next to the URL' => [self::ACS, null];
        yield 'next to the ProtocolBinding' => [null, Binding::HttpPost->value];
    }

    /**
     * Section 8, M-15: a ProtocolBinding other than HTTP-POST is refused whoever builds the request.
     */
    #[Test]
    public function itRefusesTheRedirectProtocolBinding(): void
    {
        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs('The ProtocolBinding of an AuthnRequest is not HTTP-POST, the one binding the package answers over (section 8).');

        // When
        $this->request(url: self::ACS, binding: Binding::HttpRedirect->value);
    }

    private function request(
        ?string $destination = null,
        ?string $url = null,
        ?int $index = null,
        ?string $binding = null,
    ): AuthnRequest {
        return new AuthnRequest(
            self::ID,
            new DateTimeImmutable('2026-10-01T12:00:00Z'),
            new Issuer('https://sp.example.com/saml'),
            $destination,
            $url,
            $index,
            $binding,
        );
    }
}
