<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\AuthnRequest;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\AuthnRequest\NameIdPolicyReader;
use Beffroi\Saml2\Model\Protocol\NameIdPolicy;
use Beffroi\Saml2\Model\SamlLoader;
use Dom\Element;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * Section 6.2 step 5: a samlp:NameIDPolicy read strictly (SAML Core §3.4.1.1), M-5 and M-6 on the way.
 */
final class NameIdPolicyReaderTest extends TestCase
{
    /**
     * Section 6.2 step 5: the three attributes, AllowCreate in each of the forms of a boolean (M-6) or absent.
     */
    #[Test]
    #[DataProvider('providePolicies')]
    public function itReadsThePolicy(string $attributes, NameIdPolicy $expected): void
    {
        // Given
        $policy = $this->policy($attributes, '');

        // When
        $read = NameIdPolicyReader::read($policy);

        // Then
        static::assertEquals($expected, $read);
    }

    /**
     * @return iterable<string, array{string, NameIdPolicy}>
     */
    public static function providePolicies(): iterable
    {
        $encrypted = 'urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted';
        yield 'every attribute' => [
            sprintf('Format="%s" SPNameQualifier="https://affiliation.example.com" AllowCreate="true"', $encrypted),
            new NameIdPolicy($encrypted, 'https://affiliation.example.com', true),
        ];
        yield 'AllowCreate="1"' => ['AllowCreate="1"', new NameIdPolicy(null, null, true)];
        yield 'AllowCreate="false"' => ['AllowCreate="false"', new NameIdPolicy()];
        yield 'AllowCreate="0"' => ['AllowCreate="0"', new NameIdPolicy()];
        yield 'no attribute' => ['', new NameIdPolicy()];
    }

    /**
     * M-5: NameIDPolicyType is empty, any element child is refused, a saml:Issuer as well as an extension.
     */
    #[Test]
    #[DataProvider('provideChildren')]
    public function itRefusesAnElementChild(string $child): void
    {
        // Given
        $policy = $this->policy('', $child);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The samlp:NameIDPolicy holds an element, which the schema does not allow there (M-5).');

        // When
        NameIdPolicyReader::read($policy);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideChildren(): iterable
    {
        yield 'a saml:Issuer' => ['<saml:Issuer>https://sp.example.com/saml</saml:Issuer>'];
        yield 'an element of another namespace' => ['<ext:Anything xmlns:ext="urn:example:extension"/>'];
    }

    private function policy(string $attributes, string $children): Element
    {
        return SamlLoader::create()
            ->load(sprintf(
                '<samlp:NameIDPolicy xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" %s>%s</samlp:NameIDPolicy>',
                $attributes,
                $children,
            ))
            ->root();
    }
}
