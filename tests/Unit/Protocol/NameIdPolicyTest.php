<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Protocol;

use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\InvalidNameId;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Protocol\NameIdPolicy;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3, section 6.2 step 5: the NameIDPolicy of an AuthnRequest (SAML Core §3.4.1.1), its format one of SAML
 * Core §8.3 or encrypted.
 */
final class NameIdPolicyTest extends TestCase
{
    /**
     * Section 5.3: the format, the SPNameQualifier and AllowCreate, as given.
     */
    #[Test]
    public function itHoldsItsFields(): void
    {
        // When
        $policy = new NameIdPolicy(NameIdFormat::Persistent->value, 'https://affiliation.example.com', true);

        // Then
        static::assertSame(
            [NameIdFormat::Persistent->value, 'https://affiliation.example.com', true],
            [$policy->format, $policy->spNameQualifier, $policy->allowCreate],
        );
    }

    /**
     * SAML Core §3.4.1.1: every attribute is optional, AllowCreate false when absent.
     */
    #[Test]
    public function itHoldsNothingByDefault(): void
    {
        // When
        $policy = new NameIdPolicy();

        // Then
        static::assertSame([null, null, false], [$policy->format, $policy->spNameQualifier, $policy->allowCreate]);
    }

    /**
     * Section 6.2 step 5, SAML Core §3.4.1.1: the eight formats of SAML Core §8.3 and encrypted.
     */
    #[Test]
    #[DataProvider('provideFormats')]
    public function itAcceptsTheFormatsOfSamlCore(string $format): void
    {
        // When
        $policy = new NameIdPolicy($format);

        // Then
        static::assertSame($format, $policy->format);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideFormats(): iterable
    {
        foreach (NameIdFormat::cases() as $format) {
            yield $format->name => [$format->value];
        }
        yield 'encrypted' => ['urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted'];
    }

    /**
     * M-12, section 6.2 step 5: any other format is refused, compared byte for byte.
     */
    #[Test]
    #[DataProvider('provideRefusedFormats')]
    public function itRefusesEveryOtherFormat(string $format): void
    {
        // Then
        $this->expectException(InvalidNameId::class);
        $this->expectExceptionMessageIs('The format of a samlp:NameIDPolicy is neither one of the eight of SAML Core nor encrypted (M-12).');

        // When
        new NameIdPolicy($format);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRefusedFormats(): iterable
    {
        yield 'a format of its own' => ['urn:example:nameid-format:pairwise'];
        yield 'encrypted under the 1.1 URI' => ['urn:oasis:names:tc:SAML:1.1:nameid-format:encrypted'];
        yield 'unspecified under the 2.0 URI' => ['urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified'];
        yield 'another case' => ['urn:oasis:names:tc:SAML:2.0:nameid-format:Persistent'];
    }

    /**
     * M-6: the SPNameQualifier names a service provider or an affiliation by its entity ID, a URI.
     */
    #[Test]
    public function itRefusesAnSpNameQualifierThatIsNotAUri(): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A URI is not absolute (M-6).');

        // When
        new NameIdPolicy(null, 'affiliation');
    }
}
