<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Assertion;

use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\InvalidNameId;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * Section 5.3, M-12: a NameID under the rule of its format, whoever builds it (SAML Core §2.2.3, §8.3).
 */
final class NameIdTest extends TestCase
{
    /**
     * Section 5.3: the value, the format and the three optional attributes of SAML Core §2.2.2, kept as given.
     */
    #[Test]
    public function itKeepsItsValueFormatAndQualifiers(): void
    {
        // When
        $nameId = new NameId(
            '_7a2f4c1d9e',
            NameIdFormat::Persistent,
            'https://idp.example.com/saml',
            'https://sp.example.com/saml',
            'employee-42',
        );

        // Then
        static::assertSame(
            [
                '_7a2f4c1d9e',
                NameIdFormat::Persistent,
                'https://idp.example.com/saml',
                'https://sp.example.com/saml',
                'employee-42',
            ],
            [$nameId->value, $nameId->format, $nameId->nameQualifier, $nameId->spNameQualifier, $nameId->spProvidedId],
        );
    }

    /**
     * M-12, SAML Core §2.2.2 as corrected by E60: without a format, the unspecified one, and no qualifier.
     */
    #[Test]
    public function itIsOfTheUnspecifiedFormatWithoutQualifierByDefault(): void
    {
        // When
        $nameId = new NameId('jdoe');

        // Then
        static::assertSame(
            [NameIdFormat::Unspecified, null, null, null],
            [$nameId->format, $nameId->nameQualifier, $nameId->spNameQualifier, $nameId->spProvidedId],
        );
    }

    /**
     * M-12: a value its format allows, never trimmed nor otherwise changed.
     */
    #[Test]
    #[DataProvider('provideValues')]
    public function itAcceptsAValueItsFormatAllows(string $value, NameIdFormat $format): void
    {
        // When
        $nameId = new NameId($value, $format);

        // Then
        static::assertSame($value, $nameId->value);
    }

    /**
     * @return iterable<string, array{string, NameIdFormat}>
     */
    public static function provideValues(): iterable
    {
        yield 'unspecified, a space inside' => ['John Doe', NameIdFormat::Unspecified];
        yield 'unspecified, ending with a two-byte character' => ["j\u{101}", NameIdFormat::Unspecified];
        yield 'unspecified, exactly 1024 characters' => [str_repeat('a', 1024), NameIdFormat::Unspecified];
        yield 'unspecified, exactly 1024 two-byte characters' => [
            str_repeat("\u{E9}", 1024),
            NameIdFormat::Unspecified,
        ];
        yield 'X509SubjectName, spaces inside' => ['CN=John Doe, O=Example, C=FR', NameIdFormat::X509SubjectName];
        yield 'WindowsDomainQualifiedName' => ['EXAMPLE\jdoe', NameIdFormat::WindowsDomainQualifiedName];
        yield 'kerberos' => ['jdoe/admin@EXAMPLE.COM', NameIdFormat::Kerberos];
        yield 'persistent, exactly 256 characters' => [str_repeat('a', 256), NameIdFormat::Persistent];
        yield 'persistent, exactly 256 two-byte characters' => [str_repeat("\u{E9}", 256), NameIdFormat::Persistent];
        yield 'transient, exactly 256 characters' => [str_repeat('a', 256), NameIdFormat::Transient];
        yield 'entity, a URL' => ['https://sp.example.com/saml', NameIdFormat::Entity];
        yield 'entity, a URN' => ['urn:example:sp', NameIdFormat::Entity];
        yield 'emailAddress' => ['john.doe@example.com', NameIdFormat::EmailAddress];
        yield 'emailAddress, a quoted local part holding an @' => ['"a@b"@example.com', NameIdFormat::EmailAddress];
        yield 'emailAddress, a two-byte local part' => ["\u{101}@example.com", NameIdFormat::EmailAddress];
    }

    /**
     * §9.2 row 27, M-12: an empty value; the message carries nothing of the NameID (M-16).
     */
    #[Test]
    public function itRefusesAnEmptyValue(): void
    {
        // Then
        $this->expectException(InvalidNameId::class);
        $this->expectExceptionMessageIs('The NameID is empty (M-12).');

        // When
        new NameId('');
    }

    /**
     * §9.2 row 27, M-12, M-6: whitespace or a control character around the value, never trimmed.
     */
    #[Test]
    #[DataProvider('provideSurroundedValues')]
    public function itRefusesWhitespaceAroundTheValue(string $value, NameIdFormat $format): void
    {
        // Then
        $this->expectException(InvalidNameId::class);
        $this->expectExceptionMessageIs('The NameID starts or ends with whitespace or a control character, or is not UTF-8 (M-12).');

        // When
        new NameId($value, $format);
    }

    /**
     * @return iterable<string, array{string, NameIdFormat}>
     */
    public static function provideSurroundedValues(): iterable
    {
        yield 'a leading space' => [' jdoe', NameIdFormat::Unspecified];
        yield 'a trailing space' => ['jdoe ', NameIdFormat::Unspecified];
        yield 'a leading tab' => ["\tjdoe", NameIdFormat::Unspecified];
        yield 'a trailing newline' => ["jdoe\n", NameIdFormat::Unspecified];
        yield 'a leading carriage return' => ["\rjdoe", NameIdFormat::Unspecified];
        yield 'a trailing no-break space' => ["jdoe\u{A0}", NameIdFormat::Unspecified];
        yield 'a leading ideographic space' => ["\u{3000}jdoe", NameIdFormat::Unspecified];
        yield 'a whitespace alone' => [' ', NameIdFormat::Unspecified];
        yield 'bytes that are not UTF-8' => ["jdoe\xFF", NameIdFormat::Unspecified];
        yield 'a persistent value with a trailing space' => ['_7a2f4c1d9e ', NameIdFormat::Persistent];
        yield 'an email address with a leading space' => [' john.doe@example.com', NameIdFormat::EmailAddress];
    }

    /**
     * §9.2 row 27, M-12, SAML Core §8.3.7, §8.3.8: a persistent or a transient identifier over 256 characters.
     */
    #[Test]
    #[DataProvider('provideLongPairwiseValues')]
    public function itRefusesAPersistentOrTransientValueOver256Characters(string $value, NameIdFormat $format): void
    {
        // Then
        $this->expectException(InvalidNameId::class);
        $this->expectExceptionMessageIs('A persistent or transient NameID is longer than 256 characters (M-12).');

        // When
        new NameId($value, $format);
    }

    /**
     * @return iterable<string, array{string, NameIdFormat}>
     */
    public static function provideLongPairwiseValues(): iterable
    {
        yield 'persistent, 257 characters' => [str_repeat('a', 257), NameIdFormat::Persistent];
        yield 'transient, 257 characters' => [str_repeat('a', 257), NameIdFormat::Transient];
        yield 'persistent, 257 two-byte characters' => [str_repeat("\u{E9}", 257), NameIdFormat::Persistent];
    }

    /**
     * M-12, section 7: every other format is at most 1024 characters.
     */
    #[Test]
    #[DataProvider('provideLongValues')]
    public function itRefusesAValueOver1024Characters(string $value, NameIdFormat $format): void
    {
        // Then
        $this->expectException(InvalidNameId::class);
        $this->expectExceptionMessageIs('A NameID is longer than 1024 characters (M-12).');

        // When
        new NameId($value, $format);
    }

    /**
     * @return iterable<string, array{string, NameIdFormat}>
     */
    public static function provideLongValues(): iterable
    {
        yield 'unspecified, 1025 characters' => [str_repeat('a', 1025), NameIdFormat::Unspecified];
        yield 'unspecified, 1025 two-byte characters' => [str_repeat("\u{E9}", 1025), NameIdFormat::Unspecified];
        yield 'entity, 1025 characters' => ['urn:' . str_repeat('a', 1021), NameIdFormat::Entity];
        yield 'emailAddress, 1025 characters' => [str_repeat('a', 1013) . '@example.com', NameIdFormat::EmailAddress];
    }

    /**
     * §9.2 row 27, M-12, SAML Core §8.3.6: an entity identifier carries none of the three optional attributes.
     */
    #[Test]
    #[DataProvider('provideQualifiedEntities')]
    public function itRefusesAnEntityWithAQualifier(
        ?string $nameQualifier,
        ?string $spNameQualifier,
        ?string $spProvidedId,
    ): void {
        // Then
        $this->expectException(InvalidNameId::class);
        $this->expectExceptionMessageIs('An entity NameID carries a NameQualifier, an SPNameQualifier or an SPProvidedID (M-12).');

        // When
        new NameId(
            'https://sp.example.com/saml',
            NameIdFormat::Entity,
            $nameQualifier,
            $spNameQualifier,
            $spProvidedId,
        );
    }

    /**
     * @return iterable<string, array{?string, ?string, ?string}>
     */
    public static function provideQualifiedEntities(): iterable
    {
        yield 'with NameQualifier' => ['https://idp.example.com/saml', null, null];
        yield 'with SPNameQualifier' => [null, 'https://sp.example.com/saml', null];
        yield 'with SPProvidedID' => [null, null, 'employee-42'];
    }

    /**
     * M-12, SAML Core §8.3.6: an entity identifier is a URI of M-6.
     */
    #[Test]
    #[DataProvider('provideNotUris')]
    public function itRefusesAnEntityThatIsNotAUri(string $value): void
    {
        // Then
        $this->expectException(InvalidNameId::class);
        $this->expectExceptionMessageIs('An entity NameID is not a URI (M-12).');

        // When
        new NameId($value, NameIdFormat::Entity);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNotUris(): iterable
    {
        yield 'a relative path' => ['relative/path'];
        yield 'a name' => ['sp.example.com'];
        yield 'a space inside' => ['https://sp.example.com/a b'];
    }

    /**
     * M-12, SAML Core §8.3.2: an email address is an addr-spec, a local part and a domain around the last @.
     */
    #[Test]
    #[DataProvider('provideNotAddrSpecs')]
    public function itRefusesAnEmailAddressThatIsNotAnAddrSpec(string $value): void
    {
        // Then
        $this->expectException(InvalidNameId::class);
        $this->expectExceptionMessageIs('An emailAddress NameID is not an addr-spec (M-12).');

        // When
        new NameId($value, NameIdFormat::EmailAddress);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNotAddrSpecs(): iterable
    {
        yield 'no @' => ['john.doe'];
        yield 'no local part' => ['@example.com'];
        yield 'no domain' => ['john.doe@'];
        yield 'nothing after the last @' => ['john@example.com@'];
        yield 'a space in the local part' => ['john doe@example.com'];
        yield 'a space in the domain' => ['john.doe@exa mple.com'];
        yield 'a tab in the domain' => ["john.doe@exa\tmple.com"];
        yield 'a phrase before it' => ['John Doe <john.doe@example.com>'];
    }

    /**
     * M-12, SAML Core §8.3.7, §8.3.8: the qualifiers of a persistent or a transient identifier name an entity.
     */
    #[Test]
    #[DataProvider('providePairwiseQualifiers')]
    public function itAcceptsTheEntityQualifiersOfAPairwiseIdentifier(
        NameIdFormat $format,
        ?string $nameQualifier,
        ?string $spNameQualifier,
    ): void {
        // When
        $nameId = new NameId('_7a2f4c1d9e', $format, $nameQualifier, $spNameQualifier);

        // Then
        static::assertSame([$nameQualifier, $spNameQualifier], [$nameId->nameQualifier, $nameId->spNameQualifier]);
    }

    /**
     * @return iterable<string, array{NameIdFormat, ?string, ?string}>
     */
    public static function providePairwiseQualifiers(): iterable
    {
        yield 'persistent, both' => [NameIdFormat::Persistent, 'https://idp.example.com/saml', 'urn:example:sp'];
        yield 'persistent, neither' => [NameIdFormat::Persistent, null, null];
        yield 'transient, both' => [NameIdFormat::Transient, 'https://idp.example.com/saml', 'urn:example:sp'];
        yield 'transient, NameQualifier alone' => [NameIdFormat::Transient, 'https://idp.example.com/saml', null];
        yield 'transient, SPNameQualifier alone' => [NameIdFormat::Transient, null, 'urn:example:sp'];
    }

    /**
     * M-12, SAML Core §2.2.2: for the other formats, the qualifiers are a domain, which Core does not make a URI.
     */
    #[Test]
    public function itAcceptsQualifiersThatAreNotUrisOnAnotherFormat(): void
    {
        // When
        $nameId = new NameId('jdoe', NameIdFormat::Unspecified, 'EXAMPLE', 'example sp');

        // Then
        static::assertSame(['EXAMPLE', 'example sp'], [$nameId->nameQualifier, $nameId->spNameQualifier]);
    }

    /**
     * M-12, SAML Core §8.3.7, §8.3.8: a NameQualifier of a persistent or a transient identifier that is not a URI.
     */
    #[Test]
    #[DataProvider('provideNameQualifiersNotUris')]
    public function itRefusesAPairwiseNameQualifierThatIsNotAUri(NameIdFormat $format, string $nameQualifier): void
    {
        // Then
        $this->expectException(InvalidNameId::class);
        $this->expectExceptionMessageIs('The NameQualifier of a persistent or transient NameID is not a URI (M-12).');

        // When
        new NameId('_7a2f4c1d9e', $format, $nameQualifier);
    }

    /**
     * @return iterable<string, array{NameIdFormat, string}>
     */
    public static function provideNameQualifiersNotUris(): iterable
    {
        yield 'persistent, a domain' => [NameIdFormat::Persistent, 'EXAMPLE'];
        yield 'persistent, empty' => [NameIdFormat::Persistent, ''];
        yield 'transient, a relative path' => [NameIdFormat::Transient, 'relative/path'];
    }

    /**
     * M-12, SAML Core §8.3.7, §8.3.8: an SPNameQualifier of a persistent or a transient identifier that is not a URI.
     */
    #[Test]
    #[DataProvider('provideSpNameQualifiersNotUris')]
    public function itRefusesAPairwiseSpNameQualifierThatIsNotAUri(NameIdFormat $format, string $spNameQualifier): void
    {
        // Then
        $this->expectException(InvalidNameId::class);
        $this->expectExceptionMessageIs('The SPNameQualifier of a persistent or transient NameID is not a URI (M-12).');

        // When
        new NameId('_7a2f4c1d9e', $format, null, $spNameQualifier);
    }

    /**
     * @return iterable<string, array{NameIdFormat, string}>
     */
    public static function provideSpNameQualifiersNotUris(): iterable
    {
        yield 'persistent, a name' => [NameIdFormat::Persistent, 'example sp'];
        yield 'transient, empty' => [NameIdFormat::Transient, ''];
        yield 'transient, a leading space' => [NameIdFormat::Transient, ' urn:example:sp'];
    }
}
