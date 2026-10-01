<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Assertion;

use function array_fill;
use function array_map;
use Beffroi\Saml2\Model\Assertion\Attribute;
use Beffroi\Saml2\Model\Assertion\AttributeNameFormat;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\Assertion\AttributeStatementReader;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Core\Name;
use function count;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.1 step 11: the attributes of an assertion, as read, their values as text (SAML Core §2.7.3).
 */
final class AttributeStatementReaderTest extends TestCase
{
    use AssertionFixtures;

    /**
     * Section 5.3, section 6.1 step 11: each attribute with its Name, NameFormat, FriendlyName and values, in document
     * order.
     */
    #[Test]
    public function itReadsTheAttributesInDocumentOrder(): void
    {
        // Given
        $statement = $this->child($this->document('behaviour/assertion-valid-accepted.xml'), 'AttributeStatement');

        // When
        $attributes = AttributeStatementReader::read($statement);

        // Then
        static::assertSame(
            [
                [
                    'urn:oid:0.9.2342.19200300.100.1.3',
                    AttributeNameFormat::Uri,
                    'mail',
                    ['jdoe@example.com'],
                ],
                [
                    'urn:oid:1.3.6.1.4.1.5923.1.1.1.1',
                    AttributeNameFormat::Uri,
                    'eduPersonAffiliation',
                    ['member', 'staff'],
                ],
            ],
            array_map(
                static fn (Attribute $attribute): array => [
                    $attribute->name,
                    $attribute->nameFormat,
                    $attribute->friendlyName,
                    $attribute->values,
                ],
                $attributes,
            ),
        );
    }

    /**
     * §9.3 row 18, section 6.1 step 11: Keycloak's six saml:Attribute named Role, one value each, are six attributes
     * in document order, none merged.
     */
    #[Test]
    public function itKeepsRepeatedNamesInDocumentOrder(): void
    {
        // Given
        $statement = $this->child(
            $this->document('behaviour/assertion-attribute-names-repeated-accepted.xml'),
            'AttributeStatement',
        );

        // When
        $attributes = AttributeStatementReader::read($statement);

        // Then
        static::assertSame(
            [
                ['Role', ['default-roles-idp']],
                ['Role', ['manage-account-links']],
                ['Role', ['view-profile']],
                ['Role', ['manage-account']],
                ['Role', ['uma_authorization']],
                ['Role', ['offline_access']],
            ],
            array_map(static fn (Attribute $attribute): array => [$attribute->name, $attribute->values], $attributes),
        );
    }

    /**
     * §9.3 row 10, dsig.md §6.3: SimpleSAMLphp's AttributeValue with xsi:type="xs:string", where the prefix xs
     * resolves to nothing, as in the verified document; the value is its text, and the type is never resolved.
     */
    #[Test]
    public function itReadsAValueWithAnUnresolvedXsiTypeAsItsText(): void
    {
        // Given
        $statement = $this->child(
            $this->document('behaviour/assertion-attribute-value-xsi-type-accepted.xml'),
            'AttributeStatement',
        );
        $value = Children::one(
            Children::one($statement, new Name(Saml::ASSERTION, 'Attribute')),
            new Name(Saml::ASSERTION, 'AttributeValue'),
        );

        // When
        $attributes = AttributeStatementReader::read($statement);

        // Then
        static::assertSame(
            [[['uid', ['test']]], null],
            [
                array_map(static fn (Attribute $attribute): array => [
                    $attribute->name,
                    $attribute->values,
                ], $attributes),
                $value->lookupNamespaceURI('xs'),
            ],
        );
    }

    /**
     * Section 7, M-17: 256 attributes in the statement, and 256 values in an attribute, the bounds, are accepted.
     */
    #[Test]
    #[DataProvider('provideCountsAtTheirBound')]
    public function itAcceptsACountAtItsBound(string $fixture, int $attributes, int $values): void
    {
        // Given
        $statement = $this->child($this->document($fixture), 'AttributeStatement');

        // When
        $read = AttributeStatementReader::read($statement);

        // Then
        static::assertSame(
            array_fill(0, $attributes, $values),
            array_map(static fn (Attribute $attribute): int => count($attribute->values), $read),
        );
    }

    /**
     * @return iterable<string, array{string, int, int}>
     */
    public static function provideCountsAtTheirBound(): iterable
    {
        yield '256 attributes' => ['behaviour/assertion-256-attributes-accepted.xml', 256, 1];
        yield '256 values' => ['behaviour/assertion-256-attribute-values-accepted.xml', 1, 256];
    }

    /**
     * §9.2 row 36, section 7, M-17: 257 attributes in the statement; 257 values in an attribute; the message names the
     * bound.
     */
    #[Test]
    #[DataProvider('provideCountsOverTheirBound')]
    public function itRefusesACountOverItsBound(string $fixture, string $message): void
    {
        // Given
        $document = $this->document($fixture);

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        AttributeStatementReader::read($this->child($document, 'AttributeStatement'));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideCountsOverTheirBound(): iterable
    {
        yield '257 attributes' => [
            'hostile/assertion-257-attributes-refused.xml',
            'The AttributeStatement holds more than 256 Attribute, the bound of section 7 (M-17).',
        ];
        yield '257 values' => [
            'hostile/assertion-257-attribute-values-refused.xml',
            'An Attribute holds more than 256 AttributeValue, the bound of section 7 (M-17).',
        ];
    }

    /**
     * M-4, M-5, SAML Core §2.7.3: an empty statement, an element that is not an attribute in it, an attribute without
     * Name, an unknown NameFormat, an element that is not a value in an attribute.
     */
    #[Test]
    #[DataProvider('provideMalformedStatements')]
    public function itRefusesAMalformedStatement(string $fixture, string $message): void
    {
        // Given
        $document = $this->document($fixture);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        AttributeStatementReader::read($this->child($document, 'AttributeStatement'));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideMalformedStatements(): iterable
    {
        yield 'an empty statement' => [
            'hostile/assertion-attribute-statement-empty-refused.xml',
            'The saml:AttributeStatement holds no saml:Attribute (M-4).',
        ];
        yield 'a value directly in the statement' => [
            'hostile/assertion-attribute-statement-unknown-child-refused.xml',
            'The saml:AttributeStatement holds a child out of the order of the schema, or one it does not allow there (M-5).',
        ];
        yield 'an attribute without Name' => [
            'hostile/assertion-attribute-without-name-refused.xml',
            'The saml:Attribute has no Name (M-5).',
        ];
        yield 'an unknown NameFormat' => [
            'hostile/assertion-attribute-unknown-name-format-refused.xml',
            'The NameFormat of an attribute is not one of the three of SAML Core (M-5).',
        ];
        yield 'an Audience in an attribute' => [
            'hostile/assertion-attribute-unknown-child-refused.xml',
            'The saml:Attribute holds a child out of the order of the schema, or one it does not allow there (M-5).',
        ];
    }

    /**
     * Section 6.1 step 11, section 12, I-12: a value holding an element, a NameID as the value of eduPersonTargetedID,
     * is refused by Core as it refuses it.
     */
    #[Test]
    public function itLetsCoreRefuseAValueHoldingAnElement(): void
    {
        // Given
        $document = $this->document('hostile/assertion-attribute-value-element-refused.xml');

        // Then
        $this->expectException(MixedContent::class);
        $this->expectExceptionMessageIs('The element has a child that is neither text, CDATA, comment nor processing instruction (I-12).');

        // When
        AttributeStatementReader::read($this->child($document, 'AttributeStatement'));
    }

    /**
     * §9.2 row 29, section 6.7: saml:EncryptedAttribute, until sub-spike 9e.
     */
    #[Test]
    public function itRefusesAnEncryptedAttribute(): void
    {
        // Given
        $document = $this->document('hostile/assertion-encrypted-attribute-refused.xml');
        $message = 'The attribute statement holds a saml:EncryptedAttribute, which the package does not support until sub-spike 9e (section 6.7).';

        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        AttributeStatementReader::read($this->child($document, 'AttributeStatement'));
    }
}
