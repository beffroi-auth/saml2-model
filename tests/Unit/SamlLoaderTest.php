<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit;

use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Xml\Core\Exception\DuplicateId;
use Beffroi\Xml\Core\Exception\InvalidId;
use Beffroi\Xml\Core\IdAttribute;
use Beffroi\Xml\Core\Limits;
use function array_map;
use function file_get_contents;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.1, M-14: one loader and one ID space over the SAML, XML Signature and XML Encryption ID attributes.
 */
final class SamlLoaderTest extends TestCase
{
    /**
     * M-14, core.md section 5.3: ID on the elements of the three SAML namespaces, Id on those of XML Signature and XML
     * Encryption, and nothing else.
     */
    #[Test]
    public function itRegistersTheIdAttributesOfTheSamlStack(): void
    {
        // When
        $attributes = SamlLoader::idAttributes();

        // Then
        static::assertSame(
            [
                [null, 'ID', 'urn:oasis:names:tc:SAML:2.0:assertion'],
                [null, 'ID', 'urn:oasis:names:tc:SAML:2.0:protocol'],
                [null, 'ID', 'urn:oasis:names:tc:SAML:2.0:metadata'],
                [null, 'Id', 'http://www.w3.org/2000/09/xmldsig#'],
                [null, 'Id', 'http://www.w3.org/2001/04/xmlenc#'],
            ],
            array_map(
                static fn (IdAttribute $attribute): array => [
                    $attribute->attribute->namespace,
                    $attribute->attribute->local,
                    $attribute->elementNamespace,
                ],
                $attributes->attributes,
            ),
        );
    }

    /**
     * M-14: the loader indexes the ID of every SAML element and the Id of every XML Signature and XML Encryption
     * element of the document.
     */
    #[Test]
    #[DataProvider('provideIndexedIds')]
    public function itIndexesTheIdsOfThePreset(string $id, string $namespace, string $localName): void
    {
        // Given
        $document = SamlLoader::create()->load($this->fixture('behaviour/id-attributes-of-the-five-namespaces-loads.xml'));

        // When
        $element = $document->elementById($id);

        // Then
        static::assertSame([$namespace, $localName], [$element->namespaceURI, $element->localName]);
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function provideIndexedIds(): iterable
    {
        yield 'ID of samlp:Response' => ['_response', 'urn:oasis:names:tc:SAML:2.0:protocol', 'Response'];
        yield 'ID of saml:Assertion' => ['_assertion', 'urn:oasis:names:tc:SAML:2.0:assertion', 'Assertion'];
        yield 'Id of ds:Signature' => ['_signature', 'http://www.w3.org/2000/09/xmldsig#', 'Signature'];
        yield 'Id of xenc:EncryptedData' => ['_encrypted-data', 'http://www.w3.org/2001/04/xmlenc#', 'EncryptedData'];
        yield 'ID of md:EntityDescriptor' => [
            '_entity-descriptor',
            'urn:oasis:names:tc:SAML:2.0:metadata',
            'EntityDescriptor',
        ];
    }

    /**
     * M-14, core.md section 5.3: an attribute outside the preset identifies nothing, whatever its name suggests.
     */
    #[Test]
    #[DataProvider('provideUnregisteredIds')]
    public function itDoesNotIndexAnAttributeOutsideThePreset(string $id): void
    {
        // Given
        $document = SamlLoader::create()->load(
            $this->fixture('behaviour/id-attributes-outside-the-preset-not-indexed-loads.xml'),
        );

        // When / Then
        static::assertFalse($document->hasId($id));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUnregisteredIds(): iterable
    {
        yield 'Id on a SAML element' => ['_saml-id-attribute'];
        yield 'ID on an XML Signature element' => ['_dsig-uppercase-attribute'];
        yield 'ID on an XML Encryption element' => ['_xenc-uppercase-attribute'];
        yield 'ID on an element of another namespace' => ['_foreign-namespace'];
        yield 'ID on an element in no namespace' => ['_no-namespace'];
        yield 'xml:id' => ['_xml-id'];
    }

    /**
     * M-14, section 3 (ID confusion across vocabularies), core.md I-8: an ID of one vocabulary equal to an ID of
     * another is a duplicate, and the document is refused at load.
     */
    #[Test]
    #[DataProvider('provideDuplicatesAcrossVocabularies')]
    public function itRefusesAnIdSharedAcrossVocabularies(string $fixture): void
    {
        // Given
        $bytes = $this->fixture($fixture);

        // Then
        $this->expectException(DuplicateId::class);
        $this->expectExceptionMessageIs('An ID value appears twice in the document (I-8).');

        // When
        SamlLoader::create()->load($bytes);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideDuplicatesAcrossVocabularies(): iterable
    {
        yield 'a saml:Assertion ID equal to a ds:Signature Id' => [
            'hostile/id-assertion-equal-to-signature-id-refused.xml',
        ];
        yield 'a samlp:Response ID equal to an xenc:EncryptedData Id' => [
            'hostile/id-response-equal-to-encrypted-data-id-refused.xml',
        ];
        yield 'an md:EntityDescriptor ID equal to a saml:Assertion ID' => [
            'hostile/id-entity-descriptor-equal-to-assertion-id-refused.xml',
        ];
    }

    /**
     * Section 5.1, core.md section 7: the loader applies the bounds of Core the caller gives it.
     */
    #[Test]
    public function itAppliesTheLimitsItIsGiven(): void
    {
        // Given
        $bytes = $this->fixture('behaviour/id-attributes-of-the-five-namespaces-loads.xml');

        // Then
        $this->expectException(InvalidId::class);
        $this->expectExceptionMessageIs('An ID is longer than maxIdLength, 9 bytes (I-8).');

        // When
        SamlLoader::create(new Limits(maxIdLength: 9))->load($bytes);
    }

    private function fixture(string $path): string
    {
        $bytes = file_get_contents(__DIR__ . '/../Fixture/' . $path);
        static::assertIsString($bytes);

        return $bytes;
    }
}
