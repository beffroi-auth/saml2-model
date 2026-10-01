<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Assertion;

use function array_map;
use function array_diff;
use function array_filter;
use function array_values;
use Beffroi\Saml2\Model\Assertion\Attribute;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\Assertion\AssertionReader;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Dsig\Verified;
use Beffroi\Xml\Dsig\Verifier;
use function file_get_contents;
use function preg_match_all;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;
use function str_contains;

/**
 * M-1, M-4, M-5, section 6.1 steps 7 to 11: an assertion read strictly from the document of a verification, its
 * children in the order and with the cardinality of the schema, one of each part (SAML Core §2.3.3); the package reads
 * it through readVerified() only, from the Verified of a verification (section 6.1 step 5).
 */
final class AssertionReaderTest extends TestCase
{
    use AssertionFixtures;

    /**
     * Section 6.1 steps 7 to 11, section 5.3: every part of the assertion, as read.
     */
    #[Test]
    public function itReadsTheAssertion(): void
    {
        // Given
        $document = $this->document('behaviour/assertion-valid-accepted.xml');

        // When
        $assertion = AssertionReader::read($document, $this->context());

        // Then
        static::assertSame(
            [
                '_assertion',
                '2026-09-30T11:59:58Z',
                'https://idp.example.com/saml',
                '_7a2f4c1d9e',
                NameIdFormat::Persistent,
                'https://sp.example.com/saml/acs',
                '_request',
                [['https://sp.example.com/saml']],
                '_session',
                ['mail', 'eduPersonAffiliation'],
            ],
            [
                $assertion->id,
                $assertion->issueInstant->format('Y-m-d\TH:i:s\Z'),
                $assertion->issuer->entityId,
                $assertion->nameId->value,
                $assertion->nameId->format,
                $assertion->confirmation->recipient,
                $assertion->confirmation->inResponseTo,
                $assertion->conditions->audiences,
                $assertion->authnStatement->sessionIndex,
                array_map(
                    static fn (Attribute $attribute): ?string => $attribute->friendlyName,
                    $assertion->attributes,
                ),
            ],
        );
    }

    /**
     * §9.3 row 1, M-12, I-12: <saml:NameID>user@example.com<!---->.evil.com</saml:NameID> in the assertion; the NameID
     * is user@example.com.evil.com.
     */
    #[Test]
    public function itReadsTheCommentSplitNameIdWhole(): void
    {
        // Given
        $document = $this->document('behaviour/assertion-name-id-comment-split-accepted.xml');

        // When
        $assertion = AssertionReader::read($document, $this->context());

        // Then
        static::assertSame('user@example.com.evil.com', $assertion->nameId->value);
    }

    /**
     * M-5, SAML Core §2.3.3: the statements in any order among themselves, a ds:Signature after the Issuer, no
     * AttributeStatement: each is an assertion the schema allows.
     */
    #[Test]
    #[DataProvider('provideAssertionsTheSchemaAllows')]
    public function itReadsAnAssertionTheSchemaAllows(string $fixture, int $attributes): void
    {
        // Given
        $document = $this->document($fixture);

        // When
        $assertion = AssertionReader::read($document, $this->context());

        // Then
        static::assertCount($attributes, $assertion->attributes);
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideAssertionsTheSchemaAllows(): iterable
    {
        yield 'the attribute statement before the authentication statement' => [
            'behaviour/assertion-attribute-statement-first-accepted.xml',
            2,
        ];
        yield 'a ds:Signature after the Issuer, not read' => [
            'behaviour/assertion-signature-after-issuer-accepted.xml',
            2,
        ];
        yield 'no attribute statement' => ['behaviour/assertion-without-attribute-statement-accepted.xml', 0];
    }

    /**
     * §9.2 row 25, M-4, M-5: the root another element; children out of order, a ds:Signature before the Issuer, an
     * Advice after the statements, an unknown saml: element; a part missing or repeated.
     */
    #[Test]
    #[DataProvider('provideMalformedAssertions')]
    public function itRefusesAMalformedAssertion(string $fixture, string $message): void
    {
        // Given
        $document = $this->document($fixture);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        AssertionReader::read($document, $this->context());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideMalformedAssertions(): iterable
    {
        $order = 'The saml:Assertion holds a child out of the order of the schema, or one it does not allow there (M-5).';

        yield 'the root a samlp:Response' => [
            'hostile/assertion-root-not-an-assertion-refused.xml',
            'The root of the document is not a saml:Assertion (M-4).',
        ];
        yield 'the Conditions before the Subject' => [
            'hostile/assertion-conditions-before-subject-refused.xml',
            $order,
        ];
        yield 'a ds:Signature before the Issuer' => ['hostile/assertion-signature-before-issuer-refused.xml', $order];
        yield 'an Advice after the statements' => ['hostile/assertion-advice-after-statements-refused.xml', $order];
        yield 'an unknown saml: element' => ['hostile/assertion-unknown-saml-element-refused.xml', $order];
        yield 'two ds:Signature' => [
            'hostile/assertion-two-signatures-refused.xml',
            'The saml:Assertion holds more than one ds:Signature (M-4).',
        ];
        yield 'no Subject' => [
            'hostile/assertion-without-subject-refused.xml',
            'The saml:Assertion holds no saml:Subject (M-4).',
        ];
        yield 'two Subject' => [
            'hostile/assertion-two-subjects-refused.xml',
            'The saml:Assertion holds more than one saml:Subject (M-4).',
        ];
        yield 'no Conditions' => [
            'hostile/assertion-without-conditions-refused.xml',
            'The saml:Assertion holds no saml:Conditions (M-4).',
        ];
        yield 'no AuthnStatement' => [
            'hostile/assertion-without-authn-statement-refused.xml',
            'The saml:Assertion holds no saml:AuthnStatement (M-4).',
        ];
        yield 'two AuthnStatement' => [
            'hostile/assertion-two-authn-statements-refused.xml',
            'The saml:Assertion holds more than one saml:AuthnStatement (M-4).',
        ];
        yield 'two AttributeStatement' => [
            'hostile/assertion-two-attribute-statements-refused.xml',
            'The saml:Assertion holds more than one saml:AttributeStatement (M-4).',
        ];
    }

    /**
     * Section 8, section 6.1 step 10: saml:AuthzDecisionStatement, and a saml:Statement of any xsi:type.
     */
    #[Test]
    #[DataProvider('provideUnsupportedStatements')]
    public function itRefusesAnotherStatement(string $fixture): void
    {
        // Given
        $document = $this->document($fixture);
        $message = 'The assertion holds a statement other than AuthnStatement and AttributeStatement, which the package does not support (section 8).';

        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        AssertionReader::read($document, $this->context());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUnsupportedStatements(): iterable
    {
        yield 'saml:AuthzDecisionStatement' => ['hostile/assertion-authz-decision-statement-refused.xml'];
        yield 'a saml:Statement with an xsi:type' => ['hostile/assertion-statement-xsi-type-refused.xml'];
    }

    /**
     * M-1, section 6.1 step 5: the assertion whose own signature was verified is the root of Verified::$document.
     */
    #[Test]
    public function itReadsTheAssertionAVerificationOfItsOwnSignatureCovered(): void
    {
        // Given
        $document = MetadataFixtures::load('behaviour/response-signed-assertion-accepted.xml');
        $verified = new Verifier(SamlLoader::create())->verify(
            Children::one($document->root(), new Name(Saml::ASSERTION, 'Assertion')),
            MetadataFixtures::verificationKeys('idp'),
        );

        // When
        $assertion = AssertionReader::readVerified($verified, $this->context());

        // Then
        static::assertSame(['_assertion', '_7a2f4c1d9e'], [$assertion->id, $assertion->nameId->value]);
    }

    /**
     * M-1, section 6.1 step 5: an unsigned assertion is the one saml:Assertion child of the root of the response's
     * Verified::$document.
     */
    #[Test]
    public function itReadsTheAssertionTheSignatureOfTheResponseCovered(): void
    {
        // Given
        $verified = $this->verifiedRoot('behaviour/response-signed-response-accepted.xml');

        // When
        $assertion = AssertionReader::readVerified($verified, $this->context());

        // Then
        static::assertSame(['_assertion', '_7a2f4c1d9e'], [$assertion->id, $assertion->nameId->value]);
    }

    /**
     * M-1, M-4: a verification of anything but an assertion or a response, and a verified response without its one
     * assertion, yield no assertion.
     */
    #[Test]
    #[DataProvider('provideVerificationsOfNoAssertion')]
    public function itRefusesAVerificationThatCoveredNoAssertion(string $fixture, string $message): void
    {
        // Given
        $verified = $this->verifiedRoot($fixture);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);

        // When
        AssertionReader::readVerified($verified, $this->context());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideVerificationsOfNoAssertion(): iterable
    {
        yield 'a signed md:EntityDescriptor' => [
            'behaviour/metadata-signed-by-the-identity-provider.xml',
            'The root of the verified document is neither a saml:Assertion nor a samlp:Response (M-1).',
        ];
        yield 'a signed response without assertion' => [
            'behaviour/response-status-responder-authn-failed-signed-refused.xml',
            'The verified samlp:Response does not hold exactly one saml:Assertion (M-4).',
        ];
    }

    /**
     * M-1: every call the source of the package makes to the reader is readVerified(), which takes the Verified of a
     * verification: no path reads an assertion from a document that no signature covered.
     */
    #[Test]
    public function thePackageReadsAnAssertionThroughAVerificationOnly(): void
    {
        // When
        $calls = [];
        foreach ($this->sources() as $source) {
            preg_match_all('~AssertionReader::(\w+)~', $source, $matches);
            $calls = [...$calls, ...$matches[1]];
        }

        // Then
        static::assertSame([], array_values(array_diff($calls, ['readVerified'])));
    }

    /**
     * M-1, D-10: the package builds no Verified of its own; each one comes from Dsig's Verifier.
     */
    #[Test]
    public function thePackageBuildsNoVerifiedOfItsOwn(): void
    {
        // When
        $built = array_filter($this->sources(), static fn (string $source): bool => str_contains(
            $source,
            'new Verified(',
        ));

        // Then
        static::assertSame([], $built);
    }

    /**
     * The Verified of the signature of the root of $fixture, under the identity provider's test key.
     */
    private function verifiedRoot(string $fixture): Verified
    {
        $document = MetadataFixtures::load($fixture);

        return new Verifier(SamlLoader::create())->verify($document->root(), MetadataFixtures::verificationKeys('idp'));
    }

    /**
     * @return array<string, string> the source of every PHP file of src/ but the reader itself, by its path
     */
    private function sources(): array
    {
        $sources = [];
        /** @var SplFileInfo $file */
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator(__DIR__ . '/../../../../src')) as $file) {
            if ($file->getExtension() !== 'php' || $file->getFilename() === 'AssertionReader.php') {
                continue;
            }
            $sources[$file->getPathname()] = (string) file_get_contents($file->getPathname());
        }

        return $sources;
    }
}
