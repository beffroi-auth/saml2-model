<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Assertion;

use function array_map;
use Beffroi\Saml2\Model\Assertion\Attribute;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\Assertion\AssertionReader;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * M-1, M-4, M-5, section 6.1 steps 7 to 11: an assertion read strictly from the document of a verification, its
 * children in the order and with the cardinality of the schema, one of each part (SAML Core §2.3.3).
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
}
