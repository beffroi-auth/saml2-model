<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Assertion;

use function array_fill;
use Beffroi\Saml2\Model\Assertion\Assertion;
use Beffroi\Saml2\Model\Assertion\Attribute;
use Beffroi\Saml2\Model\Assertion\AttributeNameFormat;
use Beffroi\Saml2\Model\Assertion\AuthnStatement;
use Beffroi\Saml2\Model\Assertion\Conditions;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Assertion\SubjectConfirmation;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3, M-4, M-6: an assertion, one of each of its parts, its ID an ID of M-6 (SAML Core §2.3.3).
 */
final class AssertionTest extends TestCase
{
    /**
     * Section 5.3: the eight fields, kept as given.
     */
    #[Test]
    public function itKeepsItsParts(): void
    {
        // Given
        $issueInstant = new DateTimeImmutable('2026-09-30T11:59:58Z');
        $issuer = new Issuer('https://idp.example.com/saml');
        $nameId = new NameId('jdoe');
        $confirmation = $this->confirmation();
        $conditions = $this->conditions();
        $authnStatement = $this->authnStatement();
        $attributes = [new Attribute('mail', AttributeNameFormat::Basic, null, ['jdoe@example.com'])];

        // When
        $assertion = new Assertion(
            '_assertion',
            $issueInstant,
            $issuer,
            $nameId,
            $confirmation,
            $conditions,
            $authnStatement,
            $attributes,
        );

        // Then
        static::assertSame(
            ['_assertion', $issueInstant, $issuer, $nameId, $confirmation, $conditions, $authnStatement, $attributes],
            [
                $assertion->id,
                $assertion->issueInstant,
                $assertion->issuer,
                $assertion->nameId,
                $assertion->confirmation,
                $assertion->conditions,
                $assertion->authnStatement,
                $assertion->attributes,
            ],
        );
    }

    /**
     * M-6, SAML Core §1.3.4: an ID that is not an NCName.
     */
    #[Test]
    public function itRefusesAnIdThatIsNotAnNcName(): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('An ID is not an NCName (M-6).');

        // When
        new Assertion(
            '42',
            new DateTimeImmutable('2026-09-30T11:59:58Z'),
            new Issuer('https://idp.example.com/saml'),
            new NameId('jdoe'),
            $this->confirmation(),
            $this->conditions(),
            $this->authnStatement(),
            [],
        );
    }

    private function confirmation(): SubjectConfirmation
    {
        return new SubjectConfirmation(
            'https://sp.example.com/saml/acs',
            new DateTimeImmutable('2026-09-30T12:04:58Z'),
            '_request',
            null,
        );
    }

    private function conditions(): Conditions
    {
        return new Conditions(null, null, [['https://sp.example.com/saml']], false);
    }

    private function authnStatement(): AuthnStatement
    {
        return new AuthnStatement(
            new DateTimeImmutable('2026-09-30T11:59:57Z'),
            null,
            null,
            'urn:oasis:names:tc:SAML:2.0:ac:classes:Password',
        );
    }

    /**
     * Section 7, M-15, M-17: 256 attributes, the bound the reader of the service provider applies.
     */
    #[Test]
    public function itHoldsTheAttributesOfTheirBound(): void
    {
        // Given
        $attributes = array_fill(0, 256, new Attribute('uid', AttributeNameFormat::Unspecified, null, ['jdoe']));

        // When
        $assertion = $this->assertion($attributes);

        // Then
        static::assertSame($attributes, $assertion->attributes);
    }

    /**
     * §9.2 row 36, M-15, M-17: 257 attributes, which the reader of the service provider would refuse, are refused
     * whoever builds the assertion, a writer included.
     */
    #[Test]
    public function itRefusesAttributesOverTheirBound(): void
    {
        // Given
        $attributes = array_fill(0, 257, new Attribute('uid', AttributeNameFormat::Unspecified, null, ['jdoe']));

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('The AttributeStatement holds more than 256 Attribute, the bound of section 7 (M-17).');

        // When
        $this->assertion($attributes);
    }

    /**
     * @param list<Attribute> $attributes
     */
    private function assertion(array $attributes): Assertion
    {
        return new Assertion(
            '_assertion',
            new DateTimeImmutable('2026-09-30T11:59:58Z'),
            new Issuer('https://idp.example.com/saml'),
            new NameId('jdoe'),
            $this->confirmation(),
            $this->conditions(),
            $this->authnStatement(),
            $attributes,
        );
    }
}
