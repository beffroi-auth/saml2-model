<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Writing;

use function array_map;
use Beffroi\Saml2\Model\Assertion\Assertion;
use Beffroi\Saml2\Model\Assertion\AttributeNameFormat;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Internal\Writing\AssertionBuilder;
use Beffroi\Saml2\Model\Internal\Writing\Tree;
use Beffroi\Saml2\Model\Tests\Unit\Writing\ResponseWriterFixtures as Fixtures;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\DocumentFactory;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use Dom\Element;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.6 steps 2 and 4, core.md section 6.5, SAML Core §2.3.3, SAML Profiles §4.1.4.2: the saml:Assertion of the
 * identity provider, built under a samlp:Response with one prefix per namespace, in the order of the schema.
 */
final class AssertionBuilderTest extends TestCase
{
    private const string PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';

    private const string ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';

    /**
     * Section 6.6 step 2, core.md section 6.5, SAML Core §2.3.3: the saml prefix declared on the assertion, which
     * introduces it, and on none of its descendants; its attributes, its Issuer without Format (M-8), and its children
     * in the order of the schema, no AttributeStatement without attributes.
     */
    #[Test]
    public function itBuildsTheAssertionInTheOrderOfTheSchema(): void
    {
        // Given
        $assertion = Fixtures::assertion();

        // When
        $element = $this->built($assertion);

        // Then
        $issuer = Children::one($element, self::saml('Issuer'));
        static::assertSame(
            [
                'saml:Assertion',
                ['saml' => self::ASSERTION],
                ['ID' => $assertion->id, 'Version' => '2.0', 'IssueInstant' => Fixtures::NOW],
                ['saml:Issuer', 'saml:Subject', 'saml:Conditions', 'saml:AuthnStatement'],
                [[], Fixtures::IDENTITY_PROVIDER],
                [],
            ],
            [
                $element->nodeName,
                Fixtures::declarations($element),
                Fixtures::attributes($element),
                Fixtures::names(Children::all($element)),
                [Fixtures::attributes($issuer), Text::of($issuer)],
                $this->declarationsBelow($element),
            ],
        );
    }

    /**
     * M-12, SAML Core §2.2.3, §2.4.1.2, SAML Profiles §4.1.4.2: the NameID with its Format and its three qualifiers,
     * then one bearer confirmation whose data carries its NotOnOrAfter, Recipient, InResponseTo and Address, and no
     * element.
     */
    #[Test]
    public function itBuildsTheSubjectWithEverythingItHolds(): void
    {
        // Given
        $assertion = Fixtures::everything();

        // When
        $subject = Children::one($this->built($assertion), self::saml('Subject'));

        // Then
        $nameId = Children::one($subject, self::saml('NameID'));
        $confirmation = Children::one($subject, self::saml('SubjectConfirmation'));
        $data = Children::one($confirmation, self::saml('SubjectConfirmationData'));
        static::assertSame(
            [
                ['saml:NameID', 'saml:SubjectConfirmation'],
                [
                    'Format' => NameIdFormat::Persistent->value,
                    'NameQualifier' => Fixtures::IDENTITY_PROVIDER,
                    'SPNameQualifier' => Fixtures::SERVICE_PROVIDER,
                    'SPProvidedID' => 'alice-at-sp',
                ],
                'b2c1a8f0-4e67-4a0b-9d1c-3f5e7a9b1c2d',
                ['Method' => 'urn:oasis:names:tc:SAML:2.0:cm:bearer'],
                ['saml:SubjectConfirmationData'],
                [
                    'NotOnOrAfter' => '2026-10-01T12:05:00Z',
                    'Recipient' => Fixtures::ASSERTION_CONSUMER,
                    'InResponseTo' => Fixtures::REQUEST,
                    'Address' => '192.0.2.10',
                ],
                [],
            ],
            [
                Fixtures::names(Children::all($subject)),
                Fixtures::attributes($nameId),
                Text::of($nameId),
                Fixtures::attributes($confirmation),
                Fixtures::names(Children::all($confirmation)),
                Fixtures::attributes($data),
                Children::all($data),
            ],
        );
    }

    /**
     * M-10, M-12, E60: an unspecified NameID is written with the Format of its 1.1 URI, never omitted; a confirmation
     * of an unsolicited response carries no InResponseTo, and no Address when it has none.
     */
    #[Test]
    public function itBuildsTheSubjectWithoutWhatItDoesNotHold(): void
    {
        // Given
        $assertion = Fixtures::assertion(inResponseTo: null);

        // When
        $subject = Children::one($this->built($assertion), self::saml('Subject'));

        // Then
        $confirmation = Children::one($subject, self::saml('SubjectConfirmation'));
        static::assertSame(
            [
                ['Format' => NameIdFormat::Unspecified->value],
                ['NotOnOrAfter' => '2026-10-01T12:05:00Z', 'Recipient' => Fixtures::ASSERTION_CONSUMER],
            ],
            [
                Fixtures::attributes(Children::one($subject, self::saml('NameID'))),
                Fixtures::attributes(Children::one($confirmation, self::saml('SubjectConfirmationData'))),
            ],
        );
    }

    /**
     * SAML Core §2.5.1, §2.5.1.4, §2.5.1.5: the Conditions with their window, each AudienceRestriction with its
     * audiences in order, then OneTimeUse.
     */
    #[Test]
    public function itBuildsTheConditionsWithEverythingTheyHold(): void
    {
        // Given
        $assertion = Fixtures::everything();

        // When
        $conditions = Children::one($this->built($assertion), self::saml('Conditions'));

        // Then
        $restrictions = Children::named($conditions, self::saml('AudienceRestriction'));
        static::assertSame(
            [
                ['NotBefore' => '2026-10-01T11:59:00Z', 'NotOnOrAfter' => '2026-10-01T12:10:00Z'],
                ['saml:AudienceRestriction', 'saml:AudienceRestriction', 'saml:OneTimeUse'],
                [
                    [Fixtures::SERVICE_PROVIDER, 'https://other.example.com/saml'],
                    [Fixtures::SERVICE_PROVIDER],
                ],
                [[], []],
            ],
            [
                Fixtures::attributes($conditions),
                Fixtures::names(Children::all($conditions)),
                array_map(
                    static fn (Element $restriction): array => Fixtures::texts(Children::named(
                        $restriction,
                        self::saml('Audience'),
                    )),
                    $restrictions,
                ),
                [
                    Children::all(Children::one($conditions, self::saml('OneTimeUse'))),
                    Fixtures::attributes(Children::one($conditions, self::saml('OneTimeUse'))),
                ],
            ],
        );
    }

    /**
     * SAML Core §2.5.1: Conditions without window and without OneTimeUse carry their restriction alone.
     */
    #[Test]
    public function itBuildsTheConditionsWithoutWhatTheyDoNotHold(): void
    {
        // Given
        $assertion = Fixtures::assertion();

        // When
        $conditions = Children::one($this->built($assertion), self::saml('Conditions'));

        // Then
        static::assertSame(
            [[], ['saml:AudienceRestriction'], [Fixtures::SERVICE_PROVIDER]],
            [
                Fixtures::attributes($conditions),
                Fixtures::names(Children::all($conditions)),
                Fixtures::texts(Children::named(
                    Children::one($conditions, self::saml('AudienceRestriction')),
                    self::saml('Audience'),
                )),
            ],
        );
    }

    /**
     * SAML Core §2.7.2, SAML Profiles §4.1.4.2: the authentication statement with its AuthnInstant, SessionIndex and
     * SessionNotOnOrAfter, and one AuthnContextClassRef in its AuthnContext.
     */
    #[Test]
    public function itBuildsTheAuthnStatementWithEverythingItHolds(): void
    {
        // Given
        $assertion = Fixtures::everything();

        // When
        $statement = Children::one($this->built($assertion), self::saml('AuthnStatement'));

        // Then
        $context = Children::one($statement, self::saml('AuthnContext'));
        static::assertSame(
            [
                [
                    'AuthnInstant' => '2026-10-01T11:59:30Z',
                    'SessionIndex' => '_session',
                    'SessionNotOnOrAfter' => '2026-10-01T20:00:00Z',
                ],
                ['saml:AuthnContext'],
                ['saml:AuthnContextClassRef'],
                Fixtures::CONTEXT_CLASS,
            ],
            [
                Fixtures::attributes($statement),
                Fixtures::names(Children::all($statement)),
                Fixtures::names(Children::all($context)),
                Text::of(Children::one($context, self::saml('AuthnContextClassRef'))),
            ],
        );
    }

    /**
     * SAML Core §2.7.2: an authentication statement without SessionIndex and SessionNotOnOrAfter carries its
     * AuthnInstant alone; that the identity provider always gives a SessionIndex is the writer's check.
     */
    #[Test]
    public function itBuildsTheAuthnStatementWithoutWhatItDoesNotHold(): void
    {
        // Given
        $assertion = Fixtures::assertion(sessionIndex: null);

        // When
        $statement = Children::one($this->built($assertion), self::saml('AuthnStatement'));

        // Then
        static::assertSame(['AuthnInstant' => '2026-10-01T11:59:30Z'], Fixtures::attributes($statement));
    }

    /**
     * SAML Core §2.7.3.1, section 12: one AttributeStatement after the AuthnStatement, each Attribute with its Name,
     * its NameFormat written whatever it is, its FriendlyName when given, and its values as text, without xsi:type
     * and without a namespace declaration.
     */
    #[Test]
    public function itBuildsTheAttributes(): void
    {
        // Given
        $assertion = Fixtures::everything();

        // When
        $element = $this->built($assertion);

        // Then
        $attributes = Children::named(
            Children::one($element, self::saml('AttributeStatement')),
            self::saml('Attribute'),
        );
        $values = Children::named($attributes[0], self::saml('AttributeValue'));
        static::assertSame(
            [
                ['saml:Issuer', 'saml:Subject', 'saml:Conditions', 'saml:AuthnStatement', 'saml:AttributeStatement'],
                [
                    [
                        'Name' => 'urn:oid:0.9.2342.19200300.100.1.3',
                        'NameFormat' => AttributeNameFormat::Uri->value,
                        'FriendlyName' => 'mail',
                    ],
                    ['Name' => 'groups', 'NameFormat' => AttributeNameFormat::Unspecified->value],
                    ['Name' => 'locked', 'NameFormat' => AttributeNameFormat::Basic->value],
                ],
                [['alice@example.com', 'alice@example.org'], ['admins'], []],
                [0, 0],
                [],
            ],
            [
                Fixtures::names(Children::all($element)),
                array_map(Fixtures::attributes(...), $attributes),
                array_map(
                    static fn (Element $attribute): array => Fixtures::texts(Children::named(
                        $attribute,
                        self::saml('AttributeValue'),
                    )),
                    $attributes,
                ),
                array_map(static fn (Element $value): int => $value->attributes->length, $values),
                $this->declarationsBelow($element),
            ],
        );
    }

    /**
     * The assertion built under the root of a samlp:Response.
     */
    private function built(Assertion $assertion): Element
    {
        $document = new DocumentFactory()->create(new Name(self::PROTOCOL, 'Response'), 'samlp');
        AssertionBuilder::append(Tree::of($document), $document->root(), $assertion);

        return Children::one($document->root(), self::saml('Assertion'));
    }

    /**
     * The namespace declarations of the descendants of $element.
     *
     * @return list<array<string, string>>
     */
    private function declarationsBelow(Element $element): array
    {
        $found = [];
        foreach (Children::all($element) as $child) {
            $declarations = Fixtures::declarations($child);
            if ($declarations !== []) {
                $found[] = $declarations;
            }
            $found = [...$found, ...$this->declarationsBelow($child)];
        }

        return $found;
    }

    private static function saml(string $local): Name
    {
        return new Name(self::ASSERTION, $local);
    }
}
