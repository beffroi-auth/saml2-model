<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Assertion;

use Beffroi\Saml2\Model\Internal\Assertion\AssertionContext;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\FrozenClock;
use Beffroi\Saml2\Model\Validation\TimeBounds;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use DateTimeImmutable;
use Dom\Element;
use function file_get_contents;
use function mb_strlen;
use function sprintf;
use function str_contains;

/**
 * The assertion fixtures of tests/Fixture/, one case per file, loaded with SamlLoader::create() as the verified
 * document would be (section 9.7), and what the rules of an assertion are checked against: the frozen clock at
 * 2026-09-30T12:00:00Z, the bounds of section 7 by default, the identity provider https://idp.example.com/saml, our
 * entity ID https://sp.example.com/saml, the URL of arrival https://sp.example.com/saml/acs, and the request _request.
 */
trait AssertionFixtures
{
    private function document(string $fixture): Document
    {
        $bytes = file_get_contents(__DIR__ . '/../../../Fixture/' . $fixture);
        static::assertIsString($bytes);

        return SamlLoader::create()->load($bytes);
    }

    /**
     * The one child of the root of $document named saml:$local.
     */
    private function child(Document $document, string $local): Element
    {
        return Children::one($document->root(), new Name(Saml::ASSERTION, $local));
    }

    /**
     * @param ?string $inResponseTo the request the response answers, null for an unsolicited one (M-10)
     */
    private function context(?string $inResponseTo = '_request'): AssertionContext
    {
        return new AssertionContext(
            new FrozenClock(new DateTimeImmutable('2026-09-30T12:00:00Z'))->now(),
            new TimeBounds(),
            'https://idp.example.com/saml',
            'https://sp.example.com/saml',
            'https://sp.example.com/saml/acs',
            $inResponseTo,
        );
    }

    /**
     * M-16: the message of a refusal, which expectExceptionMessageIs() pins, carries no attribute value and no text of
     * the fixture: no ID, no NameID, no entity ID, no URL, no attribute value. Values shorter than three characters
     * are not compared, since any sentence holds them.
     */
    private static function assertCarriesNothingOf(string $message, Document $document): void
    {
        foreach (self::values($document->root()) as $value) {
            static::assertFalse(
                mb_strlen($value) >= 3 && str_contains($message, $value),
                sprintf('The message carries a value of the input: %s', $value),
            );
        }
    }

    /**
     * @return list<string> the attribute values of $element and of its descendants, and the text of those without an
     *                      element child
     */
    private static function values(Element $element): array
    {
        $values = [];
        foreach ($element->attributes as $attribute) {
            $values[] = $attribute->value;
        }
        $children = Children::all($element);
        if ($children === []) {
            $values[] = Text::of($element);
        }
        foreach ($children as $child) {
            $values = [...$values, ...self::values($child)];
        }

        return $values;
    }
}
