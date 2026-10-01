<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Assertion;

use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * Section 5.3, M-6, M-8: the Issuer is an entity ID, a URI of at most 1024 characters (SAML Core §2.2.5, §8.3.6).
 */
final class IssuerTest extends TestCase
{
    /**
     * M-6, M-8: the entity ID, kept as read, never normalised.
     */
    #[Test]
    #[DataProvider('provideEntityIds')]
    public function itKeepsItsEntityId(string $entityId): void
    {
        // When
        $issuer = new Issuer($entityId);

        // Then
        static::assertSame($entityId, $issuer->entityId);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideEntityIds(): iterable
    {
        yield 'a URL' => ['https://idp.example.com/saml/metadata'];
        yield 'a URN' => ['urn:example:idp'];
        yield 'a trailing slash' => ['https://idp.example.com/'];
        yield 'an entity ID of exactly 1024 characters' => ['https://idp.example.com/' . str_repeat('a', 1000)];
    }

    /**
     * §9.2 row 26, SAML Core §8.3.6: an entity ID of 1025 characters; the message carries nothing of it (M-16).
     */
    #[Test]
    public function itRefusesAnEntityIdOf1025Characters(): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A URI is longer than 1024 characters (M-6).');

        // When
        new Issuer('https://idp.example.com/' . str_repeat('a', 1001));
    }

    /**
     * M-6, SAML Core §1.3.2: an entity ID that is not absolute.
     */
    #[Test]
    #[DataProvider('provideRelativeEntityIds')]
    public function itRefusesAnEntityIdThatIsNotAbsolute(string $entityId): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A URI is not absolute (M-6).');

        // When
        new Issuer($entityId);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRelativeEntityIds(): iterable
    {
        yield 'a relative path' => ['relative/path'];
        yield 'a host name' => ['idp.example.com'];
        yield 'empty' => [''];
    }

    /**
     * M-6: whitespace around an entity ID, never trimmed.
     */
    #[Test]
    #[DataProvider('provideSurroundedEntityIds')]
    public function itRefusesWhitespaceAroundAnEntityId(string $entityId): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A URI holds whitespace, a control, format or invisible character, or bytes that are not UTF-8 (M-6).');

        // When
        new Issuer($entityId);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSurroundedEntityIds(): iterable
    {
        yield 'a leading space' => [' https://idp.example.com/saml'];
        yield 'a trailing newline' => ["https://idp.example.com/saml\n"];
    }
}
