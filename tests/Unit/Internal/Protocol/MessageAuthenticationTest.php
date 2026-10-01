<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Protocol;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Internal\Protocol\MessageAuthentication;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Dsig\Exception\DigestMismatch;
use Beffroi\Xml\Dsig\Exception\SignatureMismatch;
use Beffroi\Xml\Dsig\VerificationKeys;
use Dom\Element;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function array_map;

/**
 * Section 5.6, M-2: the rule of a received protocol message, what authenticated it and the document to read it from;
 * M-1, M-3, M-4 on the way.
 */
final class MessageAuthenticationTest extends TestCase
{
    private const string SIGNED = 'behaviour/authentication-logout-request-signed.xml';

    private const string UNSIGNED = 'behaviour/authentication-logout-request-unsigned.xml';

    /**
     * M-2, M-1, D-10: a ds:Signature child of the root, verified under the keys of the peer's metadata, the message
     * read from Verified::$document, the signed element without its Signature, whether the signature is required or
     * optional.
     */
    #[Test]
    #[DataProvider('provideSignatureRequiredOrNot')]
    public function itVerifiesTheSignatureOfTheMessage(string $rule): void
    {
        // Given
        $received = MetadataFixtures::load(self::SIGNED);

        // When
        $authentication = $this->authenticate($rule, $received, MetadataFixtures::verificationKeys('idp'));

        // Then
        static::assertSame(
            [Authentication::XmlSignature, false, ['Issuer', 'NameID', 'SessionIndex']],
            [
                $authentication->authentication,
                $authentication->document === $received,
                array_map(
                    static fn (Element $child): string => $child->localName,
                    Children::all($authentication->document->root()),
                ),
            ],
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSignatureRequiredOrNot(): iterable
    {
        yield 'required' => ['required'];
        yield 'optional' => ['optional'];
    }

    /**
     * M-2, Profiles §4.1.6: a message whose signature is optional and absent was authenticated by nothing, and is read
     * as received, whether the peer has signing keys or not.
     */
    #[Test]
    #[DataProvider('provideKeysOrNone')]
    public function itAcceptsAnUnsignedMessageWhenTheSignatureIsOptional(?string $key): void
    {
        // Given
        $received = MetadataFixtures::load(self::UNSIGNED);

        // When
        $authentication = MessageAuthentication::signatureOptional(
            $received,
            $key === null ? null : MetadataFixtures::verificationKeys('idp'),
            SamlLoader::create(),
        );

        // Then
        static::assertSame([Authentication::None, $received], [
            $authentication->authentication,
            $authentication->document,
        ]);
    }

    /**
     * @return iterable<string, array{?string}>
     */
    public static function provideKeysOrNone(): iterable
    {
        yield 'the peer has signing keys' => ['idp'];
        yield 'the peer has none' => [null];
    }

    /**
     * M-2, Profiles §4.4.4.1: a message the profile requires signed and that carries no ds:Signature as a direct child
     * of its root is refused, one moved into samlp:Extensions included, which nothing searches (M-4).
     */
    #[Test]
    #[DataProvider('provideUnsignedMessages')]
    public function itRefusesAMessageWithoutTheSignatureTheProfileRequires(string $path): void
    {
        // Given
        $received = MetadataFixtures::load($path);

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs('The message carries no ds:Signature, which the profile requires (M-2).');

        // When
        MessageAuthentication::signatureRequired(
            $received,
            MetadataFixtures::verificationKeys('idp'),
            SamlLoader::create(),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUnsignedMessages(): iterable
    {
        yield 'no signature' => [self::UNSIGNED];
        yield 'the signature inside samlp:Extensions' => [
            'hostile/authentication-logout-request-signature-in-extensions-refused.xml',
        ];
    }

    /**
     * M-3, section 5.3: a peer whose metadata holds no signing key cannot have signed the message, whether it carries a
     * signature, required or optional, or carries none where one is required.
     */
    #[Test]
    #[DataProvider('provideMessagesWithoutKeys')]
    public function itRefusesWhenThePeerHasNoSigningKey(string $path, string $rule): void
    {
        // Given
        $received = MetadataFixtures::load($path);

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs('The metadata of the peer holds no signing key to verify the message with (M-3).');

        // When
        $this->authenticate($rule, $received, null);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideMessagesWithoutKeys(): iterable
    {
        yield 'signed, the signature required' => [self::SIGNED, 'required'];
        yield 'signed, the signature optional' => [self::SIGNED, 'optional'];
        yield 'unsigned, the signature required' => [self::UNSIGNED, 'required'];
    }

    /**
     * M-2, section 5.8: a signature that does not verify refuses the message with Dsig's refusal, as it is, whether it
     * is required or optional.
     *
     * @param class-string<RefusedXml> $exception
     */
    #[Test]
    #[DataProvider('provideSignaturesThatFail')]
    public function itLetsDsigRefusalsThrough(
        string $path,
        string $key,
        string $rule,
        string $exception,
        string $message,
    ): void {
        // Given
        $received = MetadataFixtures::load($path);
        $keys = MetadataFixtures::verificationKeys($key === 'sp' ? 'sp' : 'idp');

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        $this->authenticate($rule, $received, $keys);
    }

    /**
     * @return iterable<string, array{string, string, string, class-string<RefusedXml>, string}>
     */
    public static function provideSignaturesThatFail(): iterable
    {
        foreach (['required', 'optional'] as $rule) {
            yield 'a key not of the peer, the signature ' . $rule => [
                self::SIGNED,
                'sp',
                $rule,
                SignatureMismatch::class,
                'No trusted key verifies the signature over SignedInfo (D-7, D-8).',
            ];
            yield 'altered after signing, the signature ' . $rule => [
                'hostile/authentication-logout-request-signed-then-altered-refused.xml',
                'idp',
                $rule,
                DigestMismatch::class,
                'The claimed element is not what was signed (D-8).',
            ];
        }
    }

    /**
     * M-5: a second ds:Signature as a direct child of the root, before any is verified.
     */
    #[Test]
    #[DataProvider('provideSignatureRequiredOrNot')]
    public function itRefusesTwoSignatures(string $rule): void
    {
        // Given
        $received = MetadataFixtures::load('hostile/authentication-logout-request-two-signatures-refused.xml');

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The message holds more than one ds:Signature as a direct child of its root (M-5).');

        // When
        $this->authenticate($rule, $received, MetadataFixtures::verificationKeys('idp'));
    }

    /**
     * Section 6.8, SAML Bindings §3.4.4.1: a message the binding authenticated carries no ds:Signature, and is read as
     * received.
     */
    #[Test]
    public function itAcceptsAMessageTheBindingAuthenticated(): void
    {
        // Given
        $received = MetadataFixtures::load(self::UNSIGNED);

        // When
        $authentication = MessageAuthentication::byBinding($received, MetadataFixtures::verificationKeys('idp'));

        // Then
        static::assertSame([Authentication::Binding, $received], [
            $authentication->authentication,
            $authentication->document,
        ]);
    }

    /**
     * Section 5.6, SAML Bindings §3.4.4.1: the HTTP-Redirect encoding removes the ds:Signature of the message, one that
     * carries it did not come that way.
     */
    #[Test]
    public function itRefusesASignatureInAMessageTheBindingAuthenticated(): void
    {
        // Given
        $received = MetadataFixtures::load(self::SIGNED);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The message carries a ds:Signature, which the HTTP-Redirect encoding removes (SAML Bindings §3.4.4.1).');

        // When
        MessageAuthentication::byBinding($received, MetadataFixtures::verificationKeys('idp'));
    }

    /**
     * Section 6.8, M-3: the binding verifies the query string with the keys of the peer's metadata; a peer whose
     * metadata holds none cannot have been verified so, and is refused as validate() refuses it.
     */
    #[Test]
    public function itRefusesAMessageTheBindingAuthenticatedFromAPeerWithoutKey(): void
    {
        // Given
        $received = MetadataFixtures::load(self::UNSIGNED);

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs('The metadata of the peer holds no signing key to verify the message with (M-3).');

        // When
        MessageAuthentication::byBinding($received, null);
    }

    private function authenticate(
        string $rule,
        Document $received,
        ?VerificationKeys $keys,
    ): MessageAuthentication {
        return $rule === 'required'
            ? MessageAuthentication::signatureRequired($received, $keys, SamlLoader::create())
            : MessageAuthentication::signatureOptional($received, $keys, SamlLoader::create());
    }
}
