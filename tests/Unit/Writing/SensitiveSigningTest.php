<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Writing;

use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Tests\Unit\Validation\AuthnRequestFixtures;
use Beffroi\Saml2\Model\Tests\Unit\Validation\LogoutFixtures;
use Beffroi\Saml2\Model\Tests\Unit\Writing\ResponseWriterFixtures as Fixtures;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Saml2\Model\Writing\AuthnRequestWriter;
use Beffroi\Saml2\Model\Writing\LogoutRequestWriter;
use Beffroi\Saml2\Model\Writing\LogoutResponseWriter;
use Beffroi\Saml2\Model\Writing\MetadataWriter;
use Beffroi\Saml2\Model\Writing\ResponseWriter;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Dsig\Exception\InvalidKey;
use DateTimeImmutable;
use function file_get_contents;
use function ini_get;
use InvalidArgumentException;
use function iterator_to_array;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use SensitiveParameterValue;
use function str_starts_with;

/**
 * Section 5.7, M-16, D-13: the Signing a writer is given is a sensitive parameter of every method that takes it, so
 * that an exception thrown while signing, a private key handed in the place of the certificate among them (D-17),
 * carries no Signing in the arguments of its trace, which an error handler logs when zend.exception_ignore_args is Off,
 * as .ci-tools/phpunit.xml.dist sets it.
 */
final class SensitiveSigningTest extends TestCase
{
    /**
     * Section 5.7, M-16: every frame of a writer holds the Signing masked, never the object.
     */
    #[Test]
    #[TestWith(['ResponseWriter::write()'])]
    #[TestWith(['ResponseWriter::writeFailure()'])]
    #[TestWith(['LogoutRequestWriter::write()'])]
    #[TestWith(['LogoutResponseWriter::write()'])]
    #[TestWith(['AuthnRequestWriter::write()'])]
    #[TestWith(['MetadataWriter::write()'])]
    public function itMasksTheSigningInTheTraceOfWhatItThrows(string $writer): void
    {
        // Given
        static::assertSame('0', ini_get('zend.exception_ignore_args'));
        $privateKey = (string) file_get_contents(__DIR__ . '/../../Fixture/keys/idp-signing-key.pem');
        $signing = new Signing(MetadataFixtures::signingKey('idp'), certificatePem: $privateKey);

        // When
        try {
            $this->write($writer, $signing);
            static::fail('The writer signed with a private key as its certificate.');
        } catch (InvalidKey $refusal) {
            $trace = $refusal->getTrace();
        }

        // Then
        $masked = 0;
        foreach ($trace as $frame) {
            if (! str_starts_with($frame['class'] ?? '', 'Beffroi\\Saml2\\Model\\Writing\\')) {
                continue;
            }
            foreach ($frame['args'] ?? [] as $argument) {
                static::assertNotInstanceOf(Signing::class, $argument);
                $masked += $argument instanceof SensitiveParameterValue ? 1 : 0;
            }
        }
        static::assertGreaterThan(0, $masked);
    }

    private function write(string $writer, Signing $signing): Document
    {
        return match ($writer) {
            'ResponseWriter::write()' => new ResponseWriter()->write(Fixtures::response(), $signing),
            'ResponseWriter::writeFailure()' => new ResponseWriter()->writeFailure(Fixtures::failure(), $signing),
            'LogoutRequestWriter::write()' => new LogoutRequestWriter()->write(LogoutFixtures::request(), $signing),
            'LogoutResponseWriter::write()' => new LogoutResponseWriter()->write(LogoutFixtures::response(), $signing),
            'AuthnRequestWriter::write()' => new AuthnRequestWriter()->write(
                new AuthnRequest(
                    SamlId::generate(),
                    new DateTimeImmutable(AuthnRequestFixtures::NOW),
                    new Issuer(AuthnRequestFixtures::SERVICE_PROVIDER),
                    AuthnRequestFixtures::SINGLE_SIGN_ON,
                ),
                $signing,
            ),
            'MetadataWriter::write()' => new MetadataWriter()->write($this->descriptor(), $signing),
            default => throw new InvalidArgumentException('No such writer.'),
        };
    }

    private function descriptor(): EntityDescriptor
    {
        return iterator_to_array(MetadataWriterTest::provideDescriptors())['an identity provider'][0];
    }
}
