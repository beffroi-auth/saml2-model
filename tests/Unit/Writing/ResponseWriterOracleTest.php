<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Writing;

use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Tests\Unit\Writing\ResponseWriterFixtures as Fixtures;
use Beffroi\Saml2\Model\Writing\ResponseWriter;
use Beffroi\Saml2\Model\Writing\SignedParts;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use function file_put_contents;
use function getenv;
use function is_dir;
use function mkdir;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RequiresEnvironmentVariable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * Section 9.1, M-15: the responses the writer signs with every scheme this build offers, the assertion alone and the
 * response over it, and a signed failure, written into the directory XMLSEC_ORACLE names for xmlsec1 to verify every
 * signature of each (tests/Fixture/oracle/README.md, the job Oracle of the CI). The files are the input of the oracle,
 * not fixtures: the test is skipped when the variable is not set.
 */
#[RequiresEnvironmentVariable('XMLSEC_ORACLE')]
final class ResponseWriterOracleTest extends TestCase
{
    /**
     * Section 9.1 rows "a response with its signed assertion" and "with the response signed too".
     */
    #[Test]
    #[DataProvider('provideSchemes')]
    public function itWritesAResponseForXmlsec1(SignatureAlgorithm $algorithm, SignedParts $parts): void
    {
        // Given
        $response = Fixtures::response(Fixtures::everything());

        // When
        $document = new ResponseWriter()->write($response, $this->signing($algorithm), $parts);

        // Then
        static::assertNotFalse($this->put(sprintf('response-%s-%s.xml', $algorithm->name, $parts->name), $document));
    }

    /**
     * @return iterable<string, array{SignatureAlgorithm, SignedParts}>
     */
    public static function provideSchemes(): iterable
    {
        foreach (SignatureAlgorithm::cases() as $algorithm) {
            if (! $algorithm->isAvailable()) {
                continue;
            }
            foreach (SignedParts::cases() as $parts) {
                yield sprintf('%s, %s', $algorithm->name, $parts->name) => [$algorithm, $parts];
            }
        }
    }

    /**
     * Section 9.1 row "a failure", signed.
     */
    #[Test]
    public function itWritesASignedFailureForXmlsec1(): void
    {
        // Given
        $failure = Fixtures::failure();

        // When
        $document = new ResponseWriter()->writeFailure($failure, $this->signing(SignatureAlgorithm::RsaSha256));

        // Then
        static::assertNotFalse($this->put('failure-RsaSha256.xml', $document));
    }

    /**
     * The identity provider's test key and its certificate, the KeyInfo hint of D-17.
     */
    private function signing(SignatureAlgorithm $algorithm): Signing
    {
        return new Signing(MetadataFixtures::signingKey('idp'), $algorithm, MetadataFixtures::certificatePem('idp'));
    }

    /**
     * @return int|false what file_put_contents() returns
     */
    private function put(string $name, Document $document): int|false
    {
        $directory = getenv('XMLSEC_ORACLE');
        static::assertIsString($directory);
        static::assertTrue(is_dir($directory) || mkdir($directory, 0o777, true));

        return file_put_contents($directory . '/' . $name, new Serializer()->serialize($document));
    }
}
