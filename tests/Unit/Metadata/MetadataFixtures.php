<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Metadata;

use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Dsig\PrivateKey;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use function file_get_contents;
use function preg_replace;

/**
 * The fixtures the metadata tests share: the test keys of tests/Fixture/keys/ (section 9.1) and the files of
 * tests/Fixture/, read as bytes and loaded with the one loader (M-14).
 */
final class MetadataFixtures
{
    /**
     * The base64 of the certificate of a test key, on one line, as an X509Certificate carries it.
     *
     * @param 'idp'|'sp'|'rsa-1024' $key
     */
    public static function certificate(string $key): string
    {
        return (string) preg_replace('~-----[A-Z ]+-----|\s+~', '', self::certificatePem($key));
    }

    /**
     * @param 'idp'|'sp'|'rsa-1024' $key
     */
    public static function certificatePem(string $key): string
    {
        return self::bytes(match ($key) {
            'idp' => 'keys/idp-signing-certificate.pem',
            'sp' => 'keys/sp-signing-certificate.pem',
            'rsa-1024' => 'hostile/metadata-rsa-1024-certificate-refused.pem',
        });
    }

    /**
     * @param 'idp'|'sp' $key
     */
    public static function signingKey(string $key): PrivateKey
    {
        return PrivateKey::fromPem(self::bytes('keys/' . $key . '-signing-key.pem'));
    }

    /**
     * @param 'idp'|'sp' $key
     */
    public static function verificationKeys(string $key): VerificationKeys
    {
        return new VerificationKeys([VerificationKey::fromCertificatePem(self::certificatePem($key))]);
    }

    /**
     * The bytes of a file of tests/Fixture/, as they are on disk.
     */
    public static function bytes(string $path): string
    {
        return (string) file_get_contents(__DIR__ . '/../../Fixture/' . $path);
    }

    /**
     * A file of tests/Fixture/ loaded with SamlLoader::create() (M-14).
     */
    public static function load(string $path): Document
    {
        return SamlLoader::create()->load(self::bytes($path));
    }
}
