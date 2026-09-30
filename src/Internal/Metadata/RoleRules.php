<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Metadata;

use function array_map;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Value\Counts;
use Beffroi\Saml2\Model\Value\Uri;
use Beffroi\Xml\Dsig\Exception\InvalidKey;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use function count;

/**
 * The rules an identity provider and a service provider share, whoever builds them (section 5.3): an entity ID of
 * M-6, the counts of section 7, each certificate the base64 of an RSA key of at least 2048 bits (D-16), and the Dsig
 * keys of the signing ones (M-3).
 *
 * @internal
 */
final readonly class RoleRules
{
    /**
     * @param list<string> $signingCertificates
     * @param list<string> $encryptionCertificates
     * @param list<Endpoint> $singleLogoutServices
     * @param list<NameIdFormat> $nameIdFormats
     *
     * @throws MalformedMessage when the entity ID is not a URI of M-6
     * @throws LimitExceeded when a list is over its bound of section 7 (M-17)
     * @throws InvalidKey when a certificate is not the base64 of an RSA key of at least 2048 bits (D-16)
     */
    public static function check(
        string $entityId,
        array $signingCertificates,
        array $encryptionCertificates,
        array $singleLogoutServices,
        array $nameIdFormats,
    ): void {
        Uri::read($entityId);
        Counts::check(
            count($signingCertificates),
            Counts::SIGNING_CERTIFICATES,
            'A role holds more than 16 signing certificates, the bound of section 7 (M-17).',
        );
        Counts::check(
            count($encryptionCertificates),
            Counts::ENCRYPTION_CERTIFICATES,
            'A role holds more than 16 encryption certificates, the bound of section 7 (M-17).',
        );
        self::checkEndpoints($singleLogoutServices, 'single logout services');
        Counts::check(
            count($nameIdFormats),
            Counts::NAME_ID_FORMATS,
            'A role holds more than 16 NameID formats, the bound of section 7 (M-17).',
        );
        foreach ([...$signingCertificates, ...$encryptionCertificates] as $certificate) {
            VerificationKey::fromCertificateBase64($certificate);
        }
    }

    /**
     * @param list<Endpoint> $endpoints
     *
     * @throws LimitExceeded when there are more than 64 (section 7)
     */
    public static function checkEndpoints(array $endpoints, string $kind): void
    {
        Counts::check(
            count($endpoints),
            Counts::ENDPOINTS,
            'A role holds more than 64 ' . $kind . ', the bound of section 7 (M-17).',
        );
    }

    /**
     * The Dsig keys of the signing certificates, or null when there is none: VerificationKeys refuses an empty list
     * as a programming error, while a peer's metadata is input (section 5.3).
     *
     * @param list<string> $signingCertificates each already checked by check()
     *
     * @throws InvalidKey never for a certificate check() accepted
     */
    public static function verificationKeys(array $signingCertificates): ?VerificationKeys
    {
        if ($signingCertificates === []) {
            return null;
        }

        return new VerificationKeys(array_map(VerificationKey::fromCertificateBase64(...), $signingCertificates));
    }
}
