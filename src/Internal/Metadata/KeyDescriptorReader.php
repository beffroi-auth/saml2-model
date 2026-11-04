<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Metadata;

use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\Particle;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Saml2\Model\Value\Counts;
use Beffroi\Saml2\Model\Value\Uri;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use function count;
use Dom\Element;
use function preg_replace;

/**
 * Section 6.5 step 5, SAML Metadata §2.4.1.1, E68
 *
 * @internal
 */
final readonly class KeyDescriptorReader
{
    /**
     * @param list<Element> $keyDescriptors
     *
     * @throws LimitExceeded
     * @throws MalformedMessage
     * @throws Unsupported
     *
     * @return array{list<string>, list<string>} the signing certificates, then the encryption ones
     */
    public static function read(array $keyDescriptors): array
    {
        $uses = [];
        $signing = 0;
        $encryption = 0;
        foreach ($keyDescriptors as $keyDescriptor) {
            $use = Attributes::optional($keyDescriptor, new Name(null, 'use'));
            [$forSigning, $forEncryption] = match ($use) {
                null => [1, 1],
                'signing' => [1, 0],
                'encryption' => [0, 1],
                default => throw new MalformedMessage('An md:KeyDescriptor use is not signing or encryption (M-5).'),
            };
            $signing += $forSigning;
            $encryption += $forEncryption;
            $uses[] = $use;
        }
        Counts::check(
            $signing,
            Counts::SIGNING_CERTIFICATES,
            'A role descriptor holds more than 16 md:KeyDescriptor for signing, the bound of section 7 (M-17).',
        );
        Counts::check(
            $encryption,
            Counts::ENCRYPTION_CERTIFICATES,
            'A role descriptor holds more than 16 md:KeyDescriptor for encryption, the bound of section 7 (M-17).',
        );
        $signingCertificates = [];
        $encryptionCertificates = [];
        foreach ($keyDescriptors as $index => $keyDescriptor) {
            $certificate = self::certificate($keyDescriptor);
            if ($uses[$index] !== 'encryption') {
                $signingCertificates[] = $certificate;
            }
            if ($uses[$index] !== 'signing') {
                $encryptionCertificates[] = $certificate;
            }
        }

        return [$signingCertificates, $encryptionCertificates];
    }

    /**
     * @throws MalformedMessage
     * @throws Unsupported
     */
    private static function certificate(Element $keyDescriptor): string
    {
        [$keyInfo, $encryptionMethods] = Schema::children($keyDescriptor, 'md:KeyDescriptor', [
            Particle::of(Schema::ds('KeyInfo'), 1, 1),
            Particle::of(Schema::md('EncryptionMethod'), 0, Particle::UNBOUNDED),
        ]);
        $data = Children::named($keyInfo[0], Schema::ds('X509Data'));
        if ($data === []) {
            if (Children::named($keyInfo[0], Schema::ds('KeyValue')) !== []) {
                throw new Unsupported('A ds:KeyInfo holds a ds:KeyValue and no certificate (section 8).');
            }
            throw new MalformedMessage('A ds:KeyInfo holds no ds:X509Data (section 6.5).');
        }
        if (count($data) > 1) {
            throw new MalformedMessage('A ds:KeyInfo holds more than one ds:X509Data (section 6.5).');
        }
        $certificates = Children::named($data[0], Schema::ds('X509Certificate'));
        if (count($certificates) !== 1) {
            throw new MalformedMessage('A ds:X509Data holds no ds:X509Certificate, or more than one (section 6.5).');
        }
        foreach ($encryptionMethods as $encryptionMethod) {
            Uri::read(Schema::attribute($encryptionMethod, 'md:EncryptionMethod', 'Algorithm'));
        }

        // A base64Binary allows XML whitespace between its characters: a certificate over several lines is one key.
        return (string) preg_replace('~[\x20\x09\x0A\x0D]+~', '', Text::of($certificates[0]));
    }
}
