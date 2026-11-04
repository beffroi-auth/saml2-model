<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Protocol;

use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\InvalidNameId;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Uri;

/**
 * SAML Core §3.4.1.1
 */
final readonly class NameIdPolicy
{
    /**
     * Asks for the identifier encrypted, a format no NameID carries (SAML Core §3.4.1.1).
     */
    public const string ENCRYPTED = 'urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted';

    /**
     * @throws InvalidNameId
     * @throws MalformedMessage
     */
    public function __construct(
        public ?string $format = null,
        public ?string $spNameQualifier = null,
        public bool $allowCreate = false,
    ) {
        if ($format !== null && $format !== self::ENCRYPTED && ! NameIdFormat::tryFrom($format) instanceof NameIdFormat) {
            throw new InvalidNameId('The format of a samlp:NameIDPolicy is neither one of the eight of SAML Core nor encrypted (M-12).');
        }
        if ($spNameQualifier !== null) {
            Uri::read($spNameQualifier);
        }
    }
}
