<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Protocol;

use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\InvalidNameId;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Uri;

/**
 * The samlp:NameIDPolicy of an AuthnRequest (SAML Core §3.4.1.1, section 5.3): the format asked for, the URI of one of
 * the eight formats of SAML Core §8.3 or the encrypted format of §3.4.1.1, null when the attribute is absent; the
 * SPNameQualifier, the entity ID of the service provider or affiliation the identifier is asked in, a URI of M-6;
 * AllowCreate, false when absent (SAML Core §3.4.1.1). Returned, never enforced: whether the identity provider can
 * satisfy it is beffroi/saml's, which answers with a failure status (section 6.2 step 5, Profiles §4.1.4.1).
 */
final readonly class NameIdPolicy
{
    /**
     * The format of SAML Core §3.4.1.1 that asks for the identifier encrypted, which no NameID carries.
     */
    public const string ENCRYPTED = 'urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted';

    /**
     * @throws InvalidNameId when the format is neither one of SAML Core §8.3 nor encrypted (M-12)
     * @throws MalformedMessage when the SPNameQualifier is not a URI of M-6
     */
    public function __construct(
        public ?string $format = null,
        public ?string $spNameQualifier = null,
        public bool $allowCreate = false,
    ) {
        if (
            $format !== null
            && $format !== self::ENCRYPTED
            && ! NameIdFormat::tryFrom($format) instanceof NameIdFormat
        ) {
            throw new InvalidNameId('The format of a samlp:NameIDPolicy is neither one of the eight of SAML Core nor encrypted (M-12).');
        }
        if ($spNameQualifier !== null) {
            Uri::read($spNameQualifier);
        }
    }
}
