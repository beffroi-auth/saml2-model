<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Assertion;

use Beffroi\Saml2\Model\Exception\InvalidNameId;

/**
 * The eight name identifier formats of SAML Core §8.3, a closed vocabulary: fromUri() refuses every other URI (M-5,
 * M-12). The unspecified format is the 1.1 URI, as erratum E60 corrects SAML Core §2.2.2.
 */
enum NameIdFormat: string
{
    case Unspecified = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
    case EmailAddress = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
    case X509SubjectName = 'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName';
    case WindowsDomainQualifiedName = 'urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName';
    case Kerberos = 'urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos';
    case Entity = 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity';
    case Persistent = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
    case Transient = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';

    /**
     * The Format of a saml:NameID, null when the attribute is absent, which means Unspecified (SAML Core §2.2.2, E60).
     * Only for a NameID: an Issuer without Format is of format Entity (SAML Core §2.2.5).
     *
     * @throws InvalidNameId for every other URI (M-12)
     */
    public static function fromUri(?string $uri): self
    {
        if ($uri === null) {
            return self::Unspecified;
        }

        return (
            self::tryFrom($uri) ?? throw new InvalidNameId('The NameID format is not one of the eight of SAML Core (M-12).')
        );
    }
}
