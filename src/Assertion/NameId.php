<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Assertion;

use Beffroi\Saml2\Model\Exception\InvalidNameId;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Uri;
use function mb_strlen;
use function preg_match;

/**
 * A saml:NameID (SAML Core §2.2.3) under the rule of its format (M-12), whoever builds it: the value as read with
 * Text::of() on the verified document, never trimmed, neither empty nor surrounded by whitespace, and without a format
 * character anywhere, a right-to-left override or a zero-width space, so that what is displayed is what is compared
 * (M-6); at most 256 characters for a persistent or a transient identifier (SAML Core §8.3.7, §8.3.8), 1024 for the
 * others (section 7);
 * an entity identifier is a URI without qualifier (SAML Core §8.3.6), an email address an addr-spec (SAML Core
 * §8.3.2), and the qualifiers of a persistent or a transient identifier name an entity, a URI (SAML Core §8.3.7).
 */
final readonly class NameId
{
    private const int MAX_CHARACTERS = 1024;

    private const int MAX_PAIRWISE_CHARACTERS = 256;

    /**
     * @throws InvalidNameId when the value or a qualifier breaks the rule of the format (M-12)
     */
    public function __construct(
        public string $value,
        public NameIdFormat $format = NameIdFormat::Unspecified,
        public ?string $nameQualifier = null,
        public ?string $spNameQualifier = null,
        public ?string $spProvidedId = null,
    ) {
        if ($value === '') {
            throw new InvalidNameId('The NameID is empty (M-12).');
        }
        $pairwise = $format === NameIdFormat::Persistent || $format === NameIdFormat::Transient;
        if ($pairwise && mb_strlen($value, 'UTF-8') > self::MAX_PAIRWISE_CHARACTERS) {
            throw new InvalidNameId('A persistent or transient NameID is longer than 256 characters (M-12).');
        }
        if (mb_strlen($value, 'UTF-8') > self::MAX_CHARACTERS) {
            throw new InvalidNameId('A NameID is longer than 1024 characters (M-12).');
        }
        // false, for bytes that are not UTF-8, refuses too
        if (preg_match('~^[\p{Z}\p{Cc}]|[\p{Z}\p{Cc}]\z~u', $value) !== 0) {
            throw new InvalidNameId('The NameID starts or ends with whitespace or a control character, or is not UTF-8 (M-12).');
        }
        if (preg_match('~\p{Cf}~u', $value) === 1) {
            throw new InvalidNameId('The NameID holds a format character, invisible or reordering (M-12).');
        }
        if ($format === NameIdFormat::Entity) {
            if ($nameQualifier !== null || $spNameQualifier !== null || $spProvidedId !== null) {
                throw new InvalidNameId('An entity NameID carries a NameQualifier, an SPNameQualifier or an SPProvidedID (M-12).');
            }
            if (! $this->isUri($value)) {
                throw new InvalidNameId('An entity NameID is not a URI (M-12).');
            }
        }
        // a local part and a domain around the last @, neither empty, no whitespace and no control character
        if (
            $format === NameIdFormat::EmailAddress
            && preg_match('~^[^\p{Z}\p{Cc}]+@[^\p{Z}\p{Cc}@]+\z~u', $value) !== 1
        ) {
            throw new InvalidNameId('An emailAddress NameID is not an addr-spec (M-12).');
        }
        if ($pairwise && $nameQualifier !== null && ! $this->isUri($nameQualifier)) {
            throw new InvalidNameId('The NameQualifier of a persistent or transient NameID is not a URI (M-12).');
        }
        if ($pairwise && $spNameQualifier !== null && ! $this->isUri($spNameQualifier)) {
            throw new InvalidNameId('The SPNameQualifier of a persistent or transient NameID is not a URI (M-12).');
        }
    }

    /**
     * Whether the value is a URI of M-6: absolute, without whitespace or control character, at most 1024 characters.
     */
    private function isUri(string $value): bool
    {
        try {
            Uri::read($value);
        } catch (MalformedMessage) {
            return false;
        }

        return true;
    }
}
