<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Assertion;

use Beffroi\Saml2\Model\Exception\InvalidNameId;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Characters;
use Beffroi\Saml2\Model\Value\Uri;
use function mb_strlen;
use function preg_match;

/**
 * A saml:NameID (SAML Core §2.2.3) under the rule of its format (M-12), whoever builds it: the value as read with
 * Text::of() on the verified document, never trimmed, neither empty nor surrounded by whitespace, and holding nowhere
 * a control character, a line or paragraph separator, or an invisible character of Value\Characters, a right-to-left
 * override or a zero-width space among them, so that what is displayed is what is compared (M-6); at most 256
 * characters for a persistent or a transient identifier (SAML Core §8.3.7, §8.3.8), 1024 for the others (section 7);
 * an entity identifier is a URI without qualifier (SAML Core §8.3.6), an email address an addr-spec (SAML Core
 * §8.3.2, RFC 2822 §3.4.1: a dot-atom or a quoted string, one @, then a dot-atom or a domain literal). Each qualifier,
 * whatever the format, is held to the rule of the value but for the empty string, since the identity the consumer
 * links is the value with its qualifiers (SAML Core §2.2.2), and those of a persistent or a transient identifier name
 * an entity, a URI (SAML Core §8.3.7). The value and the qualifiers hold only characters XML carries, a NUL above all,
 * which the DOM would cut a written identifier at (M-15).
 */
final readonly class NameId
{
    private const int MAX_CHARACTERS = 1024;

    private const int MAX_PAIRWISE_CHARACTERS = 256;

    /**
     * An addr-spec (RFC 2822 §3.4.1): a local part, a dot-atom or a quoted string, one @, and a domain, a dot-atom or a
     * domain literal; an atom holds any character but whitespace, a control, a format character and the specials of
     * RFC 2822 §3.2.4, non-ASCII letters included (RFC 6531 §3.3), so that a second unquoted @, a display name in angle
     * brackets, an empty label or a trailing dot is refused.
     */
    private const string ADDR_SPEC = '~^(?:[^\p{Z}\p{Cc}\p{Cf}()<>\[\]:;@\x{5C},."]+(?:\.[^\p{Z}\p{Cc}\p{Cf}()<>\[\]:;@\x{5C},."]+)*|"(?:[^"\x{5C}\p{Cc}]|\x{5C}[^\p{Cc}])*")@(?:[^\p{Z}\p{Cc}\p{Cf}()<>\[\]:;@\x{5C},."]+(?:\.[^\p{Z}\p{Cc}\p{Cf}()<>\[\]:;@\x{5C},."]+)*|\[[^\p{Z}\p{Cc}\[\]\x{5C}]+\])\z~u';

    /**
     * @throws InvalidNameId when the value or a qualifier breaks the rule of the format (M-12), or holds a character
     *                       XML does not carry (M-15)
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
        foreach ([$value, $nameQualifier ?? '', $spNameQualifier ?? '', $spProvidedId ?? ''] as $text) {
            if (! Characters::carriedByXml($text)) {
                throw new InvalidNameId('The NameID or a qualifier holds a character XML does not carry, a NUL among them (M-15).');
            }
        }
        if (preg_match('~[\p{Cc}\p{Zl}\p{Zp}]~u', $value) === 1) {
            throw new InvalidNameId('The NameID holds a control character or a line or paragraph separator (M-12).');
        }
        if (! Characters::visible($value)) {
            throw new InvalidNameId('The NameID holds a format or invisible character, invisible or reordering (M-12).');
        }
        if ($format === NameIdFormat::Entity) {
            if ($nameQualifier !== null || $spNameQualifier !== null || $spProvidedId !== null) {
                throw new InvalidNameId('An entity NameID carries a NameQualifier, an SPNameQualifier or an SPProvidedID (M-12).');
            }
            if (! $this->isUri($value)) {
                throw new InvalidNameId('An entity NameID is not a URI (M-12).');
            }
        }
        if ($format === NameIdFormat::EmailAddress && preg_match(self::ADDR_SPEC, $value) !== 1) {
            throw new InvalidNameId('An emailAddress NameID is not an addr-spec (M-12).');
        }
        if ($pairwise && $nameQualifier !== null && ! $this->isUri($nameQualifier)) {
            throw new InvalidNameId('The NameQualifier of a persistent or transient NameID is not a URI (M-12).');
        }
        if ($pairwise && $spNameQualifier !== null && ! $this->isUri($spNameQualifier)) {
            throw new InvalidNameId('The SPNameQualifier of a persistent or transient NameID is not a URI (M-12).');
        }
        foreach ([$nameQualifier, $spNameQualifier, $spProvidedId] as $qualifier) {
            if ($qualifier !== null && ! $this->isQualifier($qualifier)) {
                throw new InvalidNameId('A qualifier of the NameID is longer than 1024 characters, starts or ends with whitespace, or holds a control, separator, format or invisible character (M-12).');
            }
        }
    }

    /**
     * Whether a qualifier holds to the rule of the value, the empty string allowed: at most 1024 characters, no
     * whitespace or control character around it, no control character, line or paragraph separator, format or
     * invisible character anywhere (M-12).
     */
    private function isQualifier(string $qualifier): bool
    {
        return (
            mb_strlen($qualifier, 'UTF-8') <= self::MAX_CHARACTERS
            && preg_match('~^[\p{Z}\p{Cc}]|[\p{Z}\p{Cc}]\z|[\p{Cc}\p{Zl}\p{Zp}]~u', $qualifier) === 0
            && Characters::visible($qualifier)
        );
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
