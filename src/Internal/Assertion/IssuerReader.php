<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Assertion;

use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\IssuerMismatch;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Saml2\Model\Value\Uri;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use function count;
use Dom\Element;
use function sprintf;

/**
 * The one reader of a saml:Issuer, a message's and an assertion's. Before any verification, the value that chooses the
 * peer (section 5.4, M-1). On what was verified, strictly (M-8, SAML Profiles §4.1.4.1, §4.1.4.2, §4.4.4.1,
 * §4.4.4.2): its Format omitted or entity, without the NameQualifier, SPNameQualifier and SPProvidedID an entity
 * identifier omits (SAML Core §8.3.6), its value read with Text::of() (I-12), a URI of M-6, and the entity ID of the
 * peer, compared exactly.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class IssuerReader
{
    /**
     * Section 5.4, M-1: the Issuer of $parent as it arrived, read before any verification to choose the peer and for
     * nothing else, a URI of M-6, or null when $parent has none. Two are refused rather than one of them picked.
     *
     * @param string $element the name of $parent in the schema, for the refusal
     *
     * @throws MalformedMessage when $parent holds more than one saml:Issuer (M-4), or the Issuer is not a URI (M-6)
     * @throws MixedContent when the Issuer holds an element
     */
    public static function unverified(Element $parent, string $element): ?string
    {
        $issuers = Children::named($parent, Schema::saml('Issuer'));
        if (count($issuers) > 1) {
            throw new MalformedMessage(sprintf('The %s holds more than one saml:Issuer (M-4).', $element));
        }

        return $issuers === [] ? null : Uri::read(Text::of($issuers[0]));
    }

    /**
     * @throws IssuerMismatch when the Format is not entity, a qualifier is present, or the value is not $peer (M-8)
     * @throws MalformedMessage when the value is not a URI of M-6
     * @throws MixedContent when the element holds an element
     */
    public static function read(Element $issuer, string $peer): Issuer
    {
        $format = Attributes::optional($issuer, new Name(null, 'Format'));
        if ($format !== null && $format !== NameIdFormat::Entity->value) {
            throw new IssuerMismatch('The Issuer has a Format other than entity (M-8).');
        }
        foreach (['NameQualifier', 'SPNameQualifier', 'SPProvidedID'] as $qualifier) {
            if (Attributes::optional($issuer, new Name(null, $qualifier)) !== null) {
                throw new IssuerMismatch('The Issuer carries a NameQualifier, an SPNameQualifier or an SPProvidedID, which an entity identifier omits (M-8).');
            }
        }
        $read = new Issuer(Text::of($issuer));
        if ($read->entityId !== $peer) {
            throw new IssuerMismatch('The Issuer is not the entity ID of the peer (M-8).');
        }

        return $read;
    }
}
