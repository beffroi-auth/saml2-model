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
 * @internal
 */
final readonly class IssuerReader
{
    /**
     * Section 5.4, M-1
     *
     * Read before any verification, to choose the peer and for nothing else.
     *
     * @param string $element the name of $parent in the schema, for the refusal
     *
     * @throws MalformedMessage
     * @throws MixedContent
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
     * @throws IssuerMismatch
     * @throws MalformedMessage
     * @throws MixedContent
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
