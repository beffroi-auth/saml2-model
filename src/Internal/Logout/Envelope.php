<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Logout;

use function array_slice;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Exception\DestinationMismatch;
use Beffroi\Saml2\Model\Exception\IssuerMismatch;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use Beffroi\Saml2\Model\Internal\Assertion\IssuerReader;
use Beffroi\Saml2\Model\Internal\Metadata\Particle;
use Beffroi\Saml2\Model\Internal\Metadata\Schema;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\Value\Time;
use Beffroi\Saml2\Model\Value\Uri;
use Beffroi\Saml2\Model\Value\Version;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use function count;
use function in_array;
use DateTimeImmutable;
use Dom\Element;
use function sprintf;

/**
 * What a samlp:LogoutRequest and a samlp:LogoutResponse share, read strictly (sections 6.3 and 6.4): the root and its
 * Issuer before any verification (M-1); the children the schema puts before the body of each, saml:Issuer, required by
 * the profile, ds:Signature and samlp:Extensions, never read (M-5); the header, read from what was authenticated,
 * Issuer, Version, ID, IssueInstant and Destination (M-6, M-7, M-8). Every refusal names the rule, never the input
 * (M-16).
 *
 * @internal
 */
final readonly class Envelope
{
    /**
     * The name of an element of the protocol namespace.
     */
    public static function samlp(string $local): Name
    {
        return new Name(Saml::PROTOCOL, $local);
    }

    /**
     * Section 5.4: the root of a received message, checked to be samlp:$local.
     *
     * @throws MalformedMessage when it is another element
     */
    public static function root(Document $document, string $local): Element
    {
        $root = $document->root();
        if (! self::samlp($local)->matches($root)) {
            throw new MalformedMessage(sprintf('The root of the message is not a samlp:%s (section 5.4).', $local));
        }

        return $root;
    }

    /**
     * Section 5.4, M-1: the Issuer of a received message, read before any verification to choose the peer, a URI of
     * M-6, or null when the message has none.
     *
     * @throws MalformedMessage when the root holds more than one saml:Issuer (M-5), or the Issuer is not a URI (M-6)
     * @throws MixedContent when the Issuer holds an element
     */
    public static function unverifiedIssuer(Element $root): ?string
    {
        $issuers = Children::named($root, Schema::saml('Issuer'));
        if (count($issuers) > 1) {
            throw new MalformedMessage('The message holds more than one saml:Issuer (M-5).');
        }

        return $issuers === [] ? null : Uri::read(Text::of($issuers[0]));
    }

    /**
     * Sections 6.3 and 6.4, before any signature: the children of $root in the order of the schema, saml:Issuer,
     * ds:Signature and samlp:Extensions, then those of $body; the saml:Issuer the schema leaves optional is required by
     * the profile.
     *
     * @param string $element the name of the root in the schema, for the refusals
     * @param string $profile the section of SAML Profiles that requires the Issuer, for the refusal
     * @param list<Particle> $body the places of the schema after samlp:Extensions
     *
     * @throws MalformedMessage when the children are not a sequence of the schema (M-5), or the Issuer is missing
     *
     * @return list<list<Element>> the children of each place of $body, in its order
     */
    public static function children(Element $root, string $element, string $profile, array $body): array
    {
        $children = Schema::children($root, $element, [
            Particle::of(Schema::saml('Issuer'), 0, 1),
            Particle::of(Schema::ds('Signature'), 0, 1),
            new Particle('samlp:Extensions', [self::samlp('Extensions')], 0, 1),
            ...$body,
        ]);
        if ($children[0] === []) {
            throw new MalformedMessage(sprintf(
                'A %s holds no saml:Issuer, which the profile requires (SAML %s).',
                $element,
                $profile,
            ));
        }

        return array_slice($children, 3);
    }

    /**
     * Sections 6.3 and 6.4, on the document the signature or the binding authenticated (M-1): the Issuer of the peer,
     * read by the one reader of an Issuer, its Format omitted or entity and no qualifier (M-8); Version 2.0 and an ID (M-6); an IssueInstant not later than now plus the skew
     * and not older than maxMessageAge (M-7); a Destination, which a signed message carries, XML or binding, equal to
     * the URL at which it arrived, one of our single logout services (M-8, section 6.2 step 3).
     *
     * @param string $element the name of the root in the schema, for the refusals
     *
     * @throws IssuerMismatch when the Issuer is not the peer's, its Format is not entity, or it carries a qualifier (M-8)
     * @throws MalformedMessage when an attribute is absent or not of its lexical form, the Issuer's included (M-5, M-6)
     * @throws OutsideValidityWindow when the IssueInstant is outside its window (M-7)
     * @throws DestinationMismatch when the Destination is absent or not the URL of arrival, or that URL is not one of
     *                             our single logout services (M-8)
     * @throws MixedContent when the Issuer holds an element
     *
     * @return array{string, DateTimeImmutable, Issuer, string} the ID, the IssueInstant, the Issuer and the Destination
     */
    public static function header(Element $root, string $element, LogoutContext $context): array
    {
        $issuer = IssuerReader::read(Children::one($root, Schema::saml('Issuer')), $context->peer);
        Version::read(Schema::attribute($root, $element, 'Version'));
        $id = Schema::attribute($root, $element, 'ID');
        $issueInstant = Time::read(Schema::attribute($root, $element, 'IssueInstant'));
        if ($issueInstant > $context->latest) {
            throw new OutsideValidityWindow('The IssueInstant of the message is later than now plus the clock skew (M-7).');
        }
        if ($issueInstant < $context->oldest) {
            throw new OutsideValidityWindow('The IssueInstant of the message is older than maxMessageAge (M-7).');
        }
        $destination = Attributes::optional($root, new Name(null, 'Destination'));
        if ($destination === null) {
            throw new DestinationMismatch('The message has no Destination, which a signed message carries (M-8).');
        }
        if ($destination !== $context->receivedAt) {
            throw new DestinationMismatch('The Destination of the message is not the URL at which it arrived (M-8).');
        }
        if (! in_array($destination, $context->endpoints, true)) {
            throw new DestinationMismatch('The URL at which the message arrived is not one of our single logout services (M-8).');
        }

        return [$id, $issueInstant, $issuer, $destination];
    }
}
