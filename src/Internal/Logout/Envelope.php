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
use Beffroi\Saml2\Model\Internal\Particle;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Saml2\Model\Value\Time;
use Beffroi\Saml2\Model\Value\Version;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Core\Name;
use DateTimeImmutable;
use Dom\Element;
use function in_array;
use function sprintf;

/**
 * Sections 6.3 and 6.4
 *
 * @internal
 */
final readonly class Envelope
{
    /**
     * Section 5.4
     *
     * @throws MalformedMessage
     */
    public static function root(Document $document, string $local): Element
    {
        $root = $document->root();
        if (! Schema::samlp($local)->matches($root)) {
            throw new MalformedMessage(sprintf('The root of the message is not a samlp:%s (section 5.4).', $local));
        }

        return $root;
    }

    /**
     * @param string $element the name of the root in the schema, for the refusals
     * @param string $profile the section of SAML Profiles that requires the Issuer, for the refusal
     * @param list<Particle> $body the places of the schema after samlp:Extensions
     *
     * @throws MalformedMessage
     *
     * @return list<list<Element>> the children of each place of $body, in its order
     */
    public static function children(Element $root, string $element, string $profile, array $body): array
    {
        $children = Schema::children($root, $element, [
            Particle::of(Schema::saml('Issuer'), 0, 1),
            Particle::of(Schema::ds('Signature'), 0, 1),
            new Particle('samlp:Extensions', [Schema::samlp('Extensions')], 0, 1),
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
     * Sections 6.3 and 6.4, M-1
     *
     * @param string $element the name of the root in the schema, for the refusals
     *
     * @throws IssuerMismatch
     * @throws MalformedMessage
     * @throws OutsideValidityWindow
     * @throws DestinationMismatch
     * @throws MixedContent
     *
     * @return array{string, DateTimeImmutable, Issuer, string} the ID, the IssueInstant, the Issuer and the Destination
     */
    public static function header(Element $root, string $element, LogoutContext $context): array
    {
        $issuer = IssuerReader::read(Children::one($root, Schema::saml('Issuer')), $context->peer);
        Version::read(Schema::attribute($root, $element, 'Version'));
        $id = Schema::attribute($root, $element, 'ID');
        $issueInstant = Time::read(Schema::attribute($root, $element, 'IssueInstant'));
        if ($issueInstant > $context->window->latest()) {
            throw new OutsideValidityWindow('The IssueInstant of the message is later than now plus the clock skew (M-7).');
        }
        if ($issueInstant < $context->window->oldest()) {
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
