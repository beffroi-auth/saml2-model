<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Logout;

use function array_map;
use Beffroi\Saml2\Model\Exception\DestinationMismatch;
use Beffroi\Saml2\Model\Exception\InvalidNameId;
use Beffroi\Saml2\Model\Exception\IssuerMismatch;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\Assertion\NameIdReader;
use Beffroi\Saml2\Model\Internal\Particle;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Saml2\Model\Protocol\LogoutRequest;
use Beffroi\Saml2\Model\Value\Counts;
use Beffroi\Saml2\Model\Value\Time;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use function count;
use DateTimeImmutable;
use Dom\Element;

/**
 * Section 6.3
 *
 * @internal
 */
final readonly class LogoutRequestReader
{
    private const string ELEMENT = 'samlp:LogoutRequest';

    /**
     * @throws MalformedMessage
     * @throws Unsupported
     * @throws LimitExceeded
     */
    public static function structure(Element $root): void
    {
        [$identifier, $sessionIndexes] = Envelope::children($root, self::ELEMENT, 'Profiles §4.4.4.1', [
            new Particle(
                'identifier',
                [Schema::saml('BaseID'), Schema::saml('NameID'), Schema::saml('EncryptedID')],
                1,
                1,
            ),
            new Particle('samlp:SessionIndex', [Schema::samlp('SessionIndex')], 0, Particle::UNBOUNDED),
        ]);
        if (Schema::saml('BaseID')->matches($identifier[0])) {
            throw new Unsupported('The LogoutRequest names its principal with a saml:BaseID, which the package does not support (section 8).');
        }
        if (Schema::saml('EncryptedID')->matches($identifier[0])) {
            throw new Unsupported('The LogoutRequest names its principal with a saml:EncryptedID, which the package does not support (section 6.7).');
        }
        Counts::check(
            count($sessionIndexes),
            Counts::SESSION_INDEXES,
            'A LogoutRequest names more than 16 session indexes, the bound of section 7 (M-17).',
        );
    }

    /**
     * Section 6.3, M-1
     *
     * @throws IssuerMismatch
     * @throws MalformedMessage
     * @throws OutsideValidityWindow
     * @throws DestinationMismatch
     * @throws InvalidNameId
     * @throws MixedContent
     */
    public static function read(Element $root, LogoutContext $context): LogoutRequest
    {
        [$id, $issueInstant, $issuer, $destination] = Envelope::header($root, self::ELEMENT, $context);
        $nameId = NameIdReader::read(Children::one($root, Schema::saml('NameID')));
        $sessionIndexes = array_map(Text::of(...), Children::named($root, Schema::samlp('SessionIndex')));
        $notOnOrAfter = Attributes::optional($root, new Name(null, 'NotOnOrAfter'));
        $notOnOrAfter = $notOnOrAfter === null ? null : Time::read($notOnOrAfter);
        if ($notOnOrAfter instanceof DateTimeImmutable && $notOnOrAfter <= $context->window->earliest()) {
            throw new OutsideValidityWindow('The NotOnOrAfter of the LogoutRequest is at or before now minus the clock skew (M-7).');
        }
        if ($notOnOrAfter instanceof DateTimeImmutable && $notOnOrAfter <= $issueInstant) {
            throw new MalformedMessage('The NotOnOrAfter of the LogoutRequest is not later than its IssueInstant (section 6.3).');
        }

        return new LogoutRequest(
            $id,
            $issueInstant,
            $issuer,
            $destination,
            $notOnOrAfter,
            $nameId,
            $sessionIndexes,
            Attributes::optional($root, new Name(null, 'Reason')),
        );
    }
}
