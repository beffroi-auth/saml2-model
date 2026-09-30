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
 * A samlp:LogoutRequest in the order of section 6.3: its structure before any signature, then its values from what
 * the signature or the binding authenticated (M-1).
 *
 * @internal
 */
final readonly class LogoutRequestReader
{
    private const string ELEMENT = 'samlp:LogoutRequest';

    /**
     * Section 6.3, before any signature: saml:Issuer, required (SAML Profiles §4.4.4.1), ds:Signature,
     * samlp:Extensions, then the one identifier of the principal, a saml:NameID (saml:BaseID refused by name, section
     * 8, and saml:EncryptedID until sub-spike 9e, section 6.7), then the samlp:SessionIndex elements, bounded (section
     * 7), counted before any is read (M-17).
     *
     * @throws MalformedMessage when the children are not a sequence of the schema, or the Issuer is missing (M-5)
     * @throws Unsupported when the principal is a saml:BaseID or a saml:EncryptedID
     * @throws LimitExceeded when there are more than 16 session indexes (section 7)
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
            throw new Unsupported('The LogoutRequest names its principal with a saml:EncryptedID, which the package does not support until sub-spike 9e (section 6.7).');
        }
        if (count($sessionIndexes) > LogoutRequest::MAX_SESSION_INDEXES) {
            throw new LimitExceeded('A LogoutRequest names more than 16 session indexes, the bound of section 7 (M-17).');
        }
    }

    /**
     * Section 6.3, on the root of what the signature or the binding authenticated, whose structure was checked: the
     * header of the envelope, the NameID under M-12, read with Text::of() (I-12), the session indexes as read, the
     * NotOnOrAfter under M-7 then later than the IssueInstant, the Reason a URI.
     *
     * @throws IssuerMismatch when the Issuer is not the peer's (M-8)
     * @throws MalformedMessage when an attribute is absent or not of its lexical form (M-5, M-6), or the NotOnOrAfter
     *                          is not later than the IssueInstant (section 6.3)
     * @throws OutsideValidityWindow when the IssueInstant or the NotOnOrAfter is outside its window (M-7)
     * @throws DestinationMismatch when the Destination is not the URL of arrival, one of ours (M-8)
     * @throws InvalidNameId when the NameID breaks the rule of its format (M-12)
     * @throws MixedContent when the Issuer, the NameID or a session index holds an element
     */
    public static function read(Element $root, LogoutContext $context): LogoutRequest
    {
        [$id, $issueInstant, $issuer, $destination] = Envelope::header($root, self::ELEMENT, $context);
        $nameId = NameIdReader::read(Children::one($root, Schema::saml('NameID')));
        $sessionIndexes = array_map(Text::of(...), Children::named($root, Schema::samlp('SessionIndex')));
        $notOnOrAfter = Attributes::optional($root, new Name(null, 'NotOnOrAfter'));
        $notOnOrAfter = $notOnOrAfter === null ? null : Time::read($notOnOrAfter);
        if ($notOnOrAfter instanceof DateTimeImmutable && $notOnOrAfter <= $context->expired) {
            throw new OutsideValidityWindow('The NotOnOrAfter of the LogoutRequest is at or before now minus the clock skew (M-7).');
        }
        // a request that expires when it is issued, or before, is no request (SAML Core §3.7.1)
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
