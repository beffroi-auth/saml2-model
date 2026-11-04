<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Protocol;

use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Characters;
use Beffroi\Saml2\Model\Value\Counts;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Saml2\Model\Value\Uri;
use function count;
use DateTimeImmutable;

/**
 * SAML Core §3.7.1
 *
 * The Destination is required: the profile authenticates every logout message, by its own signature or by the
 * binding's (SAML Profiles §4.4.4.1), and a signed message names where it goes.
 */
final readonly class LogoutRequest
{
    /**
     * @param list<string> $sessionIndexes
     *
     * @throws MalformedMessage
     * @throws LimitExceeded
     */
    public function __construct(
        public string $id,
        public DateTimeImmutable $issueInstant,
        public Issuer $issuer,
        public string $destination,
        public ?DateTimeImmutable $notOnOrAfter,
        public NameId $nameId,
        public array $sessionIndexes = [],
        public ?string $reason = null,
    ) {
        SamlId::read($id);
        Uri::read($destination);
        Counts::check(
            count($sessionIndexes),
            Counts::SESSION_INDEXES,
            'A LogoutRequest names more than 16 session indexes, the bound of section 7 (M-17).',
        );
        foreach ($sessionIndexes as $sessionIndex) {
            if (! Characters::carriedByXml($sessionIndex)) {
                throw new MalformedMessage('A SessionIndex holds a character XML does not carry, a NUL among them (M-15).');
            }
        }
        if ($reason !== null) {
            Uri::read($reason);
        }
    }
}
