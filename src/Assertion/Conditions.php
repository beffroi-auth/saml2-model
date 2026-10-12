<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Assertion;

use Beffroi\Saml2\Model\Exception\AudienceMismatch;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Counts;
use Beffroi\Saml2\Model\Value\Uri;
use function count;
use DateTimeImmutable;

/**
 * The saml:Conditions of an assertion (SAML Core §2.5.1), whoever builds them: a window whose NotBefore, when both ends
 * are given, is earlier than its NotOnOrAfter (SAML Core §2.5.1.2); at least one AudienceRestriction (SAML Profiles
 * §4.1.4.2), each a non-empty list of Audience URIs of M-6 (SAML Core §2.5.1.4), both lists within their counts of
 * section 7 (M-15, M-17); OneTimeUse, which the replay rule
 * honours (M-11). Whether each restriction holds our entity ID and the window holds against the clock are the rules of
 * the reader (M-7, M-8).
 */
final readonly class Conditions
{
    /**
     * @param list<list<string>> $audiences the Audience URIs of each AudienceRestriction, in document order
     *
     * @throws MalformedMessage when the window does not end after it starts, a restriction holds no audience, or an
     *                          audience is not a URI of M-6
     * @throws AudienceMismatch when there is no restriction at all (M-8)
     * @throws LimitExceeded when there are more than 8 restrictions, or more than 16 audiences in one (section 7)
     */
    public function __construct(
        public ?DateTimeImmutable $notBefore,
        public ?DateTimeImmutable $notOnOrAfter,
        public array $audiences,
        public bool $oneTimeUse,
    ) {
        if ($notBefore instanceof DateTimeImmutable && $notOnOrAfter instanceof DateTimeImmutable && $notBefore >= $notOnOrAfter) {
            throw new MalformedMessage('The NotBefore of the Conditions is not earlier than their NotOnOrAfter (M-7).');
        }
        if ($audiences === []) {
            throw new AudienceMismatch('The Conditions hold no AudienceRestriction (M-8).');
        }
        Counts::check(
            count($audiences),
            Counts::AUDIENCE_RESTRICTIONS,
            'The Conditions hold more than 8 AudienceRestriction, the bound of section 7 (M-17).',
        );
        foreach ($audiences as $restriction) {
            Counts::check(
                count($restriction),
                Counts::AUDIENCES,
                'An AudienceRestriction holds more than 16 Audience, the bound of section 7 (M-17).',
            );
            if ($restriction === []) {
                throw new MalformedMessage('An AudienceRestriction holds no Audience (M-5).');
            }
            foreach ($restriction as $audience) {
                Uri::read($audience);
            }
        }
    }
}
