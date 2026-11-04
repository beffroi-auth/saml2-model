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
 * SAML Core §2.5.1
 */
final readonly class Conditions
{
    /**
     * @param list<list<string>> $audiences the Audience URIs of each AudienceRestriction
     *
     * @throws MalformedMessage
     * @throws AudienceMismatch when there is no restriction at all (M-8)
     * @throws LimitExceeded
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
