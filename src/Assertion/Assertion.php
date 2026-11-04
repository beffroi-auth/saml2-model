<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Assertion;

use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Counts;
use Beffroi\Saml2\Model\Value\SamlId;
use function count;
use DateTimeImmutable;

/**
 * SAML Core §2.3.3
 */
final readonly class Assertion
{
    /**
     * @param list<Attribute> $attributes
     *
     * @throws MalformedMessage
     * @throws LimitExceeded
     */
    public function __construct(
        public string $id,
        public DateTimeImmutable $issueInstant,
        public Issuer $issuer,
        public NameId $nameId,
        public SubjectConfirmation $confirmation,
        public Conditions $conditions,
        public AuthnStatement $authnStatement,
        public array $attributes,
    ) {
        SamlId::read($id);
        Counts::check(
            count($attributes),
            Counts::ATTRIBUTES,
            'The AttributeStatement holds more than 256 Attribute, the bound of section 7 (M-17).',
        );
    }
}
