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
 * A saml:Assertion as the rules of section 6.1 steps 7 to 11 accepted it (SAML Core §2.3.3): its ID, an ID of M-6; its
 * IssueInstant; its Issuer; the NameID and the one bearer confirmation of its subject; its conditions; its one
 * authentication statement; the attributes of its attribute statement, in document order, none when it has none (M-4),
 * at most the count of section 7 whoever builds it (M-15, M-17).
 * Nothing but the strict reader of the package builds one from a document, and only from a verified one (M-1).
 */
final readonly class Assertion
{
    /**
     * @param list<Attribute> $attributes
     *
     * @throws MalformedMessage when the ID is not an ID of M-6
     * @throws LimitExceeded when there are more than 256 attributes (section 7)
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
