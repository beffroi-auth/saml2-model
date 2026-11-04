<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\AuthnRequest;

use Beffroi\Saml2\Model\Exception\InvalidNameId;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Protocol\NameIdPolicy;
use Beffroi\Saml2\Model\Value\Boolean;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Name;
use Dom\Element;

/**
 * SAML Core §3.4.1.1, section 6.2 step 5
 *
 * @internal
 */
final readonly class NameIdPolicyReader
{
    /**
     * @throws MalformedMessage
     * @throws InvalidNameId
     */
    public static function read(Element $policy): NameIdPolicy
    {
        if (Children::all($policy) !== []) {
            throw new MalformedMessage('The samlp:NameIDPolicy holds an element, which the schema does not allow there (M-5).');
        }
        $allowCreate = Attributes::optional($policy, new Name(null, 'AllowCreate'));

        return new NameIdPolicy(
            Attributes::optional($policy, new Name(null, 'Format')),
            Attributes::optional($policy, new Name(null, 'SPNameQualifier')),
            $allowCreate !== null && Boolean::read($allowCreate),
        );
    }
}
