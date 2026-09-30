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
 * A samlp:NameIDPolicy read strictly (SAML Core §3.4.1.1, section 6.2 step 5): no element child, which its schema
 * does not allow (M-5); its Format one of SAML Core §8.3 or encrypted (M-12), its SPNameQualifier a URI and its
 * AllowCreate a boolean (M-6), each checked by NameIdPolicy.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class NameIdPolicyReader
{
    /**
     * @throws MalformedMessage when it holds an element (M-5), or a value is not of its lexical form (M-6)
     * @throws InvalidNameId when the Format is neither one of SAML Core §8.3 nor encrypted (M-12)
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
