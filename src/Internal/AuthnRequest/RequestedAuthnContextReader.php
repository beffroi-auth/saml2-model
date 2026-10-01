<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\AuthnRequest;

use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Protocol\AuthnContextComparison;
use Beffroi\Saml2\Model\Protocol\RequestedAuthnContext;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use function count;
use Dom\Element;

/**
 * A samlp:RequestedAuthnContext read strictly (SAML Core §3.3.2.2.1, section 6.2 step 5): its Comparison, exact when
 * absent, and its saml:AuthnContextClassRef children, each read with Text::of() (I-12), at least one and at most 16,
 * counted before any is read (section 7, M-17); a saml:AuthnContextDeclRef is refused by name (section 8), any other
 * child is malformed (M-5).
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class RequestedAuthnContextReader
{
    /**
     * @throws LimitExceeded when it holds more than 16 class references (section 7)
     * @throws Unsupported when it holds a saml:AuthnContextDeclRef (section 8)
     * @throws MalformedMessage when it holds another child or no class reference (M-5), or a value is not of its
     *                          lexical form (M-5, M-6)
     * @throws MixedContent when a class reference holds an element
     */
    public static function read(Element $context): RequestedAuthnContext
    {
        if (
            count(Children::named($context, new Name(Saml::ASSERTION, 'AuthnContextClassRef')))
            > RequestedAuthnContext::MAX_AUTHN_CONTEXT_CLASS_REFS
        ) {
            throw new LimitExceeded('A samlp:RequestedAuthnContext holds more than 16 saml:AuthnContextClassRef, the bound of section 7 (M-17).');
        }
        $classRefs = [];
        foreach (Children::all($context) as $child) {
            if (new Name(Saml::ASSERTION, 'AuthnContextDeclRef')->matches($child)) {
                throw new Unsupported('The samlp:RequestedAuthnContext holds a saml:AuthnContextDeclRef, which the package does not support (section 8).');
            }
            if (! new Name(Saml::ASSERTION, 'AuthnContextClassRef')->matches($child)) {
                throw new MalformedMessage('The samlp:RequestedAuthnContext holds a child other than saml:AuthnContextClassRef (M-5).');
            }
            $classRefs[] = Text::of($child);
        }

        return new RequestedAuthnContext(
            AuthnContextComparison::fromAttribute(Attributes::optional($context, new Name(null, 'Comparison'))),
            $classRefs,
        );
    }
}
