<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\AuthnRequest;

use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Protocol\AuthnContextComparison;
use Beffroi\Saml2\Model\Protocol\RequestedAuthnContext;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\Value\Counts;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use function count;
use Dom\Element;

/**
 * SAML Core §3.3.2.2.1, section 6.2 step 5
 *
 * @internal
 */
final readonly class RequestedAuthnContextReader
{
    /**
     * @throws LimitExceeded
     * @throws Unsupported
     * @throws MalformedMessage
     * @throws MixedContent
     */
    public static function read(Element $context): RequestedAuthnContext
    {
        Counts::check(
            count(Children::named($context, new Name(Saml::ASSERTION, 'AuthnContextClassRef'))),
            Counts::AUTHN_CONTEXT_CLASS_REFS,
            'A samlp:RequestedAuthnContext holds more than 16 saml:AuthnContextClassRef, the bound of section 7 (M-17).',
        );
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
