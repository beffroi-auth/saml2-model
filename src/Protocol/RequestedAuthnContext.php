<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Protocol;

use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Uri;
use function count;

/**
 * The samlp:RequestedAuthnContext of an AuthnRequest (SAML Core §3.3.2.2.1, section 5.3): a comparison and the
 * saml:AuthnContextClassRef URIs it applies to, in the order of the request, at least one and at most 16 (section 7).
 * A saml:AuthnContextDeclRef is refused by name when the request is read (section 8). Returned, never enforced
 * (section 6.2 step 5).
 */
final readonly class RequestedAuthnContext
{
    public const int MAX_AUTHN_CONTEXT_CLASS_REFS = 16;

    /**
     * @param list<string> $authnContextClassRefs
     *
     * @throws MalformedMessage when the list is empty (M-5), or a reference is not a URI of M-6
     * @throws LimitExceeded when it holds more than 16 references (section 7)
     */
    public function __construct(
        public AuthnContextComparison $comparison,
        public array $authnContextClassRefs,
    ) {
        if ($authnContextClassRefs === []) {
            throw new MalformedMessage('A samlp:RequestedAuthnContext holds no saml:AuthnContextClassRef (M-5).');
        }
        if (count($authnContextClassRefs) > self::MAX_AUTHN_CONTEXT_CLASS_REFS) {
            throw new LimitExceeded('A samlp:RequestedAuthnContext holds more than 16 saml:AuthnContextClassRef, the bound of section 7 (M-17).');
        }
        foreach ($authnContextClassRefs as $authnContextClassRef) {
            Uri::read($authnContextClassRef);
        }
    }
}
