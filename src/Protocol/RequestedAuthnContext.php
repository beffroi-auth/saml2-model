<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Protocol;

use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Counts;
use Beffroi\Saml2\Model\Value\Uri;
use function count;

/**
 * SAML Core §3.3.2.2.1
 */
final readonly class RequestedAuthnContext
{
    /**
     * @param list<string> $authnContextClassRefs
     *
     * @throws MalformedMessage when the list is empty, or a reference is not a URI
     * @throws LimitExceeded
     */
    public function __construct(
        public AuthnContextComparison $comparison,
        public array $authnContextClassRefs,
    ) {
        if ($authnContextClassRefs === []) {
            throw new MalformedMessage('A samlp:RequestedAuthnContext holds no saml:AuthnContextClassRef (M-5).');
        }
        Counts::check(
            count($authnContextClassRefs),
            Counts::AUTHN_CONTEXT_CLASS_REFS,
            'A samlp:RequestedAuthnContext holds more than 16 saml:AuthnContextClassRef, the bound of section 7 (M-17).',
        );
        foreach ($authnContextClassRefs as $authnContextClassRef) {
            Uri::read($authnContextClassRef);
        }
    }
}
