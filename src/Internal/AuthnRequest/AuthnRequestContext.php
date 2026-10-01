<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\AuthnRequest;

use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Validation\Authentication;
use DateTimeImmutable;

/**
 * What the rules of an AuthnRequest are checked against (section 6.2 steps 3 to 5), as the validator states it: the
 * two edges of the window of its IssueInstant, from now read once from the clock (M-7); the service provider whose
 * metadata authenticated it and ours, the identity provider (M-8, M-9); the URL at which it arrived (M-8); how it was
 * authenticated (M-2), since a signature, of its own or of the binding, makes the Destination required.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class AuthnRequestContext
{
    /**
     * @param DateTimeImmutable $latest now plus the clock skew: an IssueInstant later than this is refused (M-7)
     * @param DateTimeImmutable $oldest now minus maxMessageAge: an IssueInstant earlier than this is refused (M-7)
     */
    public function __construct(
        public DateTimeImmutable $latest,
        public DateTimeImmutable $oldest,
        public ServiceProvider $serviceProvider,
        public IdentityProvider $identityProvider,
        public string $receivedAt,
        public Authentication $authentication,
    ) {
    }
}
