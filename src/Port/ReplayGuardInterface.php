<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Port;

use DateTimeImmutable;

/**
 * The replay port of section 5.2 (M-11): the store the validator remembers each accepted assertion in, under its
 * issuer, until its bearer window closes. The consumer implements it on a store every worker of its deployment shares;
 * the atomicity is the implementation's promise, since a store that checks then writes lets two workers accept the
 * same assertion. The package ships no implementation: a per-process store in a pool of workers forgets across them.
 */
interface ReplayGuardInterface
{
    /**
     * Remember that the assertion $id of $issuer was accepted, atomically: two concurrent calls with the same pair
     * return true once.
     *
     * @param string            $issuer    the verified entity ID of the assertion's issuer
     * @param string            $id        the verified ID of the assertion
     * @param DateTimeImmutable $expiresAt when the pair may be forgotten: the end of the bearer window plus the skew
     *
     * @return bool true when the pair had not been seen and is now remembered, false when it had
     */
    public function remember(string $issuer, string $id, DateTimeImmutable $expiresAt): bool;
}
