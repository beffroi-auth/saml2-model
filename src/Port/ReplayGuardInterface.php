<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Port;

use DateTimeImmutable;

/**
 * M-11
 *
 * Implemented on a store every worker of the deployment shares: a per-process store in a pool of workers forgets
 * across them.
 */
interface ReplayGuardInterface
{
    /**
     * Atomic: two concurrent calls with the same pair return true once.
     *
     * @param DateTimeImmutable $expiresAt when the pair may be forgotten
     *
     * @return bool true when the pair had not been seen and is now remembered
     */
    public function remember(string $issuer, string $id, DateTimeImmutable $expiresAt): bool;
}
