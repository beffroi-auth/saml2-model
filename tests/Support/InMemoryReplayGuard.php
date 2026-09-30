<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Support;

use Beffroi\Saml2\Model\Port\ReplayGuardInterface;
use DateTimeImmutable;

/**
 * The replay port of section 5.2 in the memory of one process, for the tests only and never shipped: in a pool of
 * workers, a store per process forgets across them. A pair is keyed by its issuer and its ID, never by the ID alone
 * (M-11), and is never forgotten: the tests read when it expires instead.
 */
final class InMemoryReplayGuard implements ReplayGuardInterface
{
    /**
     * @var array<string, array<string, DateTimeImmutable>> when each ID of each issuer may be forgotten
     */
    private array $remembered = [];

    public function remember(string $issuer, string $id, DateTimeImmutable $expiresAt): bool
    {
        if ($this->expiresAt($issuer, $id) instanceof DateTimeImmutable) {
            return false;
        }
        $this->remembered[$issuer][$id] = $expiresAt;

        return true;
    }

    /**
     * When the pair may be forgotten, as the validator said, or null when it was never remembered.
     */
    public function expiresAt(string $issuer, string $id): ?DateTimeImmutable
    {
        return $this->remembered[$issuer][$id] ?? null;
    }

    /**
     * Whether nothing was remembered: what a refused assertion leaves behind (M-11, §9.3).
     */
    public function isEmpty(): bool
    {
        return $this->remembered === [];
    }
}
