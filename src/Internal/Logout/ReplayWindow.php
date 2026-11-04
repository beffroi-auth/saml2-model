<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Logout;

use Beffroi\Saml2\Model\Internal\Window;
use DateTimeImmutable;
use function min;
use function sprintf;

/**
 * M-11
 *
 * @internal
 */
final readonly class ReplayWindow
{
    public static function until(Window $window, DateTimeImmutable $issueInstant, ?DateTimeImmutable $notOnOrAfter): DateTimeImmutable
    {
        $skew = sprintf('+%d seconds', $window->bounds->clockSkew);
        $until = $issueInstant->modify(sprintf('+%d seconds', $window->bounds->maxMessageAge))->modify($skew);

        return $notOnOrAfter instanceof DateTimeImmutable ? min($until, $notOnOrAfter->modify($skew)) : $until;
    }
}
