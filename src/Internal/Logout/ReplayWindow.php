<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Logout;

use Beffroi\Saml2\Model\Internal\Window;
use DateTimeImmutable;
use function min;
use function sprintf;

/**
 * Until when an accepted logout message is remembered (M-11, sections 6.3 and 6.4): the end of the window in which the
 * model would accept it again, its IssueInstant plus maxMessageAge and the skew, or the NotOnOrAfter of a request plus
 * the skew when that is earlier. The validator hands it to the replay port, last.
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
