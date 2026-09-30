<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Exception;

use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use InvalidArgumentException;

/**
 * A response whose top-level status is not Success: it carries no assertion, and yields none (M-13, SAML Profiles
 * §4.1.4.2). The consumer reads the codes from the status it carries; the message names the rule and no code, and the
 * StatusMessage the peer wrote is kept nowhere (M-16).
 */
final class UnsuccessfulResponse extends MessageRefused
{
    /**
     * @throws InvalidArgumentException for a Success status, a programming error of the caller
     */
    public function __construct(
        public readonly Status $status,
    ) {
        if ($status->code === StatusCode::Success) {
            throw new InvalidArgumentException('A response refused as unsuccessful has a status other than Success (M-13).');
        }

        parent::__construct('The status of the response is not Success, and the response yields no assertion (M-13).');
    }
}
