<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Exception;

use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use InvalidArgumentException;

final class UnsuccessfulResponse extends MessageRefused
{
    /**
     * @throws InvalidArgumentException for a Success status
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
