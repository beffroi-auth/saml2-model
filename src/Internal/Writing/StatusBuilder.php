<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Writing;

use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\Status;
use Dom\Element;

/**
 * @internal
 */
final readonly class StatusBuilder
{
    public static function append(Tree $tree, Element $parent, Status $status): void
    {
        $code = $tree->samlp($tree->samlp($parent, 'Status'), 'StatusCode');
        $code->setAttribute('Value', $status->code->value);
        if ($status->secondLevel instanceof SecondLevelStatusCode) {
            $tree->samlp($code, 'StatusCode')->setAttribute('Value', $status->secondLevel->value);
        }
    }
}
