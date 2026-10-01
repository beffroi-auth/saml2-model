<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Writing;

use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\Status;
use Dom\Element;

/**
 * The one writer of a samlp:Status, a response's and a logout response's (section 6.6): its top-level code, and its
 * second-level code inside it when it has one; no StatusMessage, which the reader never keeps (M-13, M-16).
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class StatusBuilder
{
    /**
     * The status appended to $parent, where the samlp prefix is declared.
     */
    public static function append(Tree $tree, Element $parent, Status $status): void
    {
        $code = $tree->samlp($tree->samlp($parent, 'Status'), 'StatusCode');
        $code->setAttribute('Value', $status->code->value);
        if ($status->secondLevel instanceof SecondLevelStatusCode) {
            $tree->samlp($code, 'StatusCode')->setAttribute('Value', $status->secondLevel->value);
        }
    }
}
