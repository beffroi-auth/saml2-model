<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Response;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\Particle;
use Beffroi\Saml2\Model\Internal\Protocol\StatusReader;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use function count;
use Dom\Element;

/**
 * The structure of the envelope of a response, section 6.1 step 2, read before any key is touched: its children in
 * the order of the schema (M-5), saml:Issuer optional, ds:Signature optional, samlp:Extensions optional and never
 * read, samlp:Status, then the assertions, each a saml:Assertion or a saml:EncryptedAssertion; exactly one of them, a
 * direct child, with a status of Success, none with another (M-4, M-13); a saml:EncryptedAssertion holding one
 * xenc:EncryptedData and nothing else, an xenc:EncryptedKey next to it refused by name (section 6.7). What it keeps is
 * the status, and the one assertion of the element it read, in clear or encrypted, never searched below it (I-11).
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class Envelope
{
    /**
     * @param ?Element $assertion the one saml:Assertion or saml:EncryptedAssertion child, null for a failure
     * @param bool $encrypted whether that child is a saml:EncryptedAssertion
     */
    private function __construct(
        public Status $status,
        public ?Element $assertion,
        public bool $encrypted,
    ) {
    }

    /**
     * @param Element $response a samlp:Response, as UnverifiedResponse::of() checked it
     *
     * @throws Unsupported when a saml:EncryptedAssertion holds an xenc:EncryptedKey next to its xenc:EncryptedData
     *                     (section 6.7)
     * @throws MalformedMessage when a child is out of order, repeated or not allowed, the status is malformed, the
     *                          assertions are not what the status requires, or a saml:EncryptedAssertion does not hold
     *                          one xenc:EncryptedData (M-4, M-5, M-13)
     */
    public static function of(Element $response): self
    {
        [, , , [$element], $assertions] = Schema::children($response, 'samlp:Response', [
            Particle::of(Schema::saml('Issuer'), 0, 1),
            Particle::of(Schema::ds('Signature'), 0, 1),
            Particle::of(Schema::samlp('Extensions'), 0, 1),
            Particle::of(Schema::samlp('Status'), 1, 1),
            new Particle(
                'saml:Assertion or saml:EncryptedAssertion',
                [Schema::saml('Assertion'), Schema::saml('EncryptedAssertion')],
                0,
                Particle::UNBOUNDED,
            ),
        ]);
        StatusReader::structure($element);
        $status = StatusReader::read($element);
        if ($status->code !== StatusCode::Success) {
            if ($assertions !== []) {
                throw new MalformedMessage('The samlp:Response has a status other than Success and holds a saml:Assertion or a saml:EncryptedAssertion (M-13).');
            }

            return new self($status, null, false);
        }
        if ($assertions === []) {
            throw new MalformedMessage('The samlp:Response has the status Success and holds no saml:Assertion or saml:EncryptedAssertion (M-13).');
        }
        if (count($assertions) > 1) {
            throw new MalformedMessage('The samlp:Response holds more than one saml:Assertion or saml:EncryptedAssertion (M-4).');
        }
        $encrypted = Schema::saml('EncryptedAssertion')->matches($assertions[0]);
        if ($encrypted) {
            Schema::unsupported(
                $assertions[0],
                [Schema::xenc('EncryptedKey')],
                'The saml:EncryptedAssertion holds an xenc:EncryptedKey next to its xenc:EncryptedData, a form the package does not support (section 6.7).',
            );
            Schema::children($assertions[0], 'saml:EncryptedAssertion', [
                Particle::of(Schema::xenc('EncryptedData'), 1, 1),
            ]);
        }

        return new self($status, $assertions[0], $encrypted);
    }
}
