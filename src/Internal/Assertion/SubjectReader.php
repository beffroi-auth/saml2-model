<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Assertion;

use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Assertion\SubjectConfirmation;
use Beffroi\Saml2\Model\Exception\InResponseToMismatch;
use Beffroi\Saml2\Model\Exception\InvalidNameId;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use Beffroi\Saml2\Model\Exception\RecipientMismatch;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\Particle;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Saml2\Model\Value\Time;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Name;
use Dom\Element;

/**
 * The subject of an assertion, section 6.1 step 8: one saml:NameID read under M-12, with Text::of() (I-12), and one
 * saml:SubjectConfirmation of method bearer (M-4) whose SubjectConfirmationData holds no element, a Recipient that is
 * the URL of arrival (M-8), a NotOnOrAfter in the window of M-7 and at most maxBearerWindow ahead, no NotBefore (SAML
 * Profiles §4.1.4.2), the InResponseTo the consumer expects (M-10), and an Address kept as read.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class SubjectReader
{
    private const string BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';

    /**
     * @return array{NameId, SubjectConfirmation}
     *
     * @throws MalformedMessage when an element is missing, repeated, out of order or not allowed, or a value is not of
     *                          its lexical form (M-4, M-5, M-6)
     * @throws Unsupported when the subject or its confirmation is of a kind the package does not support (section 8)
     * @throws InvalidNameId when the NameID breaks the rule of its format (M-12)
     * @throws RecipientMismatch when the Recipient is not the URL of arrival (M-8)
     * @throws OutsideValidityWindow when the bearer window has closed or ends too far ahead (M-7)
     * @throws InResponseToMismatch when the InResponseTo is not the one expected (M-10)
     */
    public static function read(Element $subject, AssertionContext $context): array
    {
        Schema::unsupported(
            $subject,
            [Schema::saml('BaseID')],
            'The subject is a saml:BaseID, which the package does not support (section 8).',
        );
        Schema::unsupported(
            $subject,
            [Schema::saml('EncryptedID')],
            'The subject is a saml:EncryptedID, which the package does not support (section 6.7).',
        );
        Schema::children($subject, 'saml:Subject', [
            Particle::of(Schema::saml('NameID'), 1, 1),
            Particle::of(Schema::saml('SubjectConfirmation'), 1, 1),
        ]);

        return [
            NameIdReader::read(Children::one($subject, Schema::saml('NameID'))),
            self::confirmation(Children::one($subject, Schema::saml('SubjectConfirmation')), $context),
        ];
    }

    private static function confirmation(Element $confirmation, AssertionContext $context): SubjectConfirmation
    {
        $method = Schema::attribute($confirmation, 'saml:SubjectConfirmation', 'Method');
        if ($method !== self::BEARER) {
            throw new Unsupported('The confirmation method is not bearer, the one the package supports (section 8).');
        }
        Schema::unsupported(
            $confirmation,
            [Schema::saml('NameID'), Schema::saml('BaseID'), Schema::saml('EncryptedID')],
            'The bearer confirmation holds an identifier of its own, which the package does not support (section 8).',
        );
        Schema::children($confirmation, 'saml:SubjectConfirmation', [Particle::of(
            Schema::saml('SubjectConfirmationData'),
            1,
            1,
        )]);
        $data = Children::one($confirmation, Schema::saml('SubjectConfirmationData'));
        if (Children::all($data) !== []) {
            throw new Unsupported('The SubjectConfirmationData of the bearer confirmation holds an element, which the package does not support (section 8).');
        }
        if (Attributes::optional($data, new Name(null, 'NotBefore')) !== null) {
            throw new MalformedMessage('The bearer confirmation has a NotBefore (section 6.1).');
        }
        $read = new SubjectConfirmation(
            Attributes::optional(
                $data,
                new Name(null, 'Recipient'),
            ) ?? throw new MalformedMessage('The bearer confirmation has no Recipient (M-8).'),
            Time::read(
                Attributes::optional(
                    $data,
                    new Name(null, 'NotOnOrAfter'),
                ) ?? throw new MalformedMessage('The bearer confirmation has no NotOnOrAfter (section 6.1).'),
            ),
            Attributes::optional($data, new Name(null, 'InResponseTo')),
            Attributes::optional($data, new Name(null, 'Address')),
        );
        if ($read->recipient !== $context->recipient) {
            throw new RecipientMismatch('The Recipient of the bearer confirmation is not the URL at which the response arrived (M-8).');
        }
        if ($read->notOnOrAfter <= $context->window->earliest()) {
            throw new OutsideValidityWindow('The NotOnOrAfter of the bearer confirmation is at or before now minus the clock skew (M-7).');
        }
        if ($read->notOnOrAfter > $context->window->bearerLimit()) {
            throw new OutsideValidityWindow('The NotOnOrAfter of the bearer confirmation is later than now plus maxBearerWindow (M-7).');
        }
        if ($read->inResponseTo !== $context->inResponseTo) {
            throw new InResponseToMismatch('The InResponseTo of the bearer confirmation is not the one the consumer expects (M-10).');
        }

        return $read;
    }
}
