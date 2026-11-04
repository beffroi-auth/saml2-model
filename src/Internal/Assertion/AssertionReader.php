<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Assertion;

use Beffroi\Saml2\Model\Assertion\Assertion;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\MessageRefused;
use Beffroi\Saml2\Model\Internal\Particle;
use Beffroi\Saml2\Model\Internal\Response\SignedAssertion;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\MixedContent;
use function count;
use Dom\Element;

/**
 * Section 6.1 steps 7 to 11
 *
 * Takes a document or the signed selection, never an element, so that no assertion is read outside a signature (M-1).
 *
 * @internal
 */
final readonly class AssertionReader
{
    /**
     * @throws MessageRefused
     * @throws MixedContent
     */
    public static function read(Document $document, AssertionContext $context): Assertion
    {
        $assertion = $document->root();
        if (! Schema::saml('Assertion')->matches($assertion)) {
            throw new MalformedMessage('The root of the document is not a saml:Assertion (M-4).');
        }

        return self::assertion($assertion, $context);
    }

    /**
     * Section 6.1 step 5, M-1
     *
     * @throws MessageRefused
     * @throws MixedContent
     */
    public static function readCovered(SignedAssertion $covered, AssertionContext $context): Assertion
    {
        $root = $covered->document->root();
        if (Schema::saml('Assertion')->matches($root)) {
            return self::assertion($root, $context);
        }
        if (! Schema::samlp('Response')->matches($root)) {
            throw new MalformedMessage('The root of the verified document is neither a saml:Assertion nor a samlp:Response (M-1).');
        }
        $assertions = Children::named($root, Schema::saml('Assertion'));
        if (count($assertions) !== 1) {
            throw new MalformedMessage('The verified samlp:Response does not hold exactly one saml:Assertion (M-4).');
        }

        return self::assertion($assertions[0], $context);
    }

    /**
     * @throws MessageRefused
     * @throws MixedContent
     */
    private static function assertion(Element $assertion, AssertionContext $context): Assertion
    {
        Schema::unsupported(
            $assertion,
            [Schema::saml('Statement'), Schema::saml('AuthzDecisionStatement')],
            'The assertion holds a statement other than AuthnStatement and AttributeStatement, which the package does not support (section 8).',
        );
        Schema::children($assertion, 'saml:Assertion', [
            Particle::of(Schema::saml('Issuer'), 1, 1),
            Particle::of(Schema::ds('Signature'), 0, 1),
            Particle::of(Schema::saml('Subject'), 1, 1),
            Particle::of(Schema::saml('Conditions'), 1, 1),
            Particle::of(Schema::saml('Advice'), 0, 1),
            new Particle(
                'statement',
                [Schema::saml('AuthnStatement'), Schema::saml('AttributeStatement')],
                0,
                Particle::UNBOUNDED,
            ),
        ]);
        $authnStatements = Children::named($assertion, Schema::saml('AuthnStatement'));
        if ($authnStatements === []) {
            throw new MalformedMessage('The saml:Assertion holds no saml:AuthnStatement (M-4).');
        }
        if (count($authnStatements) > 1) {
            throw new MalformedMessage('The saml:Assertion holds more than one saml:AuthnStatement (M-4).');
        }
        $attributeStatements = Children::named($assertion, Schema::saml('AttributeStatement'));
        if (count($attributeStatements) > 1) {
            throw new MalformedMessage('The saml:Assertion holds more than one saml:AttributeStatement (M-4).');
        }
        [$id, $issueInstant, $issuer] = HeaderReader::read($assertion, $context);
        [$nameId, $confirmation] = SubjectReader::read(Children::one($assertion, Schema::saml('Subject')), $context);

        return new Assertion(
            $id,
            $issueInstant,
            $issuer,
            $nameId,
            $confirmation,
            ConditionsReader::read(Children::one($assertion, Schema::saml('Conditions')), $context),
            AuthnStatementReader::read($authnStatements[0], $context),
            $attributeStatements === [] ? [] : AttributeStatementReader::read($attributeStatements[0]),
        );
    }
}
