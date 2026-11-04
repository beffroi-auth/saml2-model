<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Writing;

use Beffroi\Saml2\Model\Assertion\Assertion;
use Beffroi\Saml2\Model\Assertion\Attribute;
use Beffroi\Saml2\Model\Assertion\AuthnStatement;
use Beffroi\Saml2\Model\Assertion\Conditions;
use Beffroi\Saml2\Model\Assertion\SubjectConfirmation;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\Value\Time;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use DateTimeImmutable;
use Dom\Element;

/**
 * Section 6.6 steps 2 and 4, SAML Core §2.3.3
 *
 * @internal
 */
final readonly class AssertionBuilder
{
    private const string BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';

    /**
     * @throws MalformedMessage for a year that is not of four digits
     */
    public static function append(Tree $tree, Element $parent, Assertion $assertion): void
    {
        $element = $tree->introduceSaml($parent, 'Assertion');
        $element->setAttribute('ID', $assertion->id);
        $element->setAttribute('Version', Saml::VERSION);
        $element->setAttribute('IssueInstant', Time::write($assertion->issueInstant));
        $tree->saml($element, 'Issuer')->append($assertion->issuer->entityId);
        $subject = $tree->saml($element, 'Subject');
        NameIdBuilder::append($tree, $subject, $assertion->nameId);
        self::confirmation($tree, $subject, $assertion->confirmation);
        self::conditions($tree, $element, $assertion->conditions);
        self::authnStatement($tree, $element, $assertion->authnStatement);
        if ($assertion->attributes !== []) {
            self::attributes($tree, $element, $assertion->attributes);
        }
    }

    /**
     * @throws MalformedMessage
     */
    private static function confirmation(Tree $tree, Element $subject, SubjectConfirmation $confirmation): void
    {
        $element = $tree->saml($subject, 'SubjectConfirmation');
        $element->setAttribute('Method', self::BEARER);
        $data = $tree->saml($element, 'SubjectConfirmationData');
        $data->setAttribute('NotOnOrAfter', Time::write($confirmation->notOnOrAfter));
        $data->setAttribute('Recipient', $confirmation->recipient);
        self::optional($data, 'InResponseTo', $confirmation->inResponseTo);
        self::optional($data, 'Address', $confirmation->address);
    }

    /**
     * @throws MalformedMessage
     */
    private static function conditions(Tree $tree, Element $assertion, Conditions $conditions): void
    {
        $element = $tree->saml($assertion, 'Conditions');
        self::time($element, 'NotBefore', $conditions->notBefore);
        self::time($element, 'NotOnOrAfter', $conditions->notOnOrAfter);
        foreach ($conditions->audiences as $audiences) {
            $restriction = $tree->saml($element, 'AudienceRestriction');
            foreach ($audiences as $audience) {
                $tree->saml($restriction, 'Audience')->append($audience);
            }
        }
        if ($conditions->oneTimeUse) {
            $tree->saml($element, 'OneTimeUse');
        }
    }

    /**
     * @throws MalformedMessage
     */
    private static function authnStatement(Tree $tree, Element $assertion, AuthnStatement $statement): void
    {
        $element = $tree->saml($assertion, 'AuthnStatement');
        $element->setAttribute('AuthnInstant', Time::write($statement->authnInstant));
        self::optional($element, 'SessionIndex', $statement->sessionIndex);
        self::time($element, 'SessionNotOnOrAfter', $statement->sessionNotOnOrAfter);
        $context = $tree->saml($element, 'AuthnContext');
        $tree->saml($context, 'AuthnContextClassRef')->append($statement->authnContextClassRef);
    }

    /**
     * @param non-empty-list<Attribute> $attributes
     */
    private static function attributes(Tree $tree, Element $assertion, array $attributes): void
    {
        $statement = $tree->saml($assertion, 'AttributeStatement');
        foreach ($attributes as $attribute) {
            $element = $tree->saml($statement, 'Attribute');
            $element->setAttribute('Name', $attribute->name);
            $element->setAttribute('NameFormat', $attribute->nameFormat->value);
            self::optional($element, 'FriendlyName', $attribute->friendlyName);
            foreach ($attribute->values as $value) {
                $tree->saml($element, 'AttributeValue')->append($value);
            }
        }
    }

    private static function optional(Element $element, string $name, ?string $value): void
    {
        if ($value !== null) {
            $element->setAttribute($name, $value);
        }
    }

    /**
     * @throws MalformedMessage
     */
    private static function time(Element $element, string $name, ?DateTimeImmutable $time): void
    {
        if ($time instanceof DateTimeImmutable) {
            $element->setAttribute($name, Time::write($time));
        }
    }
}
