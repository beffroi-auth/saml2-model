<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Writing;

use Beffroi\Saml2\Model\Assertion\Assertion;
use Beffroi\Saml2\Model\Protocol\Response;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\Value\Time;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\DocumentFactory;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Xml\Core\Name;

/**
 * Section 6.6 step 2, SAML Core §3.2.2
 *
 * @internal
 */
final readonly class ResponseBuilder
{
    /**
     * @throws MalformedMessage for a year that is not of four digits
     */
    public static function build(Response $response): Document
    {
        $document = new DocumentFactory()->create(new Name(Saml::PROTOCOL, 'Response'), 'samlp');
        $tree = Tree::of($document);
        $root = $document->root();
        $root->setAttribute('ID', $response->id);
        $root->setAttribute('Version', Saml::VERSION);
        $root->setAttribute('IssueInstant', Time::write($response->issueInstant));
        if ($response->destination !== null) {
            $root->setAttribute('Destination', $response->destination);
        }
        if ($response->inResponseTo !== null) {
            $root->setAttribute('InResponseTo', $response->inResponseTo);
        }
        $tree->introduceSaml($root, 'Issuer')->append($response->issuer->entityId);
        StatusBuilder::append($tree, $root, $response->status);
        if ($response->assertion instanceof Assertion) {
            AssertionBuilder::append($tree, $root, $response->assertion);
        }

        return $document;
    }
}
