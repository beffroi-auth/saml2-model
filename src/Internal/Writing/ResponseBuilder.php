<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Writing;

use Beffroi\Saml2\Model\Assertion\Assertion;
use Beffroi\Saml2\Model\Protocol\Response;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\Value\Time;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\DocumentFactory;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Xml\Core\Name;

/**
 * The samlp:Response of the identity provider, section 6.6 step 2, built with DocumentFactory and the samlp prefix, in
 * the order of the schema (SAML Core §3.2.2): its ID, Version, IssueInstant in UTC to the second (M-15), Destination
 * and InResponseTo when given; its Issuer, written without Format (SAML Profiles §4.1.4.2 as corrected by E17); its
 * Status, the top-level code and the second-level one when there is one, no StatusMessage; then its one assertion,
 * none on a failure (M-13). Unsigned: signing is the writer's (section 6.6 step 3).
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class ResponseBuilder
{
    /**
     * @throws MalformedMessage what Time refuses of a year that is not of four digits (M-15)
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
        $code = $tree->samlp($tree->samlp($root, 'Status'), 'StatusCode');
        $code->setAttribute('Value', $response->status->code->value);
        if ($response->status->secondLevel instanceof SecondLevelStatusCode) {
            $tree->samlp($code, 'StatusCode')->setAttribute('Value', $response->status->secondLevel->value);
        }
        if ($response->assertion instanceof Assertion) {
            AssertionBuilder::append($tree, $root, $response->assertion);
        }

        return $document;
    }
}
