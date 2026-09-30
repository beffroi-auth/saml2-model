<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model;

use Beffroi\Xml\Core\IdAttribute;
use Beffroi\Xml\Core\IdAttributes;
use Beffroi\Xml\Core\Limits;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Name;

/**
 * The one loader of the package (section 5.1, M-14): every document the model reads, the re-parse of the Verifier and
 * the reload of the Signer go through a Core Loader with this preset of ID attributes, so that the SAML, XML Signature
 * and XML Encryption identifiers of a document form one space, and a value that appears twice refuses the document
 * (core.md I-8, section 6.2).
 */
final class SamlLoader
{
    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    private const string XENC = 'http://www.w3.org/2001/04/xmlenc#';

    /**
     * ID on the elements of the assertion, protocol and metadata namespaces, Id on those of XML Signature and XML
     * Encryption, as core.md section 5.3 records them for the SAML stack: one ID space (M-14).
     */
    public static function idAttributes(): IdAttributes
    {
        return new IdAttributes([
            new IdAttribute(new Name(null, 'ID'), Saml::ASSERTION),
            new IdAttribute(new Name(null, 'ID'), Saml::PROTOCOL),
            new IdAttribute(new Name(null, 'ID'), Saml::METADATA),
            new IdAttribute(new Name(null, 'Id'), self::DSIG),
            new IdAttribute(new Name(null, 'Id'), self::XENC),
        ]);
    }

    /**
     * The Loader every class of the package, the Verifier and the Signer are given, under the bounds of Core
     * (core.md section 7) the caller chooses.
     */
    public static function create(Limits $limits = new Limits()): Loader
    {
        return new Loader(self::idAttributes(), $limits);
    }
}
