<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model;

use Beffroi\Xml\Core\IdAttribute;
use Beffroi\Xml\Core\IdAttributes;
use Beffroi\Xml\Core\Limits;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Name;

/**
 * The Verifier and the Signer load through it too, so that the SAML, XML Signature and XML Encryption identifiers
 * of a document form one space, and a value that appears twice refuses the document (M-14, core.md I-8).
 */
final class SamlLoader
{
    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    private const string XENC = 'http://www.w3.org/2001/04/xmlenc#';

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

    public static function create(Limits $limits = new Limits()): Loader
    {
        return new Loader(self::idAttributes(), $limits);
    }
}
