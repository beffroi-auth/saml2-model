<?php

declare(strict_types=1);

/*
 * Prints, as Markdown tables, the measurements of the SAML documents of a directory that match a glob, for the
 * measurements table of tests/Interop/simplesamlphp/README.md: sizes, what is signed and how, the windows against
 * IssueInstant, the fractional digits of the times, the NameID, the attributes, the audiences, the metadata roles.
 * Plain DOM, by direct children, nothing of SimpleSAMLphp. Run from the root of the repository:
 *   docker run --rm -v "$PWD:/project:ro" -w /project ghcr.io/spomky-labs/phpqa:8.4 \
 *       php tests/Interop/simplesamlphp/measure.php tests/Fixture/real 'simplesamlphp-*.xml'
 */

const SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
const SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
const MD = 'urn:oasis:names:tc:SAML:2.0:metadata';
const DS = 'http://www.w3.org/2000/09/xmldsig#';
const XSI = 'http://www.w3.org/2001/XMLSchema-instance';
const EC = 'http://www.w3.org/2001/10/xml-exc-c14n#';

$files = glob(rtrim($argv[1] ?? '.', '/') . '/' . ($argv[2] ?? '*.xml')) ?: [];
sort($files);

$messages = [];
$assertions = [];
$metadata = [];
foreach ($files as $file) {
    $document = new DOMDocument();
    $document->loadXML((string) file_get_contents($file));
    $root = $document->documentElement;
    $name = '`' . basename($file) . '`';
    $bytes = number_format(filesize($file), 0, '.', ' ');
    if ($root->localName === 'EntityDescriptor') {
        $metadata[] = metadataRow($name, $bytes, $root);
        continue;
    }
    $messages[] = messageRow($name, $bytes, $root);
    foreach (children($root, SAML, 'Assertion') as $assertion) {
        $assertions[] = assertionRow($name, $assertion);
    }
}

table(['Document', 'Bytes', 'Root', 'XML signatures', 'Signature, digest, canonicalization', 'PrefixList', 'Times, fractional digits', 'ID', 'Destination', 'Issuer Format', 'Other'], $messages);
table(['Response', 'NameID', 'Conditions NotBefore, NotOnOrAfter', 'Bearer NotOnOrAfter', 'SessionNotOnOrAfter', 'AudienceRestriction (Audience)', 'SessionIndex', 'Attributes, most values', 'NameFormat', 'xsi:type on values', 'AuthnContextClassRef'], $assertions);
table(['Metadata', 'Bytes', 'entityID length', 'Role, flags', 'KeyDescriptor', 'Endpoints', 'NameIDFormat', 'Other'], $metadata);

/** @return list<string> */
function messageRow(string $name, string $bytes, DOMElement $root): array
{
    $signed = [];
    $algorithms = [];
    $prefixLists = [];
    foreach ([$root, ...children($root, SAML, 'Assertion')] as $element) {
        foreach (children($element, DS, 'Signature') as $signature) {
            $signed[] = $element->localName;
            $algorithms[] = signatureAlgorithms($signature);
            $prefixLists = [...$prefixLists, ...prefixLists($signature)];
        }
    }
    $issuer = children($root, SAML, 'Issuer')[0] ?? null;
    $other = [];
    foreach ($root->attributes as $attribute) {
        if (!in_array($attribute->name, ['ID', 'Version', 'IssueInstant', 'Destination', 'InResponseTo'], true)) {
            $other[] = $attribute->name . '="' . $attribute->value . '"';
        }
    }
    foreach ($root->childNodes as $child) {
        if ($child instanceof DOMElement && !in_array($child->localName, ['Issuer', 'Signature', 'Status', 'Assertion'], true)) {
            $other[] = $child->localName . attributesOf($child);
        }
    }
    if ($root->localName === 'Response' || $root->localName === 'LogoutResponse') {
        $status = children(children($root, SAMLP, 'Status')[0], SAMLP, 'StatusCode')[0]->getAttribute('Value');
        $other[] = 'status ' . substr($status, strrpos($status, ':') + 1);
    }

    return [
        $name,
        $bytes,
        $root->localName,
        $signed === [] ? 'none' : implode(', ', $signed),
        $algorithms === [] ? '' : implode('; ', array_unique($algorithms)),
        $signed === [] ? '' : ($prefixLists === [] ? 'none' : implode('; ', $prefixLists)),
        (string) maxFraction($root),
        idForm($root->getAttribute('ID')),
        $root->hasAttribute('Destination') ? 'present' : 'absent',
        $issuer === null ? 'no Issuer' : ($issuer->hasAttribute('Format') ? $issuer->getAttribute('Format') : 'omitted'),
        implode(', ', $other),
    ];
}

/** @return list<string> */
function assertionRow(string $name, DOMElement $assertion): array
{
    $issueInstant = seconds($assertion->getAttribute('IssueInstant'));
    $subject = children($assertion, SAML, 'Subject')[0];
    $nameId = children($subject, SAML, 'NameID')[0];
    $data = children(children($subject, SAML, 'SubjectConfirmation')[0], SAML, 'SubjectConfirmationData')[0];
    $conditions = children($assertion, SAML, 'Conditions')[0];
    $authn = children($assertion, SAML, 'AuthnStatement')[0];
    $restrictions = children($conditions, SAML, 'AudienceRestriction');
    $audiences = array_sum(array_map(static fn (DOMElement $r): int => count(children($r, SAML, 'Audience')), $restrictions));
    $attributes = [];
    $formats = [];
    $types = [];
    foreach (children($assertion, SAML, 'AttributeStatement') as $statement) {
        foreach (children($statement, SAML, 'Attribute') as $attribute) {
            $values = children($attribute, SAML, 'AttributeValue');
            $attributes[] = count($values);
            $formats[$attribute->getAttribute('NameFormat') ?: 'omitted'] = true;
            foreach ($values as $value) {
                $types[$value->getAttributeNS(XSI, 'type') ?: 'none'] = true;
            }
        }
    }
    $classRef = children(children($authn, SAML, 'AuthnContext')[0], SAML, 'AuthnContextClassRef')[0] ?? null;

    return [
        $name,
        sprintf('%s, %d characters%s', formatName($nameId->getAttribute('Format')), strlen($nameId->textContent), qualifiers($nameId)),
        sprintf('%s, %s', delta($conditions, 'NotBefore', $issueInstant), delta($conditions, 'NotOnOrAfter', $issueInstant)),
        delta($data, 'NotOnOrAfter', $issueInstant) . ($data->hasAttribute('NotBefore') ? ', NotBefore present' : ''),
        delta($authn, 'SessionNotOnOrAfter', $issueInstant) . ' (AuthnInstant ' . delta($authn, 'AuthnInstant', $issueInstant) . ')',
        sprintf('%d (%d)', count($restrictions), $audiences),
        $authn->hasAttribute('SessionIndex') ? strlen($authn->getAttribute('SessionIndex')) . ' characters' : 'absent',
        sprintf('%d, %d', count($attributes), $attributes === [] ? 0 : max($attributes)),
        implode(', ', array_map('formatName', array_keys($formats))),
        implode(', ', array_keys($types)),
        $classRef === null ? 'absent' : formatName($classRef->textContent),
    ];
}

/** @return list<string> */
function metadataRow(string $name, string $bytes, DOMElement $root): array
{
    $roles = [];
    $keys = [];
    $endpoints = [];
    $formats = [];
    $other = [];
    foreach ($root->attributes as $attribute) {
        if ($attribute->name !== 'entityID') {
            $other[] = $attribute->name;
        }
    }
    foreach ($root->childNodes as $role) {
        if (!$role instanceof DOMElement) {
            continue;
        }
        if ($role->localName === 'Signature') {
            $other[] = 'Signature first child: ' . signatureAlgorithms($role) . ', PrefixList ' . (prefixLists($role) === [] ? 'none' : implode(' ', prefixLists($role)));
            continue;
        }
        $flags = [];
        foreach (['AuthnRequestsSigned', 'WantAssertionsSigned', 'WantAuthnRequestsSigned'] as $flag) {
            if ($role->hasAttribute($flag)) {
                $flags[] = $flag . '="' . $role->getAttribute($flag) . '"';
            }
        }
        $roles[] = $role->localName . ($flags === [] ? '' : ' ' . implode(' ', $flags));
        foreach ($role->childNodes as $child) {
            if (!$child instanceof DOMElement) {
                continue;
            }
            match ($child->localName) {
                'KeyDescriptor' => $keys[] = ($child->getAttribute('use') ?: 'no use') . ' (' . count($child->getElementsByTagNameNS(DS, 'X509Certificate')) . ' certificate)',
                'SingleSignOnService', 'SingleLogoutService', 'AssertionConsumerService' => $endpoints[] = $child->localName . ' ' . formatName($child->getAttribute('Binding')) . ($child->hasAttribute('index') ? ' index ' . $child->getAttribute('index') : ''),
                'NameIDFormat' => $formats[] = formatName($child->textContent),
                default => $other[] = $role->localName . '/' . $child->localName,
            };
        }
        foreach ($role->attributes as $attribute) {
            if (!in_array($attribute->name, ['protocolSupportEnumeration', 'AuthnRequestsSigned', 'WantAssertionsSigned', 'WantAuthnRequestsSigned'], true)) {
                $other[] = $role->localName . '@' . $attribute->name;
            }
        }
    }

    return [$name, $bytes, (string) strlen($root->getAttribute('entityID')), implode('; ', $roles), implode(', ', $keys), implode(', ', $endpoints), implode(', ', $formats), implode(', ', $other)];
}

/** @return list<DOMElement> */
function children(DOMElement $element, string $namespace, string $localName): array
{
    $children = [];
    foreach ($element->childNodes as $child) {
        if ($child instanceof DOMElement && $child->namespaceURI === $namespace && $child->localName === $localName) {
            $children[] = $child;
        }
    }

    return $children;
}

function signatureAlgorithms(DOMElement $signature): string
{
    $signedInfo = children($signature, DS, 'SignedInfo')[0];
    $method = children($signedInfo, DS, 'SignatureMethod')[0]->getAttribute('Algorithm');
    $c14n = children($signedInfo, DS, 'CanonicalizationMethod')[0]->getAttribute('Algorithm');
    $digests = [];
    $transforms = [];
    foreach (children($signedInfo, DS, 'Reference') as $reference) {
        $digests[] = formatName(children($reference, DS, 'DigestMethod')[0]->getAttribute('Algorithm'));
        foreach (children($reference, DS, 'Transforms') as $list) {
            foreach (children($list, DS, 'Transform') as $transform) {
                $transforms[] = formatName($transform->getAttribute('Algorithm'));
            }
        }
    }

    return sprintf('%s, %s, %s (transforms %s)', formatName($method), implode(' ', $digests), formatName($c14n), implode(' ', $transforms));
}

/** @return list<string> */
function prefixLists(DOMElement $signature): array
{
    $lists = [];
    foreach ($signature->getElementsByTagNameNS(EC, 'InclusiveNamespaces') as $inclusive) {
        $lists[] = '"' . $inclusive->getAttribute('PrefixList') . '"';
    }

    return $lists;
}

function maxFraction(DOMElement $root): int
{
    $max = 0;
    foreach ((new DOMXPath($root->ownerDocument))->query('//@*') as $attribute) {
        if (preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.(\d+))?Z$/', $attribute->value, $m) === 1) {
            $max = max($max, strlen($m[1] ?? ''));
        }
    }

    return $max;
}

function seconds(string $time): int
{
    return (new DateTimeImmutable($time))->getTimestamp();
}

function delta(DOMElement $element, string $attribute, int $issueInstant): string
{
    if (!$element->hasAttribute($attribute)) {
        return 'absent';
    }
    $delta = seconds($element->getAttribute($attribute)) - $issueInstant;

    return ($delta >= 0 ? '+' : '') . $delta . ' s';
}

function idForm(string $id): string
{
    if (preg_match('/^_[0-9a-f]+$/', $id) === 1) {
        return sprintf('`_` and %d hexadecimal digits', strlen($id) - 1);
    }

    return sprintf('%d characters', strlen($id));
}

function formatName(string $uri): string
{
    return preg_replace('#^.*[:\#/]#', '', rtrim($uri, '#'));
}

function qualifiers(DOMElement $nameId): string
{
    $present = array_values(array_filter(['NameQualifier', 'SPNameQualifier', 'SPProvidedID'], static fn (string $a): bool => $nameId->hasAttribute($a)));

    return $present === [] ? '' : ', ' . implode(', ', $present);
}

function attributesOf(DOMElement $element): string
{
    $attributes = [];
    foreach ($element->attributes as $attribute) {
        $attributes[] = $attribute->name;
    }

    return $attributes === [] ? '' : ' (' . implode(' ', $attributes) . ')';
}

/**
 * @param list<string>       $headers
 * @param list<list<string>> $rows
 */
function table(array $headers, array $rows): void
{
    if ($rows === []) {
        return;
    }
    echo '| ', implode(' | ', $headers), " |\n|", str_repeat('---|', count($headers)), "\n";
    foreach ($rows as $row) {
        echo '| ', implode(' | ', array_map(static fn (string $cell): string => str_replace('|', '\|', $cell), $row)), " |\n";
    }
    echo "\n";
}
