<?php

// The authentication sources SimpleSAMLphp 2.5.3.1 distributes, and its commented example-userpass source enabled
// with one disposable test user, the dist's own.
require '/var/simplesamlphp/config-dist/authsources.php.dist';

$config['example-userpass'] = [
    'exampleauth:UserPass',
    'users' => [
        'student:studentpass' => [
            'uid' => ['test'],
            'eduPersonAffiliation' => ['member', 'student'],
        ],
    ],
];
