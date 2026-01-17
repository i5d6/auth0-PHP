<?php

return [
    'breaches' => [
        [
            'name' => 'ExampleCorp May 2023',
            'domain' => 'example.com',
            'breachDate' => '2023-05-21',
            'dataClasses' => [
                'Email addresses',
                'Names',
                'Phone numbers',
            ],
        ],
        [
            'name' => 'SampleShop January 2022',
            'domain' => 'sampleshop.test',
            'breachDate' => '2022-01-14',
            'dataClasses' => [
                'Email addresses',
                'Purchase history',
            ],
        ],
    ],
    // Demo-only list of hashed emails, using the default pepper.
    'demoHashes' => [
        '5a5f71f3bb102e798f93ef3e09ff9827ad529c4546767f1afe1ebad297ecffc7',
    ],
];
