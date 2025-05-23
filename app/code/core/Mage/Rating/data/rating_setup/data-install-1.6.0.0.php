<?php

/**
 * Maho
 *
 * @package    Mage_Rating
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/** @var Mage_Core_Model_Resource_Setup $this */
$installer = $this;

$data = [
    Mage_Rating_Model_Rating::ENTITY_PRODUCT_CODE       => [
        [
            'rating_code'   => 'Quality',
            'position'      => 0,
        ],
        [
            'rating_code'   => 'Value',
            'position'      => 0,
        ],
        [
            'rating_code'   => 'Price',
            'position'      => 0,
        ],
    ],
    Mage_Rating_Model_Rating::ENTITY_PRODUCT_REVIEW_CODE    => [
    ],
    Mage_Rating_Model_Rating::ENTITY_REVIEW_CODE            => [
    ],
];

foreach ($data as $entityCode => $ratings) {
    //Fill table rating/rating_entity
    $installer->getConnection()
        ->insert($installer->getTable('rating_entity'), ['entity_code' => $entityCode]);
    $entityId = $installer->getConnection()->lastInsertId($installer->getTable('rating_entity'));

    foreach ($ratings as $bind) {
        //Fill table rating/rating
        $bind['entity_id'] = $entityId;
        $installer->getConnection()->insert($installer->getTable('rating'), $bind);

        //Fill table rating/rating_option
        $ratingId = $installer->getConnection()->lastInsertId($installer->getTable('rating'));
        $optionData = [];
        for ($i = 1; $i <= 5; $i++) {
            $optionData[] = [
                'rating_id' => $ratingId,
                'code'      => (string) $i,
                'value'     => $i,
                'position'  => $i,
            ];
        }
        $installer->getConnection()->insertMultiple($installer->getTable('rating_option'), $optionData);
    }
}
