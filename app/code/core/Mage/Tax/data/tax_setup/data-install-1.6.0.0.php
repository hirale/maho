<?php

/**
 * Maho
 *
 * @package    Mage_Tax
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/** @var Mage_Tax_Model_Resource_Setup $this */
$installer = $this;

/**
 * install tax classes
 */
$data = [
    [
        'class_id'     => 2,
        'class_name'   => 'Taxable Goods',
        'class_type'   => Mage_Tax_Model_Class::TAX_CLASS_TYPE_PRODUCT,
    ],
    [
        'class_id'     => 3,
        'class_name'   => 'Retail Customer',
        'class_type'   => Mage_Tax_Model_Class::TAX_CLASS_TYPE_CUSTOMER,
    ],
    [
        'class_id'     => 4,
        'class_name'   => 'Shipping',
        'class_type'   => Mage_Tax_Model_Class::TAX_CLASS_TYPE_PRODUCT,
    ],
];
foreach ($data as $row) {
    $installer->getConnection()->insertForce($installer->getTable('tax/tax_class'), $row);
}

/**
 * install tax calculation rule
 */
$data = [
    'tax_calculation_rule_id'   => 1,
    'code'                      => 'Retail Customer-Taxable Goods-Rate 1',
    'priority'                  => 1,
    'position'                  => 1,
];
$installer->getConnection()->insertForce($installer->getTable('tax/tax_calculation_rule'), $data);

/**
 * install tax calculation rates
 */
$data = [
    [
        'tax_calculation_rate_id'   => 1,
        'tax_country_id'            => 'US',
        'tax_region_id'             => 12,
        'tax_postcode'              => '*',
        'code'                      => 'US-CA-*-Rate 1',
        'rate'                      => '8.2500',
    ],
    [
        'tax_calculation_rate_id'   => 2,
        'tax_country_id'            => 'US',
        'tax_region_id'             => 43,
        'tax_postcode'              => '*',
        'code'                      => 'US-NY-*-Rate 1',
        'rate'                      => '8.3750',
    ],
];
foreach ($data as $row) {
    $installer->getConnection()->insertForce($installer->getTable('tax/tax_calculation_rate'), $row);
}

/**
 * install tax calculation
 */
$data = [
    [
        'tax_calculation_rate_id'   => 1,
        'tax_calculation_rule_id'   => 1,
        'customer_tax_class_id'     => 3,
        'product_tax_class_id'      => 2,
    ],
    [
        'tax_calculation_rate_id'   => 2,
        'tax_calculation_rule_id'   => 1,
        'customer_tax_class_id'     => 3,
        'product_tax_class_id'      => 2,
    ],
];
$installer->getConnection()->insertMultiple($installer->getTable('tax/tax_calculation'), $data);
