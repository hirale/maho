<?php

/**
 * Maho
 *
 * @package    Mage_CatalogIndex
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_CatalogIndex_Model_Data_Configurable extends Mage_CatalogIndex_Model_Data_Abstract
{
    /**
     * Defines when product type has children
     *
     * @var int[]|bool[]
     */
    protected $_haveChildren = [
        Mage_CatalogIndex_Model_Retreiver::CHILDREN_FOR_TIERS => false,
        Mage_CatalogIndex_Model_Retreiver::CHILDREN_FOR_PRICES => false,
        Mage_CatalogIndex_Model_Retreiver::CHILDREN_FOR_ATTRIBUTES => true,
    ];

    /**
     * Defines when product type has parents
     *
     * @var bool
     */
    protected $_haveParents = false;

    #[\Override]
    protected function _construct()
    {
        $this->_init('catalogindex/data_configurable');
    }

    /**
      * Retrieve product type code
      *
      * @return string
      */
    #[\Override]
    public function getTypeCode()
    {
        return Mage_Catalog_Model_Product_Type::TYPE_CONFIGURABLE;
    }

    /**
     * Get child link table and field settings
     *
     * @return mixed
     */
    #[\Override]
    protected function _getLinkSettings()
    {
        return [
            'table' => 'catalog/product_super_link',
            'parent_field' => 'parent_id',
            'child_field' => 'product_id',
        ];
    }
}
