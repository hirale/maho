<?php

/**
 * Maho
 *
 * @package    Mage_Catalog
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * @method Mage_Catalog_Model_Resource_Product_Type_Configurable_Attribute _getResource()
 * @method Mage_Catalog_Model_Resource_Product_Type_Configurable_Attribute getResource()
 * @method Mage_Catalog_Model_Resource_Product_Type_Configurable_Attribute_Collection getCollection()
 *
 * @method string getAttributeCode()
 * @method int getAttributeId()
 * @method $this setAttributeId(int $value)
 * @method $this setLabel(string $value)
 * @method int getPosition()
 * @method $this setPosition(int $value)
 * @method array getPrices()
 * @method $this setPrices(array $value)
 * @method int getProductId()
 * @method $this setProductId(int $value)
 * @method Mage_Catalog_Model_Resource_Eav_Attribute getProductAttribute()
 * @method $this setProductAttribute(Mage_Catalog_Model_Resource_Eav_Attribute $value)
 * @method int getStoreId()
 * @method $this setStoreId(int $value)
 * @method int getUseDefault()
 * @method $this setUseDefault(int $value)
 * @method array getValues()
 */
class Mage_Catalog_Model_Product_Type_Configurable_Attribute extends Mage_Core_Model_Abstract
{
    #[\Override]
    protected function _construct()
    {
        $this->_init('catalog/product_type_configurable_attribute');
    }

    /**
     * Add price data to attribute
     *
     * @param array $priceData
     * @return $this
     */
    public function addPrice($priceData)
    {
        $data = $this->getPrices();
        if (is_null($data)) {
            $data = [];
        }
        $data[] = $priceData;
        $this->setPrices($data);
        return $this;
    }

    /**
     * Retrieve attribute label
     *
     * @return string
     */
    public function getLabel()
    {
        if ($this->getData('use_default') && $this->getProductAttribute()) {
            return $this->getProductAttribute()->getStoreLabel();
        } elseif (is_null($this->getData('label')) && $this->getProductAttribute()) {
            $this->setData('label', $this->getProductAttribute()->getStoreLabel());
        }

        return $this->getData('label');
    }

    /**
     * After save process
     *
     * @return $this
     */
    #[\Override]
    protected function _afterSave()
    {
        parent::_afterSave();
        $this->_getResource()->saveLabel($this);
        $this->_getResource()->savePrices($this);
        return $this;
    }
}
