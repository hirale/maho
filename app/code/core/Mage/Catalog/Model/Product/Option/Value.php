<?php

/**
 * Maho
 *
 * @package    Mage_Catalog
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2023 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * @method Mage_Catalog_Model_Resource_Product_Option_Value_Collection getCollection()
 * @method Mage_Catalog_Model_Resource_Product_Option_Value _getResource()
 * @method Mage_Catalog_Model_Resource_Product_Option_Value getResource()
 * @method int|null getOptionId()
 * @method $this setOptionId(int|null $value)
 * @method int|null getOptionTypeId()
 * @method $this setOptionTypeId(int|null $value)
 * @method string getPriceType()
 * @method string getSku()
 * @method $this setSku(string $value)
 * @method int getSortOrder()
 * @method $this setSortOrder(int $value)
 * @method float getStorePrice()
 * @method string getStoreTitle()
 * @method string getTitle()
 */
class Mage_Catalog_Model_Product_Option_Value extends Mage_Core_Model_Abstract
{
    protected $_values = [];

    protected $_product;

    protected $_option;

    #[\Override]
    protected function _construct()
    {
        $this->_init('catalog/product_option_value');
    }

    /**
     * @param array $value
     * @return $this
     */
    public function addValue($value)
    {
        $this->_values[] = $value;
        return $this;
    }

    /**
     * @return array
     */
    public function getValues()
    {
        return $this->_values;
    }

    /**
     * @param array $values
     * @return $this
     */
    public function setValues($values)
    {
        $this->_values = $values;
        return $this;
    }

    /**
     * @return $this
     */
    public function unsetValues()
    {
        $this->_values = [];
        return $this;
    }

    /**
     * @return $this
     */
    public function setOption(Mage_Catalog_Model_Product_Option $option)
    {
        $this->_option = $option;
        return $this;
    }

    /**
     * @return $this
     */
    public function unsetOption()
    {
        $this->_option = null;
        return $this;
    }

    /**
     * @return Mage_Catalog_Model_Product_Option
     */
    public function getOption()
    {
        return $this->_option;
    }

    /**
     * @param Mage_Catalog_Model_Product $product
     * @return $this
     */
    public function setProduct($product)
    {
        $this->_product = $product;
        return $this;
    }

    /**
     * @return Mage_Catalog_Model_Product
     */
    public function getProduct()
    {
        if (is_null($this->_product)) {
            $this->_product = $this->getOption()->getProduct();
        }
        return $this->_product;
    }

    /**
     * @return $this
     * @throws Exception
     */
    public function saveValues()
    {
        foreach ($this->getValues() as $value) {
            $this->setData($value)
                ->setData('option_id', $this->getOption()->getId())
                ->setData('store_id', $this->getOption()->getStoreId());

            if ($this->getData('option_type_id') == '-1') {//change to 0
                $this->unsetData('option_type_id');
            } else {
                $this->setId($this->getData('option_type_id'));
            }

            if ($this->getData('is_delete') == '1') {
                if ($this->getId()) {
                    $this->deleteValues($this->getId());
                    $this->delete();
                }
            } else {
                $this->save();
            }
        }//eof foreach()
        return $this;
    }

    /**
     * Return price. If $flag is true and price is percent
     *  return converted percent to price
     *
     * @param bool $flag
     * @return float|int
     */
    public function getPrice($flag = false)
    {
        if ($flag && $this->getPriceType() == 'percent') {
            $basePrice = $this->getOption()->getProduct()->getFinalPrice();
            return $basePrice * ($this->_getData('price') / 100);
        }
        return $this->_getData('price');
    }

    /**
     * @return Mage_Catalog_Model_Resource_Product_Option_Value_Collection
     */
    public function getValuesCollection(Mage_Catalog_Model_Product_Option $option)
    {
        return Mage::getResourceModel('catalog/product_option_value_collection')
            ->addFieldToFilter('option_id', $option->getId())
            ->getValues($option->getStoreId());
    }

    /**
     * @param array $optionIds
     * @param int $optionId
     * @param int $storeId
     * @return Mage_Catalog_Model_Resource_Product_Option_Value_Collection
     */
    public function getValuesByOption($optionIds, $optionId, $storeId)
    {
        return Mage::getResourceModel('catalog/product_option_value_collection')
            ->addFieldToFilter('option_id', $optionId)
            ->getValuesByOption($optionIds, $storeId);
    }

    /**
     * @param int|string $optionId
     * @return $this
     */
    public function deleteValue($optionId)
    {
        $this->getResource()->deleteValue($optionId);
        return $this;
    }

    /**
     * @param int $optionTypeId
     * @return $this
     */
    public function deleteValues($optionTypeId)
    {
        $this->getResource()->deleteValues($optionTypeId);
        return $this;
    }

    /**
     * Prepare array of option values for duplicate
     *
     * @return array
     */
    public function prepareValueForDuplicate()
    {
        $this->setOptionId(null);
        $this->setOptionTypeId(null);

        return $this->__toArray();
    }

    /**
     * Duplicate product options value
     *
     * @param int $oldOptionId
     * @param int $newOptionId
     * @return $this
     */
    public function duplicate($oldOptionId, $newOptionId)
    {
        $this->getResource()->duplicate($this, $oldOptionId, $newOptionId);
        return $this;
    }
}
