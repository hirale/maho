<?php

/**
 * Maho
 *
 * @package    Mage_Catalog
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Catalog_Model_Api2_Product extends Mage_Api2_Model_Resource
{
    /**
     * Get available attributes of API resource
     *
     * @param string $userType
     * @param string $operation
     * @return array
     */
    #[\Override]
    public function getAvailableAttributes($userType, $operation)
    {
        $attributes = $this->getAvailableAttributesFromConfig();
        /** @var Mage_Eav_Model_Entity_Type $entityType */
        $entityType = Mage::getSingleton('eav/config')->getEntityType(Mage_Catalog_Model_Product::ENTITY);
        $entityOnlyAttrs = $this->getEntityOnlyAttributes($userType, $operation);
        /** @var Mage_Catalog_Model_Resource_Eav_Attribute $attribute */
        foreach ($entityType->getAttributeCollection() as $attribute) {
            if ($this->_isAttributeVisible($attribute, $userType)) {
                $attributes[$attribute->getAttributeCode()] = $attribute->getFrontendLabel();
            }
        }
        $excludedAttrs = $this->getExcludedAttributes($userType, $operation);
        $includedAttrs = $this->getIncludedAttributes($userType, $operation);
        foreach (array_keys($attributes) as $code) {
            if (in_array($code, $excludedAttrs) || ($includedAttrs && !in_array($code, $includedAttrs))) {
                unset($attributes[$code]);
            }
            if (in_array($code, $entityOnlyAttrs)) {
                $attributes[$code] .= ' *';
            }
        }

        return $attributes;
    }

    /**
     * Define if attribute should be visible for passed user type
     *
     * @param string $userType
     * @return bool
     */
    protected function _isAttributeVisible(Mage_Catalog_Model_Resource_Eav_Attribute $attribute, $userType)
    {
        $isAttributeVisible = false;
        if ($userType == Mage_Api2_Model_Auth_User_Admin::USER_TYPE) {
            $isAttributeVisible = $attribute->getIsVisible();
        } else {
            $systemAttributesForNonAdmin = [
                'sku', 'name', 'short_description', 'description', 'tier_price', 'meta_title', 'meta_description',
                'meta_keyword',
            ];
            if ($attribute->getIsUserDefined()) {
                $isAttributeVisible = $attribute->getIsVisibleOnFront();
            } elseif (in_array($attribute->getAttributeCode(), $systemAttributesForNonAdmin)) {
                $isAttributeVisible = true;
            }
        }
        return (bool) $isAttributeVisible;
    }
}
