<?php

/**
 * Maho
 *
 * @package    Mage_Catalog
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2024 The OpenMage Contributors (https://openmage.org)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Catalog_Model_Resource_Product_Attribute_Frontend_Image extends Mage_Eav_Model_Entity_Attribute_Frontend_Abstract
{
    public const IMAGE_PATH_SEGMENT = 'catalog/product/';

    /**
     * Retrieve image url
     * @param Varien_Object $object
     * @return string|false
     */
    public function getUrl($object)
    {
        $url   = false;
        $image = $object->getData($this->getAttribute()->getAttributeCode());
        if ($image) {
            $url = Mage::getBaseUrl('media') . self::IMAGE_PATH_SEGMENT . $image;
        }
        return $url;
    }
}
