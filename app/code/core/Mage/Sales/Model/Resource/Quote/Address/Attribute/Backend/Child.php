<?php

/**
 * Maho
 *
 * @package    Mage_Sales
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Sales_Model_Resource_Quote_Address_Attribute_Backend_Child extends Mage_Eav_Model_Entity_Attribute_Backend_Abstract
{
    /**
     * Set store id to the attribute
     *
     * @param Varien_Object $object
     * @return $this
     */
    #[\Override]
    public function beforeSave($object)
    {
        if ($object->getAddress()) {
            $object->setParentId($object->getAddress()->getId())
                ->setStoreId($object->getAddress()->getStoreId());
        }
        parent::beforeSave($object);
        return $this;
    }
}
