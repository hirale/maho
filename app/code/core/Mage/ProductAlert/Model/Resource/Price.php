<?php

/**
 * Maho
 *
 * @package    Mage_ProductAlert
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_ProductAlert_Model_Resource_Price extends Mage_ProductAlert_Model_Resource_Abstract
{
    #[\Override]
    protected function _construct()
    {
        $this->_init('productalert/price', 'alert_price_id');
    }

    /**
     * Before save process, check exists the same alert
     *
     * @param Mage_ProductAlert_Model_Price $object
     */
    #[\Override]
    protected function _beforeSave(Mage_Core_Model_Abstract $object)
    {
        if (is_null($object->getId()) && $object->getCustomerId()
                && $object->getProductId() && $object->getWebsiteId()
        ) {
            if ($row = $this->_getAlertRow($object)) {
                $price = $object->getPrice();
                $object->addData($row);
                if ($price) {
                    $object->setPrice($price);
                }
                $object->setStatus(0);
            }
        }
        if (is_null($object->getAddDate())) {
            $object->setAddDate(Mage::getModel('core/date')->gmtDate());
        }
        return parent::_beforeSave($object);
    }
}
