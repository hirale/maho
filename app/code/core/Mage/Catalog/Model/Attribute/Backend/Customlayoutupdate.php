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

class Mage_Catalog_Model_Attribute_Backend_Customlayoutupdate extends Mage_Eav_Model_Entity_Attribute_Backend_Abstract
{
    /**
     * Product custom layout update attribute validate function.
     * In case invalid data throws exception.
     *
     * @param Varien_Object $object
     * @return bool
     * @throws Mage_Eav_Model_Entity_Attribute_Exception
     */
    #[\Override]
    public function validate($object)
    {
        $attributeName = $this->getAttribute()->getName();
        $xml = trim((string) $object->getData($attributeName));

        if (!$this->getAttribute()->getIsRequired() && empty($xml)) {
            return true;
        }

        /** @var Mage_Adminhtml_Model_LayoutUpdate_Validator $validator */
        $validator = Mage::getModel('adminhtml/layoutUpdate_validator');
        if (!$validator->isValid($xml)) {
            $messages = $validator->getMessages();
            // add first message to exception
            $massage = array_shift($messages);
            $eavExc = new Mage_Eav_Model_Entity_Attribute_Exception($massage);
            $eavExc->setAttributeCode($attributeName);
            throw $eavExc;
        }
        return true;
    }
}
