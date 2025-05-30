<?php

/**
 * Maho
 *
 * @package    Mage_Api2
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2024 The OpenMage Contributors (https://openmage.org)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Api2_Model_Auth_User
{
    /**
     * Get options in "key-value" format
     *
     * @param bool $asOptionArray OPTIONAL If TRUE - return an options array, plain array - otherwise
     * @return array
     */
    public static function getUserTypes($asOptionArray = false)
    {
        $userTypes = [];

        /** @var Mage_Api2_Helper_Data $helper */
        $helper = Mage::helper('api2');

        foreach ($helper->getUserTypes() as $modelPath) {
            /** @var Mage_Api2_Model_Auth_User_Abstract $userModel */
            $userModel = Mage::getModel($modelPath);

            if ($asOptionArray) {
                $userTypes[] = ['value' => $userModel->getType(), 'label' => $userModel->getLabel()];
            } else {
                $userTypes[$userModel->getType()] = $userModel->getLabel();
            }
        }
        return $userTypes;
    }
}
