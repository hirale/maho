<?php

/**
 * Maho
 *
 * @package    Mage_Directory
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2024 The OpenMage Contributors (https://openmage.org)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Directory_Model_Region_Api extends Mage_Api_Model_Resource_Abstract
{
    /**
     * Retrieve regions list
     *
     * @param string $country
     * @return array
     */
    public function items($country)
    {
        try {
            $country = Mage::getModel('directory/country')->loadByCode($country);
        } catch (Mage_Core_Exception $e) {
            $this->_fault('country_not_exists', $e->getMessage());
        }

        if (!$country->getId()) {
            $this->_fault('country_not_exists');
        }

        $result = [];
        foreach ($country->getRegions() as $region) {
            $result[] = [
                'region_id' => $region->getRegionId(),
                'code' => $region->getCode(),
                'name' => $region->getName(), //use the logic of default name
            ];
        }

        return $result;
    }
}
