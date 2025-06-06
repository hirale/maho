<?php

/**
 * Maho
 *
 * @package    Mage_Core
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2024 The OpenMage Contributors (https://openmage.org)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * Block that can get data from layout or from registry.
 * Can compare its data values by specified keys
 */
class Mage_Core_Block_Template_Facade extends Mage_Core_Block_Template
{
    /**
     * Just set data, like Varien_Object
     *
     * This method is to be used in layout.
     * In layout it can be understood better, than setSomeKeyBlahBlah()
     *
     * @param string $key
     * @param string $value
     */
    public function setDataByKey($key, $value)
    {
        $this->_data[$key] = $value;
    }

    /**
     * Also set data, but take the value from registry by registry key
     *
     * @param string $key
     * @param string $registryKey
     */
    public function setDataByKeyFromRegistry($key, $registryKey)
    {
        $registryItem = Mage::registry($registryKey);
        if (empty($registryItem)) {
            return;
        }
        $value = $registryItem->getData($key);
        $this->setDataByKey($key, $value);
    }

    /**
     * Check if data values by specified keys are equal
     * $conditionKeys can be array or arbitrary set of params (func_get_args())
     *
     * @param array $conditionKeys
     * @return bool
     */
    public function ifEquals($conditionKeys)
    {
        $args = func_get_args();
        if (!is_array($conditionKeys)) {
            $conditionKeys = $args;
        }

        // evaluate conditions (equality)
        if (!empty($conditionKeys)) {
            foreach ($conditionKeys as $key) {
                if (!isset($this->_data[$key])) {
                    return false;
                }
            }
            $lastValue = $this->_data[$key];
            foreach ($conditionKeys as $key) {
                if ($this->_data[$key] !== $lastValue) {
                    return false;
                }
            }
        }
        return true;
    }
}
