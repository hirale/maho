<?php

/**
 * Maho
 *
 * @package    Mage_Eav
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * Entity/Attribute/Model - attribute selection source from configuration
 * This class should be abstract, but kept usual for legacy purposes
 */
class Mage_Eav_Model_Entity_Attribute_Source_Config extends Mage_Eav_Model_Entity_Attribute_Source_Abstract
{
    /**
     * Config Node Path
     *
     * @var Mage_Core_Model_Config_Element
     */
    protected $_configNodePath;

    /**
     * Retrieve all options for the source from configuration
     *
     * @throws Mage_Eav_Exception
     * @return array
     */
    #[\Override]
    public function getAllOptions()
    {
        if ($this->_options === null) {
            $this->_options = [];
            $rootNode = null;
            if ($this->_configNodePath) {
                $rootNode = Mage::getConfig()->getNode($this->_configNodePath);
            }
            if (!$rootNode) {
                throw Mage::exception('Mage_Eav', Mage::helper('eav')->__('Failed to load node %s from config', $this->_configNodePath));
            }
            $options = $rootNode->children();
            if (empty($options)) {
                throw Mage::exception('Mage_Eav', Mage::helper('eav')->__('No options found in config node %s', $this->_configNodePath));
            }
            foreach ($options as $option) {
                $this->_options[] = [
                    'value' => (string) $option->value,
                    'label' => Mage::helper('eav')->__((string) $option->label),
                ];
            }
        }

        return $this->_options;
    }
}
