<?php

/**
 * Maho
 *
 * @package    Mage_Eav
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Eav_Model_Resource_Form_Element_Collection extends Mage_Core_Model_Resource_Db_Collection_Abstract
{
    /**
     * Initialize collection model
     */
    #[\Override]
    protected function _construct()
    {
        $this->_init('eav/form_element');
    }

    /**
     * Add Form Type filter to collection
     *
     * @param Mage_Eav_Model_Form_Type|int $type
     * @return $this
     */
    public function addTypeFilter($type)
    {
        if ($type instanceof Mage_Eav_Model_Form_Type) {
            $type = $type->getId();
        }

        return $this->addFieldToFilter('type_id', $type);
    }

    /**
     * Add Form Fieldset filter to collection
     *
     * @param Mage_Eav_Model_Form_Fieldset|int $fieldset
     * @return $this
     */
    public function addFieldsetFilter($fieldset)
    {
        if ($fieldset instanceof Mage_Eav_Model_Form_Fieldset) {
            $fieldset = $fieldset->getId();
        }

        return $this->addFieldToFilter('fieldset_id', $fieldset);
    }

    /**
     * Add Attribute filter to collection
     *
     * @param Mage_Eav_Model_Entity_Attribute_Abstract|int $attribute
     *
     * @return $this
     */
    public function addAttributeFilter($attribute)
    {
        if ($attribute instanceof Mage_Eav_Model_Entity_Attribute_Abstract) {
            $attribute = $attribute->getId();
        }

        return $this->addFieldToFilter('attribute_id', $attribute);
    }

    /**
     * Set order by element sort order
     *
     * @return $this
     */
    public function setSortOrder()
    {
        $this->setOrder('sort_order', self::SORT_ORDER_ASC);

        return $this;
    }

    /**
     * Join attribute data
     *
     * @return $this
     */
    protected function _joinAttributeData()
    {
        $this->getSelect()->join(
            ['eav_attribute' => $this->getTable('eav/attribute')],
            'main_table.attribute_id = eav_attribute.attribute_id',
            ['attribute_code', 'entity_type_id'],
        );

        return $this;
    }

    #[\Override]
    public function load($printQuery = false, $logQuery = false)
    {
        if (!$this->isLoaded()) {
            $this->_joinAttributeData();
        }
        return parent::load($printQuery, $logQuery);
    }
}
