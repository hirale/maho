<?php

/**
 * Maho
 *
 * @package    Mage_Oauth
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Oauth_Block_Adminhtml_Oauth_Consumer_Grid extends Mage_Adminhtml_Block_Widget_Grid
{
    /**
     * Allow edit status
     *
     * @var bool
     */
    protected $_editAllow = false;

    /**
     * Construct grid block
     */
    public function __construct()
    {
        parent::__construct();
        $this->setId('consumerGrid');
        $this->setUseAjax(true);
        $this->setSaveParametersInSession(true);
        $this->setDefaultSort('entity_id')
            ->setDefaultDir(Varien_Db_Select::SQL_DESC);

        /** @var Mage_Admin_Model_Session $session */
        $session = Mage::getSingleton('admin/session');
        $this->_editAllow = $session->isAllowed('system/oauth/consumer/edit');
    }

    #[\Override]
    protected function _prepareCollection()
    {
        $collection = Mage::getModel('oauth/consumer')->getCollection();
        $this->setCollection($collection);

        return parent::_prepareCollection();
    }

    #[\Override]
    protected function _prepareColumns()
    {
        $this->addColumn('entity_id', [
            'header' => Mage::helper('oauth')->__('ID'),
            'index' => 'entity_id',
        ]);

        $this->addColumn('name', [
            'header' => Mage::helper('oauth')->__('Consumer Name'), 'index' => 'name', 'escape' => true,
        ]);

        $this->addColumn('created_at', [
            'header' => Mage::helper('oauth')->__('Created At'), 'index' => 'created_at',
        ]);

        return parent::_prepareColumns();
    }

    /**
     * Get grid URL
     *
     * @return string
     */
    #[\Override]
    public function getGridUrl()
    {
        return $this->getUrl('*/*/grid', ['_current' => true]);
    }

    /**
     * Get row URL
     *
     * @param Mage_Oauth_Model_Consumer $row
     * @return string|null
     */
    #[\Override]
    public function getRowUrl($row)
    {
        if ($this->_editAllow) {
            return $this->getUrl('*/*/edit', ['id' => $row->getId()]);
        }
        return null;
    }
}
