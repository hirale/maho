<?php

/**
 * Maho
 *
 * @package    Mage_Widget
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Widget_Block_Adminhtml_Widget_Instance_Grid extends Mage_Adminhtml_Block_Widget_Grid
{
    /**
     * Internal constructor
     *
     */
    #[\Override]
    protected function _construct()
    {
        parent::_construct();
        $this->setId('widgetInstanceGrid');
        $this->setDefaultSort('title');
        $this->setDefaultDir('ASC');
    }

    #[\Override]
    protected function _prepareCollection()
    {
        /** @var Mage_Widget_Model_Resource_Widget_Instance_Collection $collection */
        $collection = Mage::getModel('widget/widget_instance')->getCollection();
        $this->setCollection($collection);
        return parent::_prepareCollection();
    }

    #[\Override]
    protected function _prepareColumns()
    {
        $this->addColumn('instance_id', [
            'header'    => Mage::helper('widget')->__('Widget ID'),
            'align'     => 'left',
            'index'     => 'instance_id',
        ]);

        $this->addColumn('title', [
            'header'    => Mage::helper('widget')->__('Widget Instance Title'),
            'align'     => 'left',
            'index'     => 'title',
        ]);

        $this->addColumn('type', [
            'header'    => Mage::helper('widget')->__('Type'),
            'align'     => 'left',
            'index'     => 'instance_type',
            'type'      => 'options',
            'options'   => $this->getTypesOptionsArray(),
        ]);

        $this->addColumn('package_theme', [
            'header'    => Mage::helper('widget')->__('Design Package/Theme'),
            'align'     => 'left',
            'index'     => 'package_theme',
            'type'      => 'theme',
            'with_empty' => true,
        ]);

        $this->addColumn('sort_order', [
            'header'    => Mage::helper('widget')->__('Sort Order'),
            'width'     => '100',
            'align'     => 'center',
            'index'     => 'sort_order',
        ]);

        return parent::_prepareColumns();
    }

    /**
     * Retrieve array (widget_type => widget_name) of available widgets
     *
     * @return array
     */
    public function getTypesOptionsArray()
    {
        $widgets = [];
        $widgetsOptionsArr = Mage::getModel('widget/widget_instance')->getWidgetsOptionArray();
        foreach ($widgetsOptionsArr as $widget) {
            $widgets[$widget['value']] = $widget['label'];
        }
        return $widgets;
    }

    /**
     * Retrieve design package/theme options array
     *
     * @return array
     */
    public function getPackageThemeOptionsArray()
    {
        $packageThemeArray = [];
        $packageThemeOptions = Mage::getModel('core/design_source_design')
            ->setIsFullLabel(true)->getAllOptions(false);
        foreach ($packageThemeOptions as $item) {
            if (is_array($item['value'])) {
                foreach ($item['value'] as $valueItem) {
                    $packageThemeArray[$valueItem['value']] = $valueItem['label'];
                }
            } else {
                $packageThemeArray[$item['value']] = $item['label'];
            }
        }
        return $packageThemeArray;
    }

    /**
     * Row click url
     *
     * @param Mage_Widget_Model_Widget_Instance $row
     * @return string
     */
    #[\Override]
    public function getRowUrl($row)
    {
        return $this->getUrl('*/*/edit', ['instance_id' => $row->getId()]);
    }
}
