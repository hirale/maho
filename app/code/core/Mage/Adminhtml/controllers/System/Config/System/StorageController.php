<?php

/**
 * Maho
 *
 * @package    Mage_Adminhtml
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2025 The OpenMage Contributors (https://openmage.org)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Adminhtml_System_Config_System_StorageController extends Mage_Adminhtml_Controller_Action
{
    /**
     * ACL resource
     * @see Mage_Adminhtml_Controller_Action::_isAllowed()
     */
    public const ADMIN_RESOURCE = 'system/config';

    /**
     * Return file storage singleton
     *
     * @return Mage_Core_Model_File_Storage
     */
    protected function _getSyncSingleton()
    {
        return Mage::getSingleton('core/file_storage');
    }

    /**
     * Return synchronize process status flag
     *
     * @return Mage_Core_Model_File_Storage_Flag
     */
    protected function _getSyncFlag()
    {
        return $this->_getSyncSingleton()->getSyncFlag();
    }

    /**
     * Synchronize action between storages
     */
    public function synchronizeAction()
    {
        session_write_close();

        if (!isset($_REQUEST['storage'])) {
            return;
        }

        $flag = $this->_getSyncFlag();
        if ($flag && $flag->getState() == Mage_Core_Model_File_Storage_Flag::STATE_RUNNING
            && $flag->getLastUpdate()
            && time() <= (strtotime($flag->getLastUpdate()) + Mage_Core_Model_File_Storage_Flag::FLAG_TTL)
        ) {
            return;
        }

        $flag->setState(Mage_Core_Model_File_Storage_Flag::STATE_RUNNING)->save();
        Mage::getSingleton('admin/session')->setSyncProcessStopWatch(false);

        $storage = ['type' => (int) $_REQUEST['storage']];
        if (isset($_REQUEST['connection']) && !empty($_REQUEST['connection'])) {
            $storage['connection'] = $_REQUEST['connection'];
        }

        try {
            $this->_getSyncSingleton()->synchronize($storage);
        } catch (Exception $e) {
            Mage::logException($e);
            $flag->passError($e);
        }

        $flag->setState(Mage_Core_Model_File_Storage_Flag::STATE_FINISHED)->save();
    }

    /**
     * Retrieve synchronize process state and it's parameters in json format
     */
    public function statusAction()
    {
        $result = [];
        $flag = $this->_getSyncFlag();

        if ($flag) {
            $state = $flag->getState();

            switch ($state) {
                case Mage_Core_Model_File_Storage_Flag::STATE_INACTIVE:
                    $flagData = $flag->getFlagData();
                    if (is_array($flagData)) {
                        if (isset($flagData['destination']) && !empty($flagData['destination'])) {
                            $result['destination'] = $flagData['destination'];
                        }
                    }

                    $state = Mage_Core_Model_File_Storage_Flag::STATE_INACTIVE;
                    break;
                case Mage_Core_Model_File_Storage_Flag::STATE_RUNNING:
                    if (!$flag->getLastUpdate()
                        || time() <= (strtotime($flag->getLastUpdate()) + Mage_Core_Model_File_Storage_Flag::FLAG_TTL)
                    ) {
                        $flagData = $flag->getFlagData();
                        if (is_array($flagData)
                            && isset($flagData['source']) && !empty($flagData['source'])
                            && isset($flagData['destination']) && !empty($flagData['destination'])
                        ) {
                            $result['message'] = Mage::helper('adminhtml')->__('Synchronizing %s to %s', $flagData['source'], $flagData['destination']);
                        } else {
                            $result['message'] = Mage::helper('adminhtml')->__('Synchronizing...');
                        }

                        break;
                    } else {
                        $flagData = $flag->getFlagData();
                        if (is_array($flagData)
                            && !(isset($flagData['timeout_reached']) && $flagData['timeout_reached'])
                        ) {
                            Mage::logException(new Mage_Core_Exception(
                                Mage::helper('adminhtml')->__('Timeout limit for response from synchronize process was reached.'),
                            ));

                            $state = Mage_Core_Model_File_Storage_Flag::STATE_FINISHED;

                            $flagData['has_errors']         = true;
                            $flagData['timeout_reached']    = true;

                            $flag->setState($state)
                                ->setFlagData($flagData)
                                ->save();
                        }
                    }
                    // no break
                case Mage_Core_Model_File_Storage_Flag::STATE_FINISHED:
                    Mage::dispatchEvent('add_synchronize_message');

                    $state = Mage_Core_Model_File_Storage_Flag::STATE_NOTIFIED;
                    // no break
                case Mage_Core_Model_File_Storage_Flag::STATE_NOTIFIED:
                    $block = Mage::getSingleton('core/layout')
                        ->createBlock('adminhtml/notification_toolbar')
                        ->setTemplate('notification/toolbar.phtml');
                    $result['html'] = $block->toHtml();

                    $flagData = $flag->getFlagData();
                    if (is_array($flagData)) {
                        if (isset($flagData['has_errors']) && $flagData['has_errors']) {
                            $result['has_errors'] = true;
                        }
                    }

                    break;
                default:
                    $state = Mage_Core_Model_File_Storage_Flag::STATE_INACTIVE;
                    break;
            }
        } else {
            $state = Mage_Core_Model_File_Storage_Flag::STATE_INACTIVE;
        }
        $result['state'] = $state;

        $result = Mage::helper('core')->jsonEncode($result);
        Mage::app()->getResponse()->setBody($result);
    }
}
