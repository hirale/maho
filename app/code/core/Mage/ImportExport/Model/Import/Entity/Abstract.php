<?php

/**
 * Maho
 *
 * @package    Mage_ImportExport
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

abstract class Mage_ImportExport_Model_Import_Entity_Abstract
{
    /**
     * Database constants
     *
     */
    public const DB_MAX_PACKET_COEFFICIENT = 900000;
    public const DB_MAX_PACKET_DATA        = 1048576;
    public const DB_MAX_VARCHAR_LENGTH     = 256;
    public const DB_MAX_TEXT_LENGTH        = 65536;

    /**
     * DB connection.
     *
     * @var Varien_Db_Adapter_Pdo_Mysql
     */
    protected $_connection;

    /**
     * Has data process validation done?
     *
     * @var bool
     */
    protected $_dataValidated = false;

    /**
     * DB data source model.
     *
     * @var Mage_ImportExport_Model_Resource_Import_Data
     */
    protected $_dataSourceModel;

    /**
     * Entity type id.
     *
     * @var int|null
     */
    protected $_entityTypeId;

    /**
     * Error codes with arrays of corresponding row numbers.
     *
     * @var array
     */
    protected $_errors = [];

    /**
     * Error counter.
     *
     * @var int
     */
    protected $_errorsCount = 0;

    /**
     * Limit of errors after which pre-processing will exit.
     *
     * @var int
     */
    protected $_errorsLimit = 100;

    /**
     * Flag to disable import.
     *
     * @var bool
     */
    protected $_importAllowed = true;

    /**
     * Attributes with index (not label) value.
     *
     * @var array
     */
    protected $_indexValueAttributes = [];

    /**
     * Array of invalid rows numbers.
     *
     * @var array
     */
    protected $_invalidRows = [];

    /**
     * Validation failure message template definitions.
     *
     * @var array
     */
    protected $_messageTemplates = [];

    /**
     * Notice messages.
     *
     * @var array
     */
    protected $_notices = [];

    /**
     * Entity model parameters.
     *
     * @var array
     */
    protected $_parameters = [];

    /**
     * Column names that holds values with particular meaning.
     *
     * @var array
     */
    protected $_particularAttributes = [];

    /**
     * Permanent entity columns.
     *
     * @var array
     */
    protected $_permanentAttributes = [];

    /**
     * Number of entities processed by validation.
     *
     * @var int
     */
    protected $_processedEntitiesCount = 0;

    /**
     * Number of rows processed by validation.
     *
     * @var int
     */
    protected $_processedRowsCount = 0;

    /**
     * Rows to skip. Valid rows but we have some reasons to skip them.
     *
     * [Row number 1] => true,
     * ...
     * [Row number N] => true
     *
     * @var array
     */
    protected $_rowsToSkip = [];

    /**
     * Array of numbers of validated rows as keys and boolean TRUE as values.
     *
     * @var array
     */
    protected $_validatedRows = [];

    /**
     * Source model.
     *
     * @var Mage_ImportExport_Model_Import_Adapter_Abstract
     */
    protected $_source;

    /**
     * Array of unique attributes
     *
     * @var array
     */
    protected $_uniqueAttributes = [];

    public function __construct()
    {
        $entityType             = Mage::getSingleton('eav/config')->getEntityType($this->getEntityTypeCode());
        $this->_entityTypeId    = $entityType->getEntityTypeId();
        $this->_dataSourceModel = Mage_ImportExport_Model_Import::getDataSourceModel();

        /** @var Varien_Db_Adapter_Pdo_Mysql $_connection */
        $_connection            = Mage::getSingleton('core/resource')->getConnection('write');
        $this->_connection      = $_connection;
    }

    /**
     * Inner source object getter.
     *
     * @return Mage_ImportExport_Model_Import_Adapter_Abstract
     */
    protected function _getSource()
    {
        if (!$this->_source) {
            Mage::throwException(Mage::helper('importexport')->__('No source specified'));
        }
        return $this->_source;
    }

    /**
     * Import data rows.
     *
     * @abstract
     * @return bool
     */
    abstract protected function _importData();

    /**
     * Returns boolean TRUE if row scope is default (fundamental) scope.
     *
     * @return true
     */
    protected function _isRowScopeDefault(array $rowData)
    {
        return true;
    }

    /**
     * Change row data before saving in DB table.
     *
     * @return array
     */
    protected function _prepareRowForDb(array $rowData)
    {
        /**
         * Convert all empty strings to null values, as
         * a) we don't use empty string in DB
         * b) empty strings instead of numeric values will product errors in Sql Server
         */
        foreach ($rowData as $key => $val) {
            if ($val === '') {
                $rowData[$key] = null;
            }
        }
        return $rowData;
    }

    /**
     * Validate data rows and save bunches to DB.
     *
     * @return Mage_ImportExport_Model_Import_Entity_Abstract|void
     */
    protected function _saveValidatedBunches()
    {
        $source          = $this->_getSource();
        $productDataSize = 0;
        $bunchRows       = [];
        $startNewBunch   = false;
        $nextRowBackup   = [];
        /** @var Mage_ImportExport_Model_Resource_Helper_Mysql4 $helper */
        $helper          = Mage::getResourceHelper('importexport');
        $maxDataSize     = $helper->getMaxDataSize();
        $bunchSize       = Mage::helper('importexport')->getBunchSize();

        /** @var Mage_Core_Helper_Data $coreHelper */
        $coreHelper = Mage::helper('core');

        $source->rewind();
        $this->_dataSourceModel->cleanBunches();

        while ($source->valid() || $bunchRows) {
            if ($startNewBunch || !$source->valid()) {
                $this->_dataSourceModel->saveBunch($this->getEntityTypeCode(), $this->getBehavior(), $bunchRows);

                $bunchRows       = $nextRowBackup;
                $productDataSize = strlen(serialize($bunchRows));
                $startNewBunch   = false;
                $nextRowBackup   = [];
            }
            if ($source->valid()) {
                if ($this->_errorsCount >= $this->_errorsLimit) { // errors limit check
                    return;
                }
                $rowData = $coreHelper->unEscapeCSVData($source->current());

                $this->_processedRowsCount++;

                if ($this->validateRow($rowData, $source->key())) { // add row to bunch for save
                    $rowData = $this->_prepareRowForDb($rowData);
                    $rowSize = strlen(Mage::helper('core')->jsonEncode($rowData));

                    $isBunchSizeExceeded = ($bunchSize > 0 && count($bunchRows) >= $bunchSize);

                    if (($productDataSize + $rowSize) >= $maxDataSize || $isBunchSizeExceeded) {
                        $startNewBunch = true;
                        $nextRowBackup = [$source->key() => $rowData];
                    } else {
                        $bunchRows[$source->key()] = $rowData;
                        $productDataSize += $rowSize;
                    }
                }
                $source->next();
            }
        }
        return $this;
    }

    /**
     * Add error with corresponding current data source row number.
     *
     * @param string $errorCode Error code or simply column name
     * @param int $errorRowNum Row number.
     * @param string $colName OPTIONAL Column name.
     * @return Mage_ImportExport_Model_Import_Entity_Abstract
     */
    public function addRowError($errorCode, $errorRowNum, $colName = null)
    {
        $this->_errors[$errorCode][] = [$errorRowNum + 1, $colName]; // one added for human readability
        $this->_invalidRows[$errorRowNum] = true;
        $this->_errorsCount++;

        return $this;
    }

    /**
     * Add message template for specific error code from outside.
     *
     * @param string $errorCode Error code
     * @param string $message Message template
     * @return Mage_ImportExport_Model_Import_Entity_Abstract
     */
    public function addMessageTemplate($errorCode, $message)
    {
        $this->_messageTemplates[$errorCode] = $message;

        return $this;
    }

    /**
     * Returns attributes all values in label-value or value-value pairs form. Labels are lower-cased.
     *
     * @param array $indexValAttrs OPTIONAL Additional attributes' codes with index values.
     * @return array
     */
    public function getAttributeOptions(Mage_Eav_Model_Entity_Attribute_Abstract $attribute, $indexValAttrs = [])
    {
        $options = [];

        if ($attribute->usesSource()) {
            // merge global entity index value attributes
            $indexValAttrs = array_merge($indexValAttrs, $this->_indexValueAttributes);

            // should attribute has index (option value) instead of a label?
            $index = in_array($attribute->getAttributeCode(), $indexValAttrs) ? 'value' : 'label';

            // only default (admin) store values used
            $attribute->setStoreId(Mage_Catalog_Model_Abstract::DEFAULT_STORE_ID);

            try {
                foreach ($attribute->getSource()->getAllOptions(false) as $option) {
                    $value = is_array($option['value']) ? $option['value'] : [$option];
                    foreach ($value as $innerOption) {
                        if (strlen($innerOption['value'])) { // skip ' -- Please Select -- ' option
                            $options[strtolower($innerOption[$index])] = $innerOption['value'];
                        }
                    }
                }
            } catch (Exception $e) {
                // ignore exceptions connected with source models
            }
        }
        return $options;
    }

    /**
     * Import behavior getter.
     *
     * @return string
     */
    public function getBehavior()
    {
        if (!isset($this->_parameters['behavior'])
            || ($this->_parameters['behavior'] != Mage_ImportExport_Model_Import::BEHAVIOR_APPEND
            && $this->_parameters['behavior'] != Mage_ImportExport_Model_Import::BEHAVIOR_REPLACE
            && $this->_parameters['behavior'] != Mage_ImportExport_Model_Import::BEHAVIOR_DELETE)
        ) {
            return Mage_ImportExport_Model_Import::getDefaultBehavior();
        }
        return $this->_parameters['behavior'];
    }

    /**
     * EAV entity type code getter.
     *
     * @abstract
     * @return string
     */
    abstract public function getEntityTypeCode();

    /**
     * Entity type ID getter.
     *
     * @return int|null
     */
    public function getEntityTypeId()
    {
        return $this->_entityTypeId;
    }

    /**
     * Returns error information grouped by error types and translated (if possible).
     *
     * @return array
     */
    public function getErrorMessages()
    {
        $translator = Mage::helper('importexport');
        $messages   = [];

        foreach ($this->_errors as $errorCode => $errorRows) {
            if (isset($this->_messageTemplates[$errorCode])) {
                $errorCode = $translator->__($this->_messageTemplates[$errorCode]);
            }
            foreach ($errorRows as $errorRowData) {
                $key = $errorRowData[1] ? sprintf($errorCode, $errorRowData[1]) : $errorCode;
                $messages[$key][] = $errorRowData[0];
            }
        }
        return $messages;
    }

    /**
     * Returns error counter value.
     *
     * @return int
     */
    public function getErrorsCount()
    {
        return $this->_errorsCount;
    }

    /**
     * Returns error limit value.
     *
     * @return int
     */
    public function getErrorsLimit()
    {
        return $this->_errorsLimit;
    }

    /**
     * Returns invalid rows count.
     *
     * @return int
     */
    public function getInvalidRowsCount()
    {
        return count($this->_invalidRows);
    }

    /**
     * Returns model notices.
     *
     * @return array
     */
    public function getNotices()
    {
        return $this->_notices;
    }

    /**
     * Returns number of checked entities.
     *
     * @return int
     */
    public function getProcessedEntitiesCount()
    {
        return $this->_processedEntitiesCount;
    }

    /**
     * Returns number of checked rows.
     *
     * @return int
     */
    public function getProcessedRowsCount()
    {
        return $this->_processedRowsCount;
    }

    /**
     * Source object getter.
     *
     * @throws Exception
     * @return Mage_ImportExport_Model_Import_Adapter_Abstract
     */
    public function getSource()
    {
        if (!$this->_source) {
            Mage::throwException(Mage::helper('importexport')->__('Source is not set'));
        }
        return $this->_source;
    }

    /**
     * Import process start.
     *
     * @return bool Result of operation.
     */
    public function importData()
    {
        return $this->_importData();
    }

    /**
     * Is attribute contains particular data (not plain entity attribute).
     *
     * @param string $attrCode
     * @return bool
     */
    public function isAttributeParticular($attrCode)
    {
        return in_array($attrCode, $this->_particularAttributes);
    }

    /**
     * Check one attribute. Can be overridden in child.
     *
     * @param string $attrCode Attribute code
     * @param array $attrParams Attribute params
     * @param array $rowData Row data
     * @param int $rowNum
     * @return bool
     */
    public function isAttributeValid($attrCode, array $attrParams, array $rowData, $rowNum)
    {
        switch ($attrParams['type']) {
            case 'varchar':
                $val   = Mage::helper('core/string')->cleanString($rowData[$attrCode]);
                $valid = Mage::helper('core/string')->strlen($val) < self::DB_MAX_VARCHAR_LENGTH;
                break;
            case 'decimal':
                $val   = trim($rowData[$attrCode]);
                $valid = (float) $val == $val;
                break;
            case 'select':
            case 'multiselect':
                $valid = isset($attrParams['options'][strtolower($rowData[$attrCode])]);
                break;
            case 'int':
                $val   = trim($rowData[$attrCode]);
                $valid = (int) $val == $val;
                break;
            case 'datetime':
                $val   = trim($rowData[$attrCode]);
                $valid = strtotime($val) !== false
                    || preg_match('/^\d{2}.\d{2}.\d{2,4}(?:\s+\d{1,2}.\d{1,2}(?:.\d{1,2})?)?$/', $val);
                break;
            case 'text':
                $val   = Mage::helper('core/string')->cleanString($rowData[$attrCode]);
                $valid = Mage::helper('core/string')->strlen($val) < self::DB_MAX_TEXT_LENGTH;
                break;
            default:
                $valid = true;
                break;
        }

        if (!$valid) {
            $this->addRowError(Mage::helper('importexport')->__("Invalid value for '%s'"), $rowNum, $attrCode);
        } elseif (!empty($attrParams['is_unique'])) {
            if (isset($this->_uniqueAttributes[$attrCode][$rowData[$attrCode]])) {
                $this->addRowError(Mage::helper('importexport')->__("Duplicate Unique Attribute for '%s'"), $rowNum, $attrCode);
                return false;
            }
            $this->_uniqueAttributes[$attrCode][$rowData[$attrCode]] = true;
        }
        return (bool) $valid;
    }

    /**
     * Is all of data valid?
     *
     * @return bool
     */
    public function isDataValid()
    {
        $this->validateData();
        return $this->_errorsCount == 0;
    }

    /**
     * Import possibility getter.
     *
     * @return bool
     */
    public function isImportAllowed()
    {
        return $this->_importAllowed;
    }

    /**
     * Returns TRUE if row is valid and not in skipped rows array.
     *
     * @param int $rowNum
     * @return bool
     */
    public function isRowAllowedToImport(array $rowData, $rowNum)
    {
        return $this->validateRow($rowData, $rowNum) && !isset($this->_rowsToSkip[$rowNum]);
    }

    /**
     * Validate data row.
     *
     * @param int $rowNum
     * @return bool
     */
    abstract public function validateRow(array $rowData, $rowNum);

    /**
     * Set data from outside to change behavior. I.e. for setting some default parameters etc.
     *
     * @return Mage_ImportExport_Model_Import_Entity_Abstract
     */
    public function setParameters(array $params)
    {
        $this->_parameters = $params;
        return $this;
    }

    /**
     * Source model setter.
     *
     * @return Mage_ImportExport_Model_Import_Entity_Abstract
     */
    public function setSource(Mage_ImportExport_Model_Import_Adapter_Abstract $source)
    {
        $this->_source = $source;
        $this->_dataValidated = false;

        return $this;
    }

    /**
     * Validate data.
     *
     * @throws Exception
     * @return Mage_ImportExport_Model_Import_Entity_Abstract
     */
    public function validateData()
    {
        if (!$this->_dataValidated) {
            // does all permanent columns exists?
            if (($colsAbsent = array_diff($this->_permanentAttributes, $this->_getSource()->getColNames()))) {
                file_put_contents($this->_getSource()->getSource(), '');
                Mage::throwException(
                    Mage::helper('importexport')->__('Can not find required columns: %s', implode(', ', $colsAbsent)),
                );
            }

            // initialize validation related attributes
            $this->_errors = [];
            $this->_invalidRows = [];

            // check attribute columns names validity
            $invalidColumns = [];

            foreach ($this->_getSource()->getColNames() as $colName) {
                if (!preg_match('/^[a-z][a-z0-9_]*$/', $colName) && !$this->isAttributeParticular($colName)) {
                    $invalidColumns[] = $colName;
                }
            }
            if ($invalidColumns) {
                Mage::throwException(
                    Mage::helper('importexport')->__('Column names: "%s" are invalid', implode('", "', $invalidColumns)),
                );
            }
            $this->_saveValidatedBunches();

            $this->_dataValidated = true;
        }
        return $this;
    }
}
