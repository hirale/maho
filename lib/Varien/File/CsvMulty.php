<?php

/**
 * Maho
 *
 * @package    Varien_File
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2025 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * Csv parse
 */
class Varien_File_Csv_Multy extends Varien_File_Csv
{
    /**
     * Retrieve CSV file data as pairs with duplicates
     *
     * @param   string $file
     * @param   int $keyIndex
     * @param   int $valueIndex
     * @return  array
     */
    #[\Override]
    public function getDataPairs($file, $keyIndex = 0, $valueIndex = 1)
    {
        $data = [];
        $csvData = $this->getData($file);
        $line_number = 0;
        foreach ($csvData as $rowData) {
            $line_number++;
            if (isset($rowData[$keyIndex])) {
                if (isset($data[$rowData[$keyIndex]])) {
                    if (isset($data[$rowData[$keyIndex]]['duplicate'])) {
                        #array_push($data[$rowData[$keyIndex]]['duplicate'],array('line' => $line_number,'value' => isset($rowData[$valueIndex]) ? $rowData[$valueIndex] : null));
                        $data[$rowData[$keyIndex]]['duplicate']['line'] .= ', ' . $line_number;
                    } else {
                        $tmp_value = $data[$rowData[$keyIndex]]['value'];
                        $tmp_line  = $data[$rowData[$keyIndex]]['line'];
                        $data[$rowData[$keyIndex]]['duplicate'] = [];
                        #array_push($data[$rowData[$keyIndex]]['duplicate'],array('line' => $tmp_line.' ,'.$line_number,'value' => $tmp_value));
                        $data[$rowData[$keyIndex]]['duplicate']['line'] = $tmp_line . ' ,' . $line_number;
                        $data[$rowData[$keyIndex]]['duplicate']['value'] = $tmp_value;
                    }
                } else {
                    $data[$rowData[$keyIndex]] = [];
                    $data[$rowData[$keyIndex]]['line'] = $line_number;
                    $data[$rowData[$keyIndex]]['value'] = $rowData[$valueIndex] ?? null;
                }
            }
        }
        return $data;
    }
}
