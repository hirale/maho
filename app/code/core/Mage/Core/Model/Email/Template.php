<?php

/**
 * Maho
 *
 * @package    Mage_Core
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2017-2025 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024-2025 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

use Symfony\Component\Mailer\Transport;
use Symfony\Component\Mailer\Mailer;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\Address;

/**
 * Template model
 *
 * Example:
 *
 * // Loading of template
 * $emailTemplate  = Mage::getModel('core/email_template')
 *    ->load(Mage::getStoreConfig('path_to_email_template_id_config'));
 * $variables = array(
 *    'someObject' => Mage::getSingleton('some_model')
 *    'someString' => 'Some string value'
 * );
 * $emailTemplate->send('some@domain.com', 'Name Of User', $variables);
 *
 * @method Mage_Core_Model_Resource_Email_Template _getResource()
 * @method Mage_Core_Model_Resource_Email_Template getResource()
 * @method string getTemplateCode()
 * @method $this setTemplateCode(string $value)
 * @method string getTemplateText()
 * @method $this setTemplateText(string $value)
 * @method string getTemplateStyles()
 * @method $this setTemplateStyles(string $value)
 * @method int getTemplateType()
 * @method $this setTemplateType(int $value)
 * @method string getTemplateSubject()
 * @method $this setTemplateSubject(string $value)
 * @method string getTemplateSenderName()
 * @method $this setTemplateSenderName(string $value)
 * @method string getTemplateSenderEmail()
 * @method $this setTemplateSenderEmail(string $value)
 * @method string getAddedAt()
 * @method $this setAddedAt(string $value)
 * @method string getModifiedAt()
 * @method $this setModifiedAt(string $value)
 * @method string getOrigTemplateCode()
 * @method $this setOrigTemplateCode(string $value)
 * @method string getOrigTemplateVariables()
 * @method $this setOrigTemplateVariables(string $value)
 * @method $this setQueue(Mage_Core_Model_Abstract $value)
 * @method Mage_Core_Model_Email_Queue getQueue()
 * @method int hasQueue()
 * @method bool getSentSuccess()
 * @method string getSenderName()
 * @method string getSenderEmail()
 * @method int getTemplateId()
 * @method $this setTemplateId(int $value)
 * @method $this setSenderName(string $value)
 * @method $this setSenderEmail(string $value)
 * @method $this setSentSuccess(bool $value)
 * @method $this setCreatedAt(string $value)
 * @method int getTemplateActual()
 * @method bool getUseAbsoluteLinks()
 * @method setUseAbsoluteLinks(bool $value)
 * @method $this setInlineCssFile(string $value)
 */
class Mage_Core_Model_Email_Template extends Mage_Core_Model_Email_Template_Abstract
{
    /**
     * Configuration path for default email templates
     */
    public const XML_PATH_TEMPLATE_EMAIL               = 'global/template/email';
    public const XML_PATH_SENDING_SET_RETURN_PATH      = 'system/smtp/set_return_path';
    public const XML_PATH_SENDING_RETURN_PATH_EMAIL    = 'system/smtp/return_path_email';

    protected $_templateFilter;
    protected $_preprocessFlag = false;
    protected $_bccEmails = [];
    protected ?string $_replyToEmail = null;
    protected ?string $_returnPathEmail = null;

    protected static $_defaultTemplates;

    #[\Override]
    protected function _construct()
    {
        $this->_init('core/email_template');
    }

    /**
     * Declare template processing filter
     *
     * @return  $this
     */
    public function setTemplateFilter(Varien_Filter_Template $filter)
    {
        $this->_templateFilter = $filter;
        return $this;
    }

    /**
     * Get filter object for template processing logi
     *
     * @return Mage_Core_Model_Email_Template_Filter
     */
    public function getTemplateFilter()
    {
        if (empty($this->_templateFilter)) {
            $this->_templateFilter = Mage::getModel('core/email_template_filter');
            $this->_templateFilter->setUseAbsoluteLinks($this->getUseAbsoluteLinks())
                ->setStoreId($this->getDesignConfig()->getStore());
        }
        return $this->_templateFilter;
    }

    /**
     * Load template by code
     *
     * @param   string $templateCode
     * @return   $this
     */
    public function loadByCode($templateCode)
    {
        $this->addData($this->getResource()->loadByCode($templateCode));
        return $this;
    }

    /**
     * Load default email template from locale translate
     *
     * @param string $templateId
     * @param string $locale
     * @return $this
     */
    public function loadDefault($templateId, $locale = null)
    {
        $defaultTemplates = self::getDefaultTemplates();
        if (!isset($defaultTemplates[$templateId])) {
            return $this;
        }

        $data = &$defaultTemplates[$templateId];
        $this->setTemplateType($data['type'] == 'html' ? self::TYPE_HTML : self::TYPE_TEXT);

        $templateText = Mage::app()->getTranslator()->getTemplateFile(
            $data['file'],
            'email',
            $locale,
        );

        if (preg_match('/<!--@subject\s*(.*?)\s*@-->/u', $templateText, $matches)) {
            $this->setTemplateSubject($matches[1]);
            $templateText = str_replace($matches[0], '', $templateText);
        }

        if (preg_match('/<!--@vars\s*((?:.)*?)\s*@-->/us', $templateText, $matches)) {
            $this->setData('orig_template_variables', str_replace("\n", '', $matches[1]));
            $templateText = str_replace($matches[0], '', $templateText);
        }

        if (preg_match('/<!--@styles\s*(.*?)\s*@-->/s', $templateText, $matches)) {
            $this->setTemplateStyles($matches[1]);
            $templateText = str_replace($matches[0], '', $templateText);
        }

        /**
         * Remove comment lines
         */
        $templateText = preg_replace('#\{\*.*\*\}#suU', '', $templateText);

        $this->setTemplateText($templateText);
        $this->setId($templateId);

        return $this;
    }

    /**
     * Retrieve default templates from config
     *
     * @return array
     */
    public static function getDefaultTemplates()
    {
        if (is_null(self::$_defaultTemplates)) {
            self::$_defaultTemplates = Mage::getConfig()->getNode(self::XML_PATH_TEMPLATE_EMAIL)->asArray();
        }

        return self::$_defaultTemplates;
    }

    /**
     * Retrieve default templates as options array
     *
     * @return array
     */
    public static function getDefaultTemplatesAsOptionsArray()
    {
        $options = [
            ['value' => '', 'label' => ''],
        ];

        $idLabel = [];
        foreach (self::getDefaultTemplates() as $templateId => $row) {
            if (isset($row['@']) && isset($row['@']['module'])) {
                $module = $row['@']['module'];
            } else {
                $module = 'adminhtml';
            }
            $idLabel[$templateId] = Mage::helper($module)->__($row['label']);
        }
        asort($idLabel);
        foreach ($idLabel as $templateId => $label) {
            $options[] = ['value' => $templateId, 'label' => $label];
        }

        return $options;
    }

    /**
     * Return template id
     * return int|null
     */
    #[\Override]
    public function getId()
    {
        return $this->getTemplateId();
    }

    /**
     * Set id of template
     * @param int $value
     * @return $this
     */
    #[\Override]
    public function setId($value)
    {
        return $this->setTemplateId($value);
    }

    /**
     * Return true if this template can be used for sending queue as main template
     *
     * @return bool
     */
    public function isValidForSend()
    {
        return $this->getSenderName()
            && $this->getSenderEmail()
            && $this->getTemplateSubject();
    }

    /**
     * Getter for template type
     *
     * @return int|string
     */
    #[\Override]
    public function getType()
    {
        return $this->getTemplateType();
    }

    /**
     * Process email template code
     *
     * @return  string
     */
    public function getProcessedTemplate(array $variables = [])
    {
        $processor = $this->getTemplateFilter();
        $processor->setUseSessionInUrl(false)
            ->setPlainTemplateMode($this->isPlain());

        if (!$this->_preprocessFlag) {
            $variables['this'] = $this;
        }

        if (isset($variables['subscriber']) && ($variables['subscriber'] instanceof Mage_Newsletter_Model_Subscriber)) {
            $processor->setStoreId($variables['subscriber']->getStoreId());
        }

        // Apply design config so that all subsequent code will run within the context of the correct store
        $this->_applyDesignConfig();

        // Populate the variables array with store, store info, logo, etc. variables
        $variables = $this->_addEmailVariables($variables, $processor->getStoreId());

        $processor
            ->setTemplateProcessor([$this, 'getTemplateByConfigPath'])
            ->setIncludeProcessor([$this, 'getInclude'])
            ->setVariables($variables);

        try {
            // Filter the template text so that all HTML content will be present
            $result = $processor->filter($this->getTemplateText());
            // If the {{inlinecss file=""}} directive was included in the template, grab filename to use for inlining
            $this->setInlineCssFile($processor->getInlineCssFile());
            // Now that all HTML has been assembled, run email through CSS inlining process
            $processedResult = $this->getPreparedTemplateText($result);
        } catch (Exception $e) {
            $this->_cancelDesignConfig();
            throw $e;
        }
        $this->_cancelDesignConfig();
        return $processedResult;
    }

    /**
     * Makes additional text preparations for HTML templates
     *
     * @return string
     */
    /**
     * @param string|null $html
     * @return string
     */
    public function getPreparedTemplateText($html = null)
    {
        if ($this->isPlain() && $html) {
            return $html;
        } elseif ($this->isPlain()) {
            return $this->getTemplateText();
        }

        return $this->_applyInlineCss($html);
    }

    /**
     * Get template code for include directive
     *
     * @param   string $template
     * @return  string
     */
    public function getInclude($template, array $variables)
    {
        $thisClass = self::class;
        /** @var Mage_Core_Model_Email_Template $includeTemplate */
        $includeTemplate = new $thisClass();
        $includeTemplate->loadByCode($template);

        return $includeTemplate->getProcessedTemplate($variables);
    }

    /**
     * Send mail to recipient
     *
     * @param   array|string       $email        E-mail(s)
     * @param   array|string|null  $name         receiver name(s)
     * @param   array              $variables    template variables
     * @return bool
     **/
    public function send(#[\SensitiveParameter] $email, $name = null, array $variables = [])
    {
        if (!$this->isValidForSend()) {
            Mage::logException(new Exception('This letter cannot be sent.'));
            return false;
        }

        $emails = array_values((array) $email);
        $names = is_array($name) ? $name : (array) $name;
        $names = array_values($names);
        foreach ($emails as $key => $email) {
            if (!isset($names[$key])) {
                $names[$key] = substr($email, 0, strpos($email, '@'));
            }
        }

        $variables['email'] = reset($emails);
        $variables['name'] = reset($names);

        $this->setUseAbsoluteLinks(true);
        $text = $this->getProcessedTemplate($variables, true);
        $subject = $this->getProcessedTemplateSubject($variables);

        $emailTransport = Mage::getStoreConfig('system/smtp/enabled');
        $setReturnPath = Mage::getStoreConfig(self::XML_PATH_SENDING_SET_RETURN_PATH);
        $returnPathEmail = match ($setReturnPath) {
            1 => $this->getSenderEmail(),
            2 => Mage::getStoreConfig(self::XML_PATH_SENDING_RETURN_PATH_EMAIL),
            default => null,
        };

        if ($this->hasQueue() && $this->getQueue() instanceof Mage_Core_Model_Email_Queue) {
            $emailQueue = $this->getQueue();
            $emailQueue->clearRecipients();
            $emailQueue->setMessageBody($text);
            $emailQueue->setMessageParameters([
                'subject'           => $subject,
                'return_path_email' => $returnPathEmail,
                'is_plain'          => $this->isPlain(),
                'from_email'        => $this->getSenderEmail(),
                'from_name'         => $this->getSenderName(),
                'reply_to'          => $this->_replyToEmail,
                'return_to'         => $this->_returnPathEmail,
            ])
                ->addRecipients($emails, $names, Mage_Core_Model_Email_Queue::EMAIL_TYPE_TO)
                ->addRecipients($this->_bccEmails, [], Mage_Core_Model_Email_Queue::EMAIL_TYPE_BCC);
            $emailQueue->addMessageToQueue();

            return true;
        }

        try {
            $email = new Email();
            $email->subject($subject);
            $email->from(new Address($this->getSenderEmail(), $this->getSenderName()));
            if ($returnPathEmail !== null) {
                $email->returnPath($returnPathEmail);
            }
            if ($this->_returnPathEmail !== null) {
                $email->returnPath($this->_returnPathEmail);
            }
            if ($this->_replyToEmail !== null) {
                $email->replyTo($this->_replyToEmail);
            }
            foreach ($emails as $key => $recipient) {
                $email->addTo(new Address($recipient, $names[$key]));
            }
            if (!empty($this->_bccEmails)) {
                foreach ($this->_bccEmails as $bccEmail) {
                    $email->addBcc($bccEmail);
                }
            }
            if ($this->isPlain()) {
                $email->text($text);
            } else {
                $email->html($text);
            }

            $dsn = Mage::helper('core')->getMailerDsn();
            if (!$dsn) {
                // This means email sending is disabled
                return true;
            }
            $mailer = new Mailer(Transport::fromDsn($dsn));

            $transportObj = new Varien_Object();
            Mage::dispatchEvent('email_template_send_before', [
                'mail'      => $email,
                'template'  => $this,
                'transport' => $transportObj,
                'variables' => $variables,
            ]);

            $mailer->send($email);

            foreach ($emails as $recipientEmail) {
                Mage::dispatchEvent('email_template_send_after', [
                    'to'         => $recipientEmail,
                    'html'       => !$this->isPlain(),
                    'subject'    => $subject,
                    'template'   => $this->getTemplateId(),
                    'email_body' => $text,
                ]);
            }

            return true;
        } catch (Exception $e) {
            Mage::logException($e);
            return false;
        }
    }

    /**
     * Send transactional email to recipient
     *
     * @param   string|int $templateId
     * @param   array|string $sender sender information, can be declared as part of config path
     * @param   string $email recipient email
     * @param   array|string|null $name recipient name
     * @param   array $vars variables which can be used in template
     * @param   int|null $storeId
     *
     * @throws Mage_Core_Exception
     *
     * @return  $this
     */
    public function sendTransactional($templateId, $sender, #[\SensitiveParameter] $email, $name, $vars = [], $storeId = null)
    {
        $this->setSentSuccess(false);
        if (($storeId === null) && $this->getDesignConfig()->getStore()) {
            $storeId = $this->getDesignConfig()->getStore();
        }

        if (is_numeric($templateId)) {
            $queue = $this->getQueue();
            $this->load($templateId);
            $this->setQueue($queue);
        } else {
            $localeCode = Mage::getStoreConfig('general/locale/code', $storeId);
            $this->loadDefault($templateId, $localeCode);
        }

        if (!$this->getId()) {
            throw Mage::exception('Mage_Core', Mage::helper('core')->__('Invalid transactional email code: %s', $templateId));
        }

        if (!is_array($sender)) {
            $this->setSenderName(Mage::getStoreConfig('trans_email/ident_' . $sender . '/name', $storeId));
            $this->setSenderEmail(Mage::getStoreConfig('trans_email/ident_' . $sender . '/email', $storeId));
        } else {
            $this->setSenderName($sender['name']);
            $this->setSenderEmail($sender['email']);
        }

        if (!isset($vars['store'])) {
            $vars['store'] = Mage::app()->getStore($storeId);
        }
        $this->setSentSuccess($this->send($email, $name, $vars));
        return $this;
    }

    /**
     * Process email subject
     *
     * @return  string
     */
    public function getProcessedTemplateSubject(array $variables)
    {
        $processor = $this->getTemplateFilter();

        if (!$this->_preprocessFlag) {
            $variables['this'] = $this;
        }

        $processor->setVariables($variables);

        $this->_applyDesignConfig();
        try {
            $processedResult = $processor->filter($this->getTemplateSubject());
        } catch (Exception $e) {
            $this->_cancelDesignConfig();
            throw $e;
        }
        $this->_cancelDesignConfig();
        return $processedResult;
    }

    /**
     * @param array|string $bcc
     * @return $this
     */
    public function addBcc($bcc)
    {
        if (is_array($bcc)) {
            foreach ($bcc as $email) {
                $this->_bccEmails[] = $email;
            }
        } elseif ($bcc) {
            $this->_bccEmails[] = $bcc;
        }
        return $this;
    }

    /**
     * Set Return Path
     *
     * @param string $email
     * @return $this
     */
    public function setReturnPath(#[\SensitiveParameter] $email)
    {
        $this->_returnPathEmail = $email;
        return $this;
    }

    /**
     * Add Reply-To header
     *
     * @param string $email
     * @return $this
     */
    public function setReplyTo(#[\SensitiveParameter] $email)
    {
        $this->_replyToEmail = $email;
        return $this;
    }

    /**
     * Parse variables string into array of variables
     *
     * @param string $variablesString
     * @return array
     */
    protected function _parseVariablesString($variablesString)
    {
        $variables = [];
        if ($variablesString && is_string($variablesString)) {
            $variablesString = str_replace("\n", '', $variablesString);
            $variables = Mage::helper('core')->jsonDecode($variablesString);
        }
        return $variables;
    }

    /**
     * Retrieve option array of variables
     *
     * @param bool $withGroup if true wrap variable options in group
     * @return array
     */
    public function getVariablesOptionArray($withGroup = false)
    {
        $optionArray = [];
        $variables = $this->_parseVariablesString($this->getData('orig_template_variables'));
        if ($variables) {
            foreach ($variables as $value => $label) {
                $optionArray[] = [
                    'value' => '{{' . $value . '}}',
                    'label' => Mage::helper('core')->__('%s', $label),
                ];
            }
            if ($withGroup) {
                $optionArray = [
                    'label' => Mage::helper('core')->__('Template Variables'),
                    'value' => $optionArray,
                ];
            }
        }
        return $optionArray;
    }

    /**
     * Validate email template code
     */
    #[\Override]
    protected function _beforeSave()
    {
        $code = $this->getTemplateCode();
        if (empty($code)) {
            Mage::throwException(Mage::helper('core')->__('The template Name must not be empty.'));
        }
        if ($this->_getResource()->checkCodeUsage($this)) {
            Mage::throwException(Mage::helper('core')->__('Duplicate Of Template Name'));
        }
        return parent::_beforeSave();
    }
}
