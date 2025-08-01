# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Maho is an open-source ecommerce platform forked from OpenMage, designed for medium-to-small on-premise projects. It's based on the Magento 1 architecture but modernized with PHP 8.3+ support and contemporary development tools.

## Essential Commands

### Code Quality & Standards
```bash
vendor/bin/php-cs-fixer fix        # Fix code style (lint)
vendor/bin/phpstan analyze         # Run static analysis
vendor/bin/rector -c .rector.php
```

### Cache Management
```bash
./maho cache:flush        # Flush all caches
```

### Database & Indexing
```bash
./maho index:list         # List all indexes
./maho index:reindex      # Reindex specific index
./maho index:reindex:all  # Reindex all indexes
```

## Architecture Overview

### Bootstrapping Maho
To bootstrap Maho in any PHP script, simply require the Composer autoloader:
```php
require 'vendor/autoload.php';
Mage::app();
// That's it! Maho is now bootstrapped and ready to use
```
No need for complex initialization - the autoloader handles everything.

### MVC Pattern
Maho follows a traditional MVC architecture:
- **Models** (`Model/`): Business logic and data access
- **Views** (`Block/` and templates): Presentation layer
- **Controllers** (`controllers/`): Request handling

### Module Structure
Each module follows this structure:
```
app/code/core/Mage/[ModuleName]/
├── Block/          # View blocks
├── Helper/         # Helper classes
├── Model/          # Business logic
├── controllers/    # Controllers
├── etc/            # Configuration (config.xml, system.xml)
├── sql/            # Database migrations
└── data/           # Data install scripts
```

### Key Configuration Files
- `app/etc/local.xml`: Main configuration (DB, cache, etc.)
- `app/etc/config.xml`: Base configuration
- `app/etc/modules/*.xml`: Module declarations

### Theme Structure
```
app/design/
├── adminhtml/      # Admin panel themes
├── frontend/       # Frontend themes
└── install/        # Installer theme
```

### Database Access Pattern
- Models extend `Mage_Core_Model_Abstract`
- Resource models handle database operations
- Collections for querying multiple records
- Uses Zend_Db adapters for database abstraction

### Event System
Maho uses an event-driven architecture:
```php
Mage::dispatchEvent('event_name', ['data' => $data]);
```
Observers are configured in module's `config.xml`.

### Layout System
- XML-based layout configuration
- Block hierarchy system
- Template assignment via layout XML

### Session Management
- Customer sessions: `Mage::getSingleton('customer/session')`
- Admin sessions: `Mage::getSingleton('admin/session')`
- Checkout sessions: `Mage::getSingleton('checkout/session')`

### Translation System
- CSV-based translations in `app/locale/[locale]/`
- Helper method: `$this->__('Text to translate')`
- Admin translations: `Mage::helper('adminhtml')->__('Text')`

## Development Guidelines

- When you write CSS, use the most modern features, do not care for Internet Explorer or old unsupported browsers.
- When you write Javascript, never use prototypejs or jquery, only the most modern vanillajs
- If you're integrating new tools/libraries, always use their latest available version
- Update headers of the PHP files, adding the current year for the copyright Maho line
- For new PHP files, only include Maho copyright with the current year - no other entities:
```php
/**
 * Maho
 *
 * @package    Mage_Module
 * @copyright  Copyright (c) 2025 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */
```
- Before committing, ensure all translatable strings (`$this->__()` or `Mage::helper()->__()`) are present in the corresponding CSV files in `app/locale/en_US/`

### Adding New Features
- If you've to create a new module, use the `app/code/core/Maho/` namespace 
- Declare module in `app/etc/modules/`
- Follow existing module patterns for consistency
- Add strict typing to all new code and use modern PHP8.3+ features
- New Maho modules now include:
  - `Maho_AdminActivityLog`: Tracks admin actions and logins
  - `Maho_Captcha`: CAPTCHA functionality
- When overriding admin routes in Maho modules, use `before="Mage_Adminhtml"` pattern

### Modifying Existing Features
- Do not increment module's version number in module's `config.xml`
- Feel free to modify the files in the core, there's no problem with that
- Avoid creating a new module unless asked for it

### Database Changes
- Use setup scripts in `sql/maho_setup/YY.MM.[incremental number].php`

### Working with Collections
```php
$collection = Mage::getResourceModel('catalog/product_collection')
    ->addAttributeToSelect('*')
    ->addFieldToFilter('status', 1);
```

### Error Handling
- Exceptions extend module-specific exception classes
- Use `Mage::throwException()` for user-facing errors
- Log errors with `Mage::log()`

## Testing Approach
While there's no dedicated test suite, ensure code quality through:
- PHPStan static analysis (level 6)
- PHP-CS-Fixer for code standards
- Manual testing of features
- GitHub Actions CI for automated checks

## Modern PHP Patterns

### Type Declarations
- Use `declare(strict_types=1);` at the top of new PHP files
- Add type hints for all new method parameters and return types
- Use PHP 8.3+ features like `#[\Override]` attribute for overridden methods

### Security Patterns
- Use `getUserParam()` instead of `getParam()` for user-supplied parameters in controllers
- Define `public const ADMIN_RESOURCE` in admin controllers for ACL permissions
- Example:
```php
declare(strict_types=1);

class Mage_Module_Adminhtml_SomeController extends Mage_Adminhtml_Controller_Action
{
    public const ADMIN_RESOURCE = 'system/module/resource';
    
    #[\Override]
    public function preDispatch()
    {
        $this->_setForcedFormKeyActions('delete');
        return parent::preDispatch();
    }
}
```


## Git Commit Rules
- **NEVER** include "Co-Authored-By: Claude" or any AI attribution in commits
- **NEVER** mention Claude, AI, or assistant in commit messages
- Keep commits professional and focused only on code changes
