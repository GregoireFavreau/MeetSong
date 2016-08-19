<?php
/**
 * Application Configuration
 *
 * @author David Carr - dave@daveismyname.com
 * @author Virgil-Adrian Teaca - virgil@giulianaeassociati.com
 * @version 3.0
 */

use Core\Config;


/**
 * The Application configuration.
 */
Config::set('app', array(
    'debug' => false,
    'url' => URL,
    'email' => EMAIL,
    'path' => PATH,
    'name' => TITRE,
    'template' => 'MeetSong',
    'color_scheme' => 'blue',
    'locale' => LANGUAGE,
    'timezone' => 'Europe/London',
    'key' => CLE,
    'csrf' => true,

    'providers' => array(
        'Auth\AuthServiceProvider',
        'Cache\CacheServiceProvider',
        'Routing\RoutingServiceProvider',
        'Cookie\CookieServiceProvider',
        'Database\DatabaseServiceProvider',
        'Encryption\EncryptionServiceProvider',
        'Filesystem\FilesystemServiceProvider',
        'Hashing\HashServiceProvider',
        'Log\LogServiceProvider',
        'Mail\MailServiceProvider',
        'Pagination\PaginationServiceProvider',
        'Auth\Reminders\ReminderServiceProvider',
        'Session\SessionServiceProvider',
        'Validation\ValidationServiceProvider',
        'Template\TemplateServiceProvider',
        'View\ViewServiceProvider',
        'Cron\CronServiceProvider',
    ),

    'manifest' => STORAGE_PATH,

    'aliases' => array(
        'Errors'        => 'Core\Error',
        'View'          => 'Core\View',
        'Mail'          => 'Helpers\Mailer',
        'Assets'        => 'Helpers\Assets',
        'Csrf'          => 'Helpers\Csrf',
        'Date'          => 'Helpers\Date',
        'Document'      => 'Helpers\Document',
        'Encrypter'     => 'Helpers\Encrypter',
        'FastCache'     => 'Helpers\FastCache',
        'Form'          => 'Helpers\Form',
        'Ftp'           => 'Helpers\Ftp',
        'GeoCode'       => 'Helpers\GeoCode',
        'Hooks'         => 'Helpers\Hooks',
        'Inflector'     => 'Helpers\Inflector',
        'Number'        => 'Helpers\Number',
        'RainCaptcha'   => 'Helpers\RainCaptcha',
        'ReservedWords' => 'Helpers\ReservedWords',
        'SimpleCurl'    => 'Helpers\SimpleCurl',
        'TableBuilder'  => 'Helpers\TableBuilder',
        'Tags'          => 'Helpers\Tags',
        'Console'       => '\Forensics\Console',
        'Arr'           => 'Support\Arr',
        'Str'           => 'Support\Str',
        'App'           => 'Support\Facades\App',
        'Auth'          => 'Support\Facades\Auth',
        'Cache'         => 'Support\Facades\Cache',
        'Config'        => 'Support\Facades\Config',
        'Cookie'        => 'Support\Facades\Cookie',
        'Crypt'         => 'Support\Facades\Crypt',
        'DB'            => 'Support\Facades\DB',
        'Event'         => 'Support\Facades\Event',
        'File'          => 'Support\Facades\File',
        'Hash'          => 'Support\Facades\Hash',
        'Input'         => 'Support\Facades\Input',
        'Language'      => 'Support\Facades\Language',
        'Mailer'        => 'Support\Facades\Mailer',
        'Paginator'     => 'Support\Facades\Paginator',
        'Password'      => 'Support\Facades\Password',
        'Redirect'      => 'Support\Facades\Redirect',
        'Request'       => 'Support\Facades\Request',
        'Response'      => 'Support\Facades\Response',
        'Route'         => 'Support\Facades\Route',
        'Router'        => 'Support\Facades\Router',
        'Session'       => 'Support\Facades\Session',
        'Validator'     => 'Support\Facades\Validator',
        'Log'           => 'Support\Facades\Log',
        'URL'           => 'Support\Facades\URL',
        'Template'      => 'Support\Facades\Template',
        'Cron'          => 'Support\Facades\Cron',
    ),
));
