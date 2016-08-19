<?php

/**
 * Configuration générales
 * @version 1.0
 * @author Grégoire Favreau <mohinette@hotmail.fr>
 */
 
 namespace App\Models;
 
 class Configuration {
  
  public function __construct() {
   define('SITE_NAME', 'MeetSong');
   define('EMAIL_FROM', 'equipe@meetsong.com');
   define('MAX_ATTEMPTS', 3);
   define('BASE_URL', 'http://localhost/MeetSong');
   define('ACTIVATION_ROUTE', 'activate');
   define('RESET_PASSWORD_ROUTE', 'resetpassword');
   define('SESSION_DURATION', '+1 month');
   define('SECURITY_DURATION', '+5 minutes');
   define('COST', 10);
   define('HASH_LENGTH', 22);
   define('LOC', 'fr');
   define('MIN_USERNAME_LENGTH', 5);
   define('MAX_USERNAME_LENGTH', 30);
   define('MIN_PASSWORD_LENGTH', 5);
   define('MAX_PASSWORD_LENGTH', 30);
   define('MIN_EMAIL_LENGTH', 5);
   define('MAX_EMAIL_LENGTH', 100);
   define('RANDOM_KEY_LENGTH', 15);
   $waittime = preg_replace("/[^0-9]/", "", SECURITY_DURATION);
   define('WAIT_TIME', $waittime);
  }
 }
