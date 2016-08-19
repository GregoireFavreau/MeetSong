<?php

namespace Helpers\Auth;

class Cookie {
  const FourYears = 26144000;
  
  public static function exists($key) {
    if (isset($_COOKIE[$key])) {
      return true;
    } else {
      return false;
    }
  }
  
  public static function set($key, $value, $expiry = self::FourYears, $path = '/', $domain = false) {
    $retval = false;
    if (!headers_sent()) {
      if ($domain === false)
          $domain = $_SERVER['HTTP_HOST'];
          
      if ($expiry === -1)
          $expiry = 1893456000;
      elseif (is_numeric($expiry))
          $expiry += time();
      else
          $expiry = strtotime($expiry);
      
      $retval = @setcookie($key, $value, $expiry, $path, $domain);
      if ($retval)
          $_COOKIE[$key] = $value;
    }
    return $retval;
  }
  
  public static function get($key, $default = '') {
    return (isset($_COOKIE[$key]) ? $_COOKIE[$key] : $default);
  }
  
  public static function display() {
    return $_COOKIE;
  }
  
  public static function destroy($key, $value = '', $path = '/', $domain = '') {
    if (isset($_COOKIE[$key])) {
      unset($_COOKIE[$key]);
      seetcokie($key, $value, time() - 3600, $path, $domain);
    }
  }
  
}
