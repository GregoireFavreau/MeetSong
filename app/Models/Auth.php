<?php

namespace App\Models;

use Helpers\Database,
    Helpers\Auth\Cookie;

class Auth
{
	protected $db
	public $erreurmsg;
	public $successmsg;
	public $lang;
	
	public function __construct() {
		new \Helpers\Auth\Setup();
		$this->lang = include 'Lang.php';
		$this->db = Database::get();
		$this->expireAttempt();
	}
	
	/*
	 * Connexion de l'utilisateur
	 * @param string $username
	 * @param string $password
	 * @return boolean
	 */
	 public function connexion($username, $password) {
	 	if (!Cookie::get('auth_session')) {
	 		$attcount = $this->getAttempt($_SERVER['REMOTE_ADDR']);
	 		
	 		if ($attcount[0]->count >= MAX_ATTEMPTS) {
	 			$this->erreurmsg[] = $this->lang['login_lockedout'];
	 			$this->erreurmsg[] = sprintf($this->lang['login_wait'], WAIT_TIME);
	 			return false;
	 		} else {
	 			if (strlen($username) == 0) {
	 				$this->erreurmsg[] = $this->lang['login_username_empty'];
	 				return false;
	 			} elseif (strlen($username) > MAX_USERNAME_LENGTH) {
	 				$this->erreurmsg[] = $this->lang['login_username_long'];
	 				return false;
	 			} elseif (strlen($username) < MIN_USERNAME_LENGTH) {
	 				$this->erreurmsg[] = $this->lang['login_username_short'];
	 				return false;
	 			} elseif (strlen($password) == 0) {
	 				$this->erreurmsg[] = $this->lang['login_password_empty'];
	 				return false;
	 			} elseif (strlen($password) > MAX_PASSWORD_LENGTH) {
	 				$this->erreurmsg[] = $this->lang['login_password_long'];
	 				return false;
	 			} elseif (strlen($password) < MIN_PASSWORD_LENGTH) {
	 				$this->erreurmsg[] = $this->lang['login_password_short'];
	 				return false;
	 			} else {
	 				//TODO LIST
	 			}
	 		}
	 	}
	 }
}
