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
	 				$query = $this->db->select("SELECT isactive,password FROM ".PREFIX."users WHERE username=:username", array(":username" => $username));
	 				$count = count($query);
	 				$hashed_db_password = $query[0]->password;
	 				$verify_password = \Helpers\Password::verify($password, $hashed_db_password);
	 				if ($count == 0 || $verify_password == 0) {
	 					$this->erreurmsg[] = $this->lang['login_incorrect'];
	 					$this->addAttempt($_SERVER['REMOTE_ADDR']);
	 					$attcount[0]->count = $attcount[0]->count + 1;
	 					$remaincount = (int) MAX_ATTEMPTS - $attcount[0]->count;
	 					$this->logActivity("UNKNOWN", "AUTH_LOGIN_FAIL", "Username / Password incorrect - {$userame} / {$password}");
	 					$this->erreurmsg[] = sprintf($this->lang['login_attemps_remaining'], $remaincount);
	 					return false;
	 				} else {
	 					if ($query[0]->isactive == "0") {
	 						$this->logActivity($username, "AUTH_LOGIN_FAIL", "Compte inactif");
	 						$this->erreurmsg[] = $this->lang['login_account_inactive'];
	 						return false;
	 					} else {
	 						$this->newSession($username)
	 						$this->logActivity($username, "AUTH_LOGIN_SUCCESS", "Vous êtes maintenant connecté.");
	 						$this->successmsg[] = $this->lang['login_success'];
	 						return true;
	 					}
	 				}
	 			}
	 		}
	 	} else {
	 		$this->erreurmsg[] = $this->lang['login_already'];
	 		return true;
	 	}
	 }
	 
	 /*
	  * Deconnexion de l'utilisateur, suppression des sessions et destructions des cookies
	  */
	  public function deconnexion() {
	  	$auth_session = Cookie::get('auth_session');
	  	if ($auth_session != '') {
	  		$this->deleteSession($auth_session);
	  	}
	  }
	  
	  /*
	   * Rafraichissement sur l'état de connexion de l'utilisateur
	   * @return boolean
	   */
	   public function etatConnex() {
	   	$auth_session = Cookie::get('auth_session');
	   	return ($auth_session != '' & $this->sessionIsValid($auth_session));
	   }
	   
	   /*
	    * Informations régulières sur la session
	    * @return array
	    */
	    public function etatSessionInfo() {
	    	if ($this->etatConnex()) {
	    		$auth_session = Cookie::get('auth_session');
	    		return $this->sessionInfo($auth_session);
	    	}
	    }
	    
	   /*
	    * Avoir des informations sur la session crypté de l'utilisateur
	    * @param string $hash
	    * @return array $session
	    */
	    private function sessionInfo($hash) {
	    	$query = $this->db->select("SELECT uid, username, expiredate, ip FROM ".PREFIX."session WHERE hash=:hash", array(':hash' => $hash));
	    	$count = count($query);
	    	if ($count == 0) {
	    		$this->erreurmsg[] = $this->lang['sessioninfo_invalid'];
	    		Cookie::destroy('auth_session', $hash)
	    		return false;
	    	} else {
	    		$session['uid'] = $query[0]->uid;
	    		$session['username'] = $query[0]->username;
	    		$sesion['expiredate'] = $query[0]->expiredate;
	    		$session['ip'] = $query[0]->ip;
	    		return $session;
	    	}
	    }
	    
	    /*
	     * Voir si le hash de la session est valide dans la base de données
	     * @param string $hash
	     * @return boolean
	     */
	     private function sessionValide($hash) {
	     	$sql = 'SELECT username, expiredate, ip FROM ".PREFIX."sessions WHERE hash=:hash';
	     	$session = $this->db->select($sql, array(':hash' => $hash));
	     	$count = count($session);
	     	if ($count == 0) {
	     		Cookie::destroy('auth_session', $hash);
	     		$this->logActivity('UNKNOWN', 'AUTH_CHECKSESSION', "User session cookie deleted - Hash ({$hash}) didn't exist");
	     		return false;
	     	} else {
	     		$username = $session[0]->username;
	     		$db_expiredate = $session[0]->expiredate;
	     		$db_ip = $session[0]->ip;
	     		if ($_SERVER['REMOTE_ADDR'] != $db_ip) {
	     			$this->db->delete(PREFIX."sessions", array('username' => $username));
	     			Cookie::destroy('auth_session', $hash);
	     			$this->logActivity($username, 'AUTH_CHECKSESSION', "");
	     			return false
	     		} else {
	     			//TODO LIST
	     		}
	     	}
	     }
}
