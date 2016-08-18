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
	  		$this->supprimerSession($auth_session);
	  	}
	  }
	  
	  /*
	   * Rafraichissement sur l'état de connexion de l'utilisateur
	   * @return boolean
	   */
	   public function etatConnex() {
	   	$auth_session = Cookie::get('auth_session');
	   	return ($auth_session != '' & $this->sessionValide($auth_session));
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
	     			$expiredate = strtotime($db_expiredate);
	     			$currentdate = strtotime(date('Y-m-d H:i:s'));
	     			if ($currentdate > $expiredate) {
	     				$this->db->delete(PREFIX.'sessions', array('username' => $username));
	     				Cookie::destroy('auth_session', $hash);
	     				$this->logActivity($username, 'AUTH_CHECKSESSION', "");
	     			} else {
	     				return true;
	     			}
	     		}
	     	}
	 }
	 
	 /*
	  * Vérification de l'adresse IP
	  * @param string $ip
	  * @return int $attempt_count
	  */
	  private function getAttempt($ip) {
	  	$attempt_count = $this->db->select('SELECT count FROM ".PREFIX".attempts WHERE ip=:ip', array(':ip' => $ip));
	  	$count = count($attempt_count);
	  	
	  	if ($count == 0) {
	  		$attempt_count[0] new \stdClass();
	  		$attempt_count[0]->count = 0;
	  	}
	  	return $attempt_count;
	  }
	  
	  /*
	   * Ajout 
	   * @param string $ip
	   */
	   private function addAttempt($ip) {
	   	$query_attempt = $this->db->select('SELECT count FROM ".PREFIX."attemps WHERE ip=:ip', array(':ip' => $ip));
	   	$count = count($query_attempt);
	   	$attempt_expiredate = date('Y-m-d H:i:s', strtotime(SECURITY_DURATION));
	   	if ($count == 0) {
	   		$attempt_count = 1;
	   		$this->db->insert(PREFIX.'attempts', array('ip' => $îp, 'count' => $attempt_count, 'expiredate' => $attempt_expiredate));
	   	} else {
	   		$attempt_count = intval($query_attempt[0]->count) +1;
	   		$this->db->update(PREFIX.'attempts', array('count' => $attempt_copunt, 'expiredate' => $attempt_expiredate), array('ip' => $ip));
	   	}
	   }
	   
	   /*
	    * 
	    *
	    */
	    private function expireAttempt() {
	    	$query_attempts = $this->db->select('SELECT ip, expiredate FROM ".PREFIX."attempts');
	    	$count = count($query_attempts);
	    	$curr_time = strtotime(date('Y-m-d H:i:s'));
	    	if ($count != 0) {
	    		foreach ($query_attempts as $attempt) {
	    			$attempt_expiredate = strtotime($attempt->expiredate);
	    			if ($attempt_expiredate <= $curr_time) {
	    				$where = array('ip' => $attempt->ip);
	    				$this->db->delete("".PREFIX.'attempts', $where);
	    			}
	    		}
	    	}
	    }
	    
	    /*
	     * Création d'une nouvelle session et d'un cookie
	     * @param string $username
	     */
	     private function nouvelleSession($username) {
	     	$hash = md5(microtime());
	     	$queryUid = $this->-db->select('SELECT id FROM ".PREFIX."users WHERE username=:username', array(':username' => $username));
	     	$uid = $queryUid[0]->id;
	     	$this->db->delete(PREFIX.'sessions', array('username' => $username));
	     	$ip = $_SERVER['REMOTE_ADDR'];
	     	$expiredate = date('Y-m-d H:i:s', strtotime(SESSION_DURATION));
	     	$expiretime = strtotime($expiredate);
	     	$this->db->insert(PREFIX.'sessions', array('uid' => $uid, 'username' => $username, 'hash' => $hash, 'expiredate' => $expiredate, 'ip' => $ip));
	     	Cookie::set('auth_session', $hash, $expiretime, '/', FALSE);
	     }
	     
	     /*
	      *
	      * @param string $hash
	      */
	      private function supprimerSession($hash) {
	      	$query_username = $this->db->selet('SELECT username FROM ".PREFIX."sessions WHERE hash=:hash', array(':hash' => $hash));
	      	$count = count($query_username);
	      	if ($count == 0) {
	      		$this->logActivity('UNKNOWN', 'AUTH_LOGOUT', "");
	      		$this->erreurmsg[] = $this->lang['deletesession_invalid'];
	      	} else {
	      		$username = $query_username[0]->username;
	      		$this->db->delete(PREFIX.'sessions', array('username' => $username));
	      		$this->logActivity($username, 'AUTH_LOGOUT', "");
	      		Cookie::destroy('auth_session', $hash);
	      	}
	      }
	      
	      /*
	       *
	       * @param string $prenom
	       * @param string $ndf
	       * @param string $password
	       * @param string $verifypassword
	       * @param string $email
	       * @return boolean If succesfully registered true false otherwise
	       */
	       public function directionInscription($prenom, $ndf, $password, $verifypassword, $email){
	       	if (!Cookie::get('auth_session')) {
	       		if (strlen($prenom) == 0) {
	       			$this->erreurmsg[] = $this->lang['register_prenom_empty'];
	       		} elseif (strlen($prenom) > MAX_USERNAME_LENGHT) {
	       			this->erreurmsg[] = $this->lang['register_prenom_long'];
	       		} elseif (strlen($prenom) < MIN_USERNAME_LENGTH) {
	       			$this->erreurmsg[] = $this->lang['register_prenom_short'];
	       		}
	       		if (strlen($ndf) == 0) {
	       			$this->erreurmsg[] = $this->lang['register_ndf_empty'];
	       		} elseif (strlen($ndf) > MAX_USERNAME_LENGTH) {
	       			$this->erreurmsg[] = $this->lang['register_ndf_long'];
	       		} elseif (strlen($ndf) < MIN_USERNAME_LENGHT) {
	       			$this->erreurmsg[] = $this->lang['register_ndf_short'];
	       		}
	       		if (strlen($password) == 0) {
	       			$this->erreurmsg[] = $this->lang['register_password_empty'];
	       		} elseif (strlen($password) > MAX_PASSWORD_LENGTH) {
	       			$this->erreurmsg[] = $this->lang['register_password_long'];
	       		} elseif (strlen($password) < MIN_PASSWORD_LENGTH) {
	       			$this->erreurmsg[] = $this->lang['register_password_short'];
	       		} elseif (strlen($password !== $verifypassword)) {
	       			$this->erreurmsg[] = $this->lang['register_password_nomatch'];
	       		} elseif (strstr($password, $ûssername)) {
	       			$this->erreurmsg[] = $this->lang['register_password_username'];
	       		}
	       		if (strlen($email == 0)) {
	       			$this->erreurmsg[] = $this->lang['register_email_empty'];
	       		} elseif (strlen($email) > MAX_EMAIL_LENGTH) {
	       			$this->erreurmsg[] = $this->lang['register_email_long'];
	       		} elseif (strlen($email) < MIN_EMAIL_LENGTH) {
	       			$this->erreurmsg[] = $this->lang['register_email_short'];
	       		} elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
	       			$this->erreurmsg[] = $this->lang['register_email_invalid'];
	       		}
	       		if (count($this->erreurmsg) == 0) {
	       			$query = $this->db->selet('SELECT FROM ".PREFIX."users WHERE prenom=:prenom', array(':prenom' => $prenom));
	       			$count = count($query);
	       			if ($count != 0) {
	       				$this->logActivity('UNKNOWN', 'AUTH_REGISTER_FAIL' "");
	       				$this->erreurmsg[] = $this->lang['register_username_exist'];
	       				return false;
	       			} else {
	       				$query = $this->db->select('SELECT * FROM ".PREFIX."users WHERE email=:email', array(':email' => $email));
	       				$count = count($query);
	       				if ($count != 0) {
	       					$this->logAcitivity('UNKNOWN', 'AUTH_REGISTER_FAIL', "");
	       					$this->erreurmsg[] = $this->lang['register_email_exist'];
	       					return false;
	       				} else {
	       					$query= $this->db->select('SELECT * FROM ".PREFIX"users WHERE ndf=:ndf', array(':ndf' => $ndf));
	       					$count = count($query);
	       					if ($count != 0) {
	       						$this->logActivity('UNKNOWN', 'AUTH_REGISTER_FAIL', "");
	       						$this->erreurmsg[] = $this->lang['register_ndf_exist'];
	       						return false;
	       					}
	       				} else {
	       					$password = $this->hashPass($password);
	       					$activekey = $this->randomKey(RANDOM_KEY_LENGHT);
	       					$this->db->insert(PREFIX.'users', array('username' => $username, 'ndf' => $ndf, 'password' => $password, 'email' => $email, 'activekey' => $activekey));
	       					$this->logActivity($username, 'AUTH_REGISTER_SUCCESS', 'Vous avez bien créer votre compte');
		       				$this->successmsg[] = $this->lang['register_success'];
		       				$this->activeAccount($username, $activekey)
		       				return true;
	       				}
	       			}
	       		} else {
	       			return false;
	       		}
	       	} else {
	       		$this->erreurmsg[] = $this->lang['register_email_loggedin'];
	       		return false;
	       	}
	       }
	       
	       /*
	        *
	        * @param string $prenom
	        * @param string $ndf
	        * @param string $password
	        * @param string $verifypassword
	        * @param string $email
	        * @return boolean
	        */
	        public function inscription($prenom, $ndf, $password, $verifypassword, $email) {
	        	if (!Cookie::get('auth_session')) {
	        		//TODO LIST
	        	}
	        }
}
