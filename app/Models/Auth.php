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
	        		if (strlen($prenom) == 0) {
	        			$this->erreurmsg[] = $this->lang['register_prenom_empty'];
	        		} elseif (strlen($prenom) > MAX_USERNAME_LENGTH) {
	        			$this->erreurmsg[] = $this->lang['register_prenom_long'];
	        		} elseif (strlen($prenom) < MIN_USERNAME_LENGTH) {
	        			$this->erreurmsg[] = $this->lang['register_prenom_short'];
	        		}
	        		if (strlen($ndf) == 0) {
	        			$this->erreurmsg[] = $this->lang['register_ndf_empty'];
	        		} elseif (strlen($ndf) > MAX_USERNAME_LENGTH) {
	        			$this->erreurmsg[] = $this->lang['register_ndf_long'];
	        		} elseif (strlen($ndf) < MIN_USERNAME_LENGTH) {
	        			$this->erreurmsg[] = $this->lang['register_ndf_short'];
	        		}
	        		if (strlen($password) == 0) {
	        			$this->erreurmsg[] = $this->lang['register_password_empty'];
	        		} elseif (strlen($password) > MAX_PASSWORD_LENGTH) {
	        			$this->erreurmsg[] = $this->lang['register_password_long'];
	        		} elseif (strlen($password) < MIN_PASSWORD_LENGTH) {
	        			$this->erreurmsg[] = $this->lang['register_password_short'];
	        		} elseif ($password !== $verifypassword) {
	        			$this->erreurmsg[] = $this->lang['register_password_nomatch'];
	        		} elseif (strstr($password, $prenom, $ndf)) {
	        			$this->erreurmsg[] = $this->lang['register_password_prenom_ndf'];
	        		}
	        		if (strlen($email) == 0) {
	        			$this->erreurmsg[] = $this->lang['register_email_empty'];
	        		} elseif (strlen($email) > MAX_EMAIL_LENGTH) {
	        			$this->erreurmsg[] = $this->lang['register_email_long'];
	        		} elseif (strlen($email) < MIN_EMAIL_LENGTH) {
	        			$this->erreurmsg[] = $this->lang['register_email_short'];
	        		} elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
	        			$this->erreurmsg[] = $this->lang['register_email_invalid'];
	        		} 
	        		if (count($this->erreurmsg) == 0) {
	        			$query = $this->db->select('SELECT * FROM ".PREFIX."users WHERE prenom=:prenom', array(':prenom' => $prenom));
	        			$count = count($query);
	        			if ($count != 0) {
	        				$this->logActivity('UNKNOWN', 'AUTH_REGISTER_FAIL', "Le prénom ({$prenom}) existe déjà");
	        				$this->ereurmsg[] = $this->lang['register_prenom_exist'];
	        				return false;
	        			} else {
	        				$query = $this->db->select('SELECT * FROM ".PREFIX."users WHERE ndf=:ndf', array(':ndf' => $ndf));
	        				$count = count($query);
	        				if ($count != 0) {
	        					$this->logActivity('UNKNOWN', 'AUTH_REGISTER_FAIL', "Le nom de famille ({$ndf}) existe déjà");
	        					$this->erreurmsg[] = $this->lang['register_ndf_exist'];
	        					return false;
	        				} else {
	        					$query = $this->db->select('SELECT * FROM ".PREFIX."users WHERE email=:email', array(':email' => $email));
	        					$count = count($query);
	        					if ($count != 0) {
	        						$this->logActivity('UNKNOWN', 'AUTH_REGISTER_FAIL', "L'email ({$email}) existe déjà");
	        						$this->erreurmsg[] = $this->lang['register_email_exist'];
	        						return false;
	        					} else {
	        						$password = $this->hashPass($password);
	        						$activekey = $this->randomKey(RANDOM_KEY_LENGTH);
	        						$this->db->insert(PREFIX.'users', array('prenom' => $prenom, 'ndf' => $ndf, 'password' => $password, 'email' => $email, 'activekey' => $activekey));
	        						$mail = new \Helpers\PhpMailer\Mail();
	        						$mail->setFrom(EMAIL_FROM);
	        						$mail->addAddress($email);
	        						$mail->subject(SITE_NAME);
	        						$body = 'Bonjour {$prenom} {$ndf}<br/><br/>';
	        						$body .= 'Vous vous êtes récemment inscrit sur ".SITE_NAME."<br/>';
	        						$body .= "Pour activer votre compte s'il vous plaît cliquez sur le lien suivant<br/><br/>";
	        						$body .= "<b><a href='".BASE_URL.ACTIVATION_ROUTE."?meetsong={$prenom}&key={$activekey}'> Activer mon compte</a></b>";
	        						$mail->body($body);
	        						$mail->send();
	        						$this->logActivity($username, 'AUTH_REGISTER_SUCCESS', "Votre compte a été crée, vérifier votre email");
	        						$this->successmsg[] = $this->lang['register_success'];
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
	        	 * Activer un compte
	        	 * @param string $prenom
	        	 * @param string $key
	        	 */
	        	 public function activerCompte($prenom, $key) {
	        	 	$query_active = $this->db->select('SELECT isactive,activekey FROM ".PREFIX."users WHERE prenom=:prenom', array(':prenom' => $prenom));
	        	 	
	        	 	if($db_isactive){
	        	 		if($db_key == $key){
	        	 			$this->logActivity($prenom, 'AUTH_ACTIVATE_ERROR', 'Votre compte a déjà été activé.');
	        	 			$this->erreurmsg[] = $this->lang['activate_account_activated'];
	        	 			return false;
	        	 		} else {
	        	 			$this->logActivity($prenom, 'AUTH_ACTIVATE_ERROR', "La clée d'activation est incorrect.");
	        	 			$this->erreurmsg[] = $this->lang['activate_key_incorrect'];
	        	 			return false;
	        	 		}
	        	 	} else {
	        	 		if($db_key == $key){
	        	 			$activated = $this->db->update(PREFIX.'users', array('isactive' => 1, 'activekey' => ''), array('prenom' => $prenom));
	        	 			if ($activated > 0) {
	        	 				$this->logActivity($prenom, 'AUTH_ACTIVATE_SUCCESS', 'Votre activation est validé.');
	        	 				$this->successmsg[] = $this->lang['activate_success'];
	        	 				return true;
	        	 			} else {
	        	 				$this->logActivity($prenom, 'AUTH_ACTIVATE_ERROR', "Problème lors de l'activation de votre compte.");
	        	 				$this->erreurmsg[] = $this->lang['activate_key_incorrect'];
	        	 				return false;
	        	 			}
	        	 		} else {
	        	 			$this->logActivity($prenom, 'AUTH_ACTIVATE_ERROR', "Clée incorrect.");
	        	 			$this->erreurmsg[] = $this->lang['activate_key_incorrect'];
	        	 			return false;
	        	 		}
	        	 	}
	        	 } else {
	        	 	$this->logActivity($prenom, 'AUTH_ACTIVATE_ERROR', "Votre prénom n'existe pas das dans la base de données.");
	        	 	$this->erreurmsg[] = $this->lang['activate_username_incorrect'];
	        	 	return false;
	        	 }
	        }
	        
	        /*
	         * Système de sauvegarde des erreurs
	         * @param string $prenom
	         * @param string $action
	         * @param string $additionalinfo
	         * @return boolean
	         */
	         public function logActivity($prenom, $action, $additionalinfo = 'none') {
	         	if (strlen($prenom) == 0) {
	         		$prenom = 'GUEST';
	         	} elseif (strlen($prenom) < MIN_USERNAME_LENGTH) {
	         		$this->erreurmsg[] = $this->lang['logactivity_username_short'];
	         		return false;
	         	} elseif (strlen($prenom) > MAX_USERNAME_LENGTH) {
	         		$this->erreurmsg[] = $this->lang['logactivity_username_long'];
	         		return false;
	         	}
	         	if (strlen($action) == 0) {
	         		$this->erreurmsg[] = $this->lang['logactivity_action_empty'];
	         		return false;
	         	} elseif (strlen($action) < 3) {
	         		$this->erreurmsg[] = $this->lang['logactivity_action_short'];
	         		return false;
	         	} elseif (strlen($action) > 100) {
	         		$this->erreurmsg[] = $this->lang['logactivity_action_long'];
	         		return false
	         	}
	         	if (strlen($additionalinfo) == 0) {
	         		$additionalinfo = 'none';
	         	} elseif (strlen($additionalinfo) > 500) {
	         		$this->erreurmsg[] = $this->lang['logactivity_addinfo_long'];
	         		return false;
	         	}
	         	if (count($this->erreurmsg) == 0) {
	         		$ip = $_SERVER['REMOTE_ADDR'];
	         		$date = date('Y-m-d H:i:s');
	         		$this->db->insert(PREFIX.'activitylog', array('date' => $date, 'prenom' => $prenom, 'action' => $action, 'additionalinfo' => $additionalinfo, 'ip' => $ip));
	         		return true;
	         	}
	         }
	         
	         /*
	          * Cryptage des mots de passes
	          * @param string $password
	          * @return string $hashed_password
	          */
	          private function hashPass($password) {
	          	$options = [
	          		'cost' => COST,
	          		'salt' => mcrypt_create_iv(HASH_LENGTH, MCRYPT_DEV_URANDOM)
	          	];
	          	return \Helpers\Password::make($password, PASSWORD_BCRYPT, $options);
	          }
	          
	          /*
	           * Modifie la longueur et retourne une clé au hasard
	           * @param int $length
	           * @return string $key
	           */
	           private function randomKey($length = 10) {
	           	$chars = 'ABCDEFGHIJKLMNOPQRSTUVWYXZabcdefghijklmnopqrstuvwxyz1234567890';
	           	$key = '7a80gWBX1oAYW6y1eEGAl4TKjTL4WDtu';
	           	for ($i = 0; $i < $length; $i++) {
	           		$key .= $chars{rand(0, strlen($chars) -1)};
	           	}
	           	return $key;
	           }
	           
	           /*
	            * Changement du mot de passe
	            * @param string $prenom
	            * @param string $currpass
	            * @param string $newpass
	            * @param string $verifynewpass
	            * @return boolean
	            */
	            function changePass($prenom, $currpass, $newpass, $veirfynewpass) {
	            	if (strlen($prenom) == 0) {
	            		$this->erreurmsg[] = $this->lang['changepass_prenom_empty'];
	            	} elseif (strlen($prenom) > MAX_USERNAME_LENGTH) {
	            		$this->erreurmsg[] = $this->lang['changepass_prenom_long'];
	            	} elseif (strlen($prenom) < MIN_USERNAME_LENGTH) {
	            		$this->erreurmsg[] = $this->lang['changepass_prenom_short'];
	            	}
	            	if (strlen($currpass) == 0) {
	            		$this->erreurmsg[] = $this->lang['changepass_currpass_empty'];
	            	} elseif (strlen($currpass) < MIN_PASSWORD_LENGTH) {
	            		$this->erreurmsg[] = $this->lang['changepass_curpass_short'];
	            	} elseif (strlen($currpass) > MAX_PASSWORD_LENGTH) {
	            		$this->erreurmsg[] = $this->lang['changepass_currpass_long'];
	            	}
	            	if (strlen($newpass) == 0) {
	            		$this->erreurmsg[] = $this->lang['changepass_newpass_empty'];
	            	} elseif (strlen($newpass) < MIN_PASSWORD_LENGTH) {
	            		$this->erreurmsg[] = $this->lang['changepass_newpass_short'];
	            	} elseif (strlen($newpass) > MAX_PASSWORD_LENGTH) {
	            		$this->erreurmsg[] = $this->lang['changepass_newpass_long'];
	            	} elseif (strstr($newpass, $prenom, $ndf)) {
	            		$this->erreurmsg[] = $this->lang['changepass_password_prenom_ndf'];
	            	} elseif ($newpass !== $verifynewpass) {
	            		$this->erreurmsg[] = $this->lang['changepass_password_nomatch'];
	            	}
	            	if (count($this->erreurmsg) == 0) {
	            		$newpass = $this->hashPass($newpass);
	            		$query = $this->db->select('SELECT password FROM ".PREFIX."users WHERE prenom=:prenom', array(':prenom' => $prenom));
	            		$count = count($query);
	            		if ($count == 0) {
	            			$this->logActivity('UNKNOWN', 'AUTH_CHANGEPASS_FAIL', "Prénom incorrect ({$prenom})");
	            			$this->erreurmsg[] = $this->lang['changepass_username_incorrect'];
	            			return false;
	            		} else {
	            			$db_curpass = $query[0]->password;
	            			$verify_password = \Helpers\Password::verify($curpass, $db_currpass);
	            			if ($verify_password) {
	            				$this->db->update(PREFIX.'users', array('password' => $newpass), array('prenom' => $prenom));
	            				$this->logActivity($prenom, 'AUTH_CHANGEPASS_SUCCESS', 'Mot de passe changé');
	            				$this->successmsg[] = $this->lang['changepass_success'];
	            				return true;
	            			} else {
	            				$this->logActivity($prenom, 'AUTH_CHANGEPASS_FAIL', "Le mot de passe est incorrect (DB: {$db_currpass} / Given: {$currpass} )");
	            				$this->erreurmsg[] = $this->lang['changepass_currpass_incorrect'];
	            				return false;
	            			}
	            		}
	            	} else {
	            		return false;
	            	}
	            }
	            
	            /*
	             * Changement de l'email
	             * @param string $prenom
	             * @param string $email
	             * @return boolean
	             */
	             function changeEmail($prenom, $email) {
	             	if (strlen($prenom) == 0) {
	             		$this->erreurmsg[] = $this->lang['changeemail_prenom_empty'];
	             	} elseif (strlen($prenom) > MAX_USERNAME_LENGTH) {
	             		$this->erreurmsg[] = $this->lang['changeemail_prenom_long'];
	             	} elseif (strlen($prenom) < MIN_USERNAME_LENGTH) {
	             		$this->erreurmsg[] = $this->lang['changeemail_prenom_short'];
	             	}
	             	if (strlen($email) == 0) {
	             		$this->erreurmsg[] $this->lang['changeemail_email_empty'];
	             	} elseif (strlen($email) > MAX_EMAIL_LENGTH) {
	             		$this->erreurmsg[] = $this->lang['changeemail_email_long'];
	             	} elseif (strlen($email) < MIN_EMAIL_LENGTH) {
	             		$this->erreurmsg[] = $this->lang['changeemail_email_short'];
	             	} elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
	             		$this->erreurmsg[] = $this->lang['changeemail_email_invalid'];
	             	}
	             	if (count($this->erreurmsg) == 0) {
	             		$query = $this->db->select('SELECT email FROM ".PREFIX."users WHERE prenom=:prenom', array(':prenom' => $prenom));
	             		$count = count($query);
	             		if ($count == 0) {
	             			$this->logActivity('UNKNOWN', 'AUTH_CHANGEEMAIL_FAIL', "Prénom incorrect ({$prenom})");
	             			$this->erreurmsg[] = $this->lang['changeemail_prenom_incorrect'];
	             			return false;
	             		} else {
	             			$db_email = $query[0]->email;
	             			if ($email == $db_email) {
	             				$this->logActivity($prenom, 'AUTH_CHANGEEMAIL_FAIL', "L'ancienne et la nouvelle email correspondent ({$email})");
	             				$this->erreurmsg[] = $this->lang['changeemail_email_match'];
	             				return false;
	             			} else {
	             				$this->db->update(PREFIX.'users', array('email' => $email), array('prenom', => $prenom));
	             				$this->logActivity($prenom, 'AUTH_CHANGEEMAIL_SUCCESS', "L'email {$db_email} a été changé par {$email}");
	             				$this->successmsg[] = $this->lang['changeemail_success'];
	             				return true;
	             			}
	             		}
	             	} else {
	             		return false;
	             	}
	             }
	             
	             /*
	              * Autorisé les changements de données, et récupérer le mot de passe par email
	              * @param string $email
	              * @param string $prenom
	              * @param string $key
	              * @param string $newpass
	              * @param string $verifynewpass
	              * @return boolean
	              */
	              function resetPass($email = '0', $prenom = '0', $key = '0', $newpass = '0', $verifynewpass = '0') {
	              	$attcount = $this->getAttempt($_SERVER['REMOTE_ADDR']);
	              	if ($attcount[0]->count >= MAX_ATTEMPTS) {
	              		$this->erreurmsg[] = $this->lang['resetpass_lockedout'];
	              		$this->erreurmsg[] = sprintf($this->lang['resetpass_wait'], WAIT_TIME);
	              		return false;
	              	} else {
	              		if ($prenom == '0' && $key == '0') {
	              			if (strlen($email) == 0) {
	              				$this->erreurmsg[] = $this->lang['resetpass_email_empty'];
	              			} elseif (strlen($email) > MAX_EMAIL_LENGTH) {
	              				$this->erreurmsg[] = $this->lang['resetpass_email_long'];
	              			} elseif (strlen($email) < MIN_EMAIL_LENGTH) {
	              				$this->erreurmsg[] = $this->lang['resetpass_email_short'];
	              			} elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
	              				$this->erreurmsg[] = $this->lang['resetpass_email_invalid'];
	              			}
	              			$query = $this->db->select('SELECT prenom FROM ".PREFIX."users WHERE email=:email', array(':email' => $email));
	              			$count = count($query);
	              			if ($count == 0) {
	              				$this->erreurmsg[] = $this->lang['resetpass_email_incorrect'];
	              				$attcount[0]->count = $attcount[0]->count +1;
	              				$remaincount = (int) MAX_ATTEMPTS - $attcount[0]->count;
	              				$this->logActivity('UNKNOWN', 'AUTH_RESETPASS_FAIL', "L'email saisie est incorrect ({$email})");
	              				$this->erreurmsg[] = sprintf($this->lang['resetpass_attempts_remaining'], $remaincount);
	              				$this->addAttempt($_SERVER['REMOTE_ADDR']);
	              				return false;
	              			} else {
	              				$resetkey = $this->randomKey(RANDOM_KEY_LENGTH);
	              				$prenom = $query[0]->prenom;
	              				$this->db->update(PREFIX.'users', array('resetkey' => $resetkey), array('prenom', $prenom));
	              				$mail = new \Helpers\PhpMailer\Mail();
	              				$mail->addAddress($email);
	              				$mail->subject(SITE_NAME . " - Changement de mot de passe");
	              				$body = "Bonjour {$prenom}<br/><br/>";
	              				$body .= "Vous avez récemment demandé votre mot de passe sur " . SITE_NAME . "<br/>";
	              				$body .= "Pour proccéder au changement du mot de passe cliqué sur le lien ci dessous: <br/><br/>";
	              				$body .= "<b><a href='{BASE_URL}{RESET_PASSWORD_ROUTE}?prenom={$prenom}&key={$resetkey}'>Changer mon mot de passe</a></b>";
	              				$mail->body($body);
	              				$mail->send();
	              				$this->logActivity($prenom, 'AUTH_RESETPASS_SUCCESS', "Le changement de mot de passe a bien été envoyé à {$email} (Clé: {$resetkey} )");
	              				$this->successmsg[] = $this->lang['resetpass_email_sent'];
	              				return true;
	              			}
	              		} else {
	              			//TODO LIST
	              		}
	              	}
	              }
}
