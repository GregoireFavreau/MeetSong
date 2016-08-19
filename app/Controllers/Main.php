<?php

namespace Controllers;

use Core\View;
use Core\Controller;
use Helpers\Request as Request;

class Main extends Controller {
  private $auth;
  
  public function __construct() {
    parent::__construct();
    $this->auth = new \Helpers\Auth\Auth();
  }
  
  public function index() {
    View::renderTemplate('header');
    View::render('ajax_view');
    View::renderTemplate('footer');
  }
  
  public function secured() {
    if ($this->auth->etatConnex()) {
      echo "all ok you are secured";
    }
  }
  
  public function authenticate() {
    $prenom = Request::post('prenom');
    $password = Request::post('password');
    $reponse = array();
    if ($this->auth->connexion($prenom, $password)) {
      if ($this->auth->erreurmsg) {
        $reponse['status'] = 'already';
        $reponse['message'] = $this->auth->erreurmsg[0];
        echo json_encode($response);
      } else {
        $reponse['status'] = 'success';
        $reponse['message'] = $this->auth->successmsg[0];
        echo json_encode($response);
      }
    } else {
      $response['status'] = 'fail';
      $response['message'] = $this->auth->erreurmsg[0];
      echo json_encode($response);
    }
  }
}
