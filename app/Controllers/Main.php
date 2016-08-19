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
    if ($this->auth->isLogged()) {
      echo "all ok you are secured";
    }
  }
}
