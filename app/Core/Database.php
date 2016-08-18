<?php 
namespace Core;

use Helpers\Database;

class ConnexionDB
{
	protected $db;

	public function __construct()
	{
		$this->db = Database::get();
	}
}