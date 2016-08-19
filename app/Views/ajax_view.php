<?php
/*
 *
 *
 *
 */
?>
<div class='ui middle aligned center aligned grid'>
  <div class='column'>
    <h2 class='ui teal image header'>
      <i class='user teal icon'></i>
      <div class='content'>
        Login to your account
      </div>
    </h2>
    <form class='ui large form'>
      <div class='ui stacked segment'>
        <div class='field'>
          <div class='ui left icon input'>
            <i class='user icon'></i>
            <input type='text' name='prenom' placeholder='User Name'>
          </div>
        </div>
        <div class='field'>
          <div class='ui left icon input'>
            <i class='lock icon'></i>
            <input type='password' name='password' placeholder='password'>
          </div>
        </div>
        <div class='ui fluid large teal submit button'>Login</div>
      </div>
      <div class='ui error message'></div>
    </form>
    <div id='status' class='ui message'>
      Welcome
    </div>
  </div>
</div>
