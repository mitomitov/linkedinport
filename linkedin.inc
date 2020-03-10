<?php

/*
 * @file : LinkedIn API requests related functions
 */

/*
 * Called from submit callback at linkedin/token/%user
 * Let the user authorize us to gain access to his profile, and store credentials.
 * Also used for login.
 */

/**
 * @todo Please document this function.
 * @see http://drupal.org/node/1354
 */
function linkedin_get_user_data($token){
  //get email
  $options = array(
      'method' => 'GET',
      'headers' => array(
        'Content-Type' => 'application/x-www-form-urlencoded',
        'Authorization' => 'Bearer  '.$token,
      ),
    );

    $email_endpoint = 'https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))';
    $result = drupal_http_request($email_endpoint, $options);
    //eldoprint ($result);
    if($result->code != 200){
        if($result->code == 401){
           $access_token = $oauth2_client->getAccessToken(FALSE);
           drupal_goto('linkedin/login');
        }  
     } else {
        $data = json_decode($result->data);
        $retunr['email'] = $data->elements[0]->{'handle~'}->emailAddress;
     }   
      
   //get info
    $options = array(
      'method' => 'GET',
      'headers' => array(
        'Content-Type' => 'application/x-www-form-urlencoded',
        'Authorization' => 'Bearer  '.$token,
      ),
    );

  
    //get info
    $email_endpoint = 'https://api.linkedin.com/v2/me?projection=(id,firstName,lastName,profilePicture(displayImage~:playableStreams))';
    
    $result = drupal_http_request($email_endpoint, $options);
    //eldoprint ($result);
    if($result->code != 200){
        if($result->code == 401){
           $access_token = $oauth2_client->getAccessToken(FALSE);
           drupal_goto('linkedin/login');
        }  
     } else {
       $data = json_decode($result->data);
       $retunr['id'] = $data->id;
       $retunr['firstName'] = current($data->firstName->localized);
       $retunr['lastName'] = current($data->lastName->localized);
     }  
     
    return $retunr;
}
function linkedin_access_token($account, $destination = NULL) {
  //Get sure library is loaded before doing anything.
  
  linkedin_init();

  try {
  // server-side flow
    $redirect_url = variable_get('linkedin_redirect_url');
    if(strpos($redirect_url, 'http') === FALSE){
      $redirect_url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://". $_SERVER['HTTP_HOST'].'/'.$redirect_url;
    }
    $oauth2_config = array(
      'token_endpoint' => variable_get('token_endpoint'),
      'auth_flow' => 'server-side',
      'client_id' => variable_get('linkedin_consumer_key'),
      'client_secret' => variable_get('linkedin_consumer_secret'),
      'authorization_endpoint' => variable_get('authorization_endpoint'),
      'redirect_uri' => $redirect_url,
      'scope' => 'r_liteprofile r_emailaddress',
    );
    $oauth2_client = new OAuth2\ExtendClient($oauth2_config);
    $access_token = $oauth2_client->getAccessToken();
  }
  catch (Exception $e) {
    eldoprint($e->getMessage());
    
  }
        


     
     
    
     $info = linkedin_get_user_data($access_token);
     $info['access_token']=$access_token;


  if ($account->uid < 1) {
    $anon = TRUE;
    $back = 'login';
  }
  else {
    $anon = FALSE;
    $back = 'token';
  }
  
  
  //eldoprint($info);
  //exit;

  if ($info['access_token']) {

      if (!$anon) { // Logged in user : store request token for next step in db instead of $_SESSION for security       
        db_delete('linkedin_token')
          ->condition('uid', $account->uid)
          ->execute();
        $sql = array(
          'uid' => $account->uid,
          'token_key' => $info['access_token'],
          'token_secret' => '',
          'type' => 'request',
        );
        drupal_write_record('linkedin_token', $sql);

      }
      else { // Anonymous user. We can't use db storage, but $_SESSION can not lead to identity forgery for anonymous
        $_SESSION['oauth_token_secret'] = $info['access_token'];
      }
    }
    else {
      if (variable_get('linkedin_debug_mode', 0) == 1) {
        drupal_set_message(t('LinkedIn debug : received no answer from linkedin.com. Check your API credential at admin/settings/linkedin'));
      }
      else {
        drupal_set_message(t('There was a problem with the configuration of LinkedIn on this website. Please try again later.'), 'error');
      }
      watchdog('linkedin', t('The website could not communicate with LinkedIn. It is likely your API credentials are misconfigured.'), array(), WATCHDOG_ERROR);
      drupal_goto();
    }
  
  
  
  


    if (!$anon) {
      $result = db_query("SELECT token_secret FROM {linkedin_token} WHERE uid = :uid AND type = :type", array(':uid' => $account->uid, ':type' => 'request'))->fetchField();
    }
    else {
      $result = $_SESSION['oauth_token_secret'];
    }
 
    if (!$anon) {
      
      //Check if the same LinkedIn account is not already tied to another user
      $result = db_query("SELECT uid FROM {linkedin_token} WHERE token_key = :token_key AND token_secret = :token_secret AND type = :type ", array(':token_key' => $info['access_token'], ':token_secret' => '', ':type' => 'access'))->fetchField();
      if ($result) {
        $registered = user_load($result);
        drupal_set_message(t('Sorry, this LinkedIn account is already associated with user !registered', array('!registered' => l($registered->name, 'user/' . $result))), 'warning');
        drupal_goto('user/' . $account->uid . '/edit/linkedin');
      }
      //save acces token for future requests
      $sql = array(
        'uid' => $account->uid,
        'token_key' => $info['access_token'],
        'token_secret' => '',
        'type' => 'access',
      );
   
      drupal_write_record('linkedin_token', $sql, array('uid'));
      //associate LinkedIn ID with uid for future use
      user_set_authmaps($account, array('authmap_linkedin' => $info['id']));
      drupal_goto("user/$account->uid/edit/linkedin");
    }
    else {
      
      // Query for UID using oauth token values returned from LinkedIn.
      $uid = db_query("SELECT uid FROM {linkedin_token} WHERE token_key = :token_key AND token_secret = :token_secret AND type = :type ", array(':token_key' => $info['access_token'], ':token_secret' => '', ':type' => 'access'))->fetchField();
      $name = db_query("SELECT authname FROM {authmap} WHERE uid = :uid AND module = :module", array(':uid' => $uid, ':module' => 'linkedin'))->fetchField();
      // If user is found, log them in.

      if ($uid > 0 && $name != '') {
        user_external_login_register($name, 'linkedin');
        drupal_goto();
        
      }
      // Token not associated with uid.
      // Token expired or user never was associated with LinkedIn.
      else {
        if($uid > 0 && $name == ''){
          db_query("DELETE FROM {linkedin_token} WHERE uid = :uid ", array(':uid' => $uid));
        }

        // Check authmap table for user with same LinkedIn user id.
        // Called in the event LinkedIn auth token has been revoked or expired.
        $account = user_external_load($info['id']);
        if (isset($account->uid)) {
          // Overwrite out of date token with new token. Authmap doesn't change.
          db_merge('linkedin_token')
            ->key(array('uid' => $account->uid))
            ->fields(array(
              'uid' => $account->uid,
              'token_key' => $info['access_token'],
              'token_secret' => '',
              'type' => 'access',
            ))
            ->execute();
          // Login user.
          //print 'zzz';
          user_external_login_register($info['id'], 'linkedin');
          drupal_goto();
        }

        if (!isset($info['email'])) {
          watchdog('linkedin_error', t('Your LinkedIn access token is invalid or has expired! The website could not communicate with LinkedIn. It is likely your API credentials are misconfigured. '));
          $url1 = $GLOBALS['base_url']."/linkedin/login/0?goto=".$_GET['destination'];
          $http_response_code = 302;
          header('Location: ' . $url1, TRUE, $http_response_code);
          drupal_exit($url1);
        }

        global $user;

        // See if email is already in use as either email or username.
        $email_or_name = db_or()
          ->condition('mail', $info['email'], '=')
          ->condition('name', $info['email'], '=');
        $exists_email = db_select('users', 'u')
          ->fields('u', array('name', 'mail','uid'))
          ->condition($email_or_name)
          ->execute()
          ->fetchObject();

        if ($exists_email) {
		  $ex_user = user_load($exists_email->uid);

          // Save acces token for future requests
          $sql = array(
            'uid' => $ex_user->uid,
            'token_key' => $info['access_token'],
            'token_secret' => '',
            'type' => 'access',
          );
          db_delete('linkedin_token')->condition('uid', $ex_user->uid)->execute();
          drupal_write_record('linkedin_token', $sql);
          
          // Associate LinkedIn ID with uid for future use
          user_set_authmaps($ex_user, array('authmap_linkedin' => $info['id']));

          //user_external_login($account);

          user_external_login_register($info['id'], 'linkedin');
          drupal_goto();
		  
          /*drupal_set_message(
            t('An account registered to the email address of that LinkedIn user already exists. You must first !login with your !site password and then associate the account with your LinkedIn profile before you can login with LinkedIn. If you do not remember your !site username and password, you can !reset.',
              array(
                '!reset' => l(t('request a new password'), 'user/password'),
                '!login' => l(t('login'), 'user/login'),
                '!site' => variable_get('site_name', $_SERVER['HTTP_HOST']),
              )), 'error'
          );
          drupal_goto('user/login'); */
		  
        }
		
		$iterator = '';
		$int_iterator = 0;
		$unique_username = '';
        do{

          $exists_username = db_select('users', 'u')
            ->fields('u', array('name', 'mail','uid'))
            ->condition('name',$info['firstName'].' '.$info['lastName'].$iterator , '=')
            ->execute()
            ->fetchObject();
		  $unique_username = $info['firstName'].' '.$info['lastName'].$iterator;	
		  $int_iterator++;
		  $iterator .= ' '.$int_iterator;
		  
		}while($exists_username);
        // Create new user.
        $newUser = array(
          //'name' => $unique_username,
          'name' => $info['email'],
          'pass' => user_password(),
          'mail' => $info['email'],
          'field_first_name' => array(LANGUAGE_NONE => array(array('value' => $info['firstName']))), //$email_response['first-name'].' '.$email_response['last-name']))),
          'field_last_name' => array(LANGUAGE_NONE => array(array('value' => $info['lastName']))), //$email_response['first-name'].' '.$email_response['last-name']))),
          'field_from_linkedin' => array(LANGUAGE_NONE => array(array('value' => 1))),
          'field_user_linkedin' => array(LANGUAGE_NONE => array(array('value' => $response['person']['public-profile-url']))),
          'status' => 1,
        );
        $orig_image = $response['person']['picture-url'];
        if(!empty($response['person']['picture-urls']['picture-url'])){
          $orig_image = $response['person']['picture-urls']['picture-url'];
        }
        $format_const=exif_imagetype($orig_image);
        $format='.jpg';

        switch($format_const){
          case '2': // jpg
            $format='.jpg';
            break;

          case '3': // png
            $format='.png';
            break;

          case '4': // bmp
            $format='.bmp';
            break;

        }
        $image = file_get_contents($orig_image); // this is a PHP function to get a string representation of the image file
        $account = user_save($user, $newUser);
        if(!empty($image)){
          $rand=rand();
          $destination = 'public://pictures/'.$response['person']['first-name'].'_'.$response['person']['last-name'].$rand.$format; // a stream wrapper path where you want this image to reside on your file system including the desired filename

          $file = file_save_data($image, $destination, FILE_EXISTS_REPLACE);

          if (is_object($file)) { // if you get back a Drupal $file object, everything went as expected so make the status permenant
            $file->status = 1;
            $file = file_save($file);
          }

          $account->picture=$file;
          user_save($account);
        }


        // Set operation.
        //$op = 'register_no_approval_required';
        // Send an email.
        //_user_mail_notify($op, $account);

        // Save acces token for future requests
        $sql = array(
          'uid' => $account->uid,
          'token_key' => $info['access_token'],
          'token_secret' => '',
          'type' => 'access',
        );
        drupal_write_record('linkedin_token', $sql);

        // Associate LinkedIn ID with uid for future use
        user_set_authmaps($account, array('authmap_linkedin' => $response['person']['id']));

        //user_external_login($account);

        $form_state['uid'] = $account->uid;
        user_login_submit(array(), $form_state);

        $user = $account;
        $liuser = $response + $info;

        // Allow other modules to manipulate the user information after save.
        module_invoke_all('linkedin_user_save', $account, $liuser);

        //module_load_include('pages.inc', 'user');
        //user_logout();

        drupal_goto();

      }
    }
  
}

/*
 * Let us retrieve profile fields.
 * Returns an array contening the fields requested.
 * @params
 * $uid : the uid of the user we want to access infos
 * $fields : the fields we want to retrieve, as an array (see http://developer.linkedin.com/docs/DOC-1061 for complete list).
 */

/**
 * @todo Please document this function.
 * @see http://drupal.org/node/1354
 */
function _linkedin_get_profile_fields($uid, $fields = array()) {
  //Get sure library is loaded before doing anything.
  linkedin_init();

  $base_url = "https://api.linkedin.com/v1/people/";

  $row = db_query("SELECT * FROM {linkedin_token} WHERE uid = :uid AND type = :type", array(':uid' => $uid, ':type' => 'access'))->fetchAssoc();
  if (!$row || empty($row)) {
    // This account does not have any LinkedIn account associated with.
    $response = array(
      'status' => '401',
      'error-code' => 'custom',
      'message' => 'No LinkedIn account is associated with this user',
    );
    if (variable_get('linkedin_debug_mode', 0) == 1) {
      drupal_set_message(t('Linkedin debug : @status : @message', array('@status' => $response['status'], '@message' => $response['message'])));
    }
    return $response;
  }

  global $user;
  if ($user->uid == $uid) {
    //User is requesting his own profile.
    $tokens = $row;
    $append = '~';
    $type = 'auth';
  }
  else {
    $tokens = db_query("SELECT * FROM {linkedin_token} WHERE uid = :uid AND type = :type", array(':uid' => $user->uid, ':type' => 'access'))->fetchAssoc();
    if (!$tokens) {
      //We don't have any LinkedIn account associated with the user viewing the profile.
      //Make the request on the behalf on viewed user and switch to public profile.
      $tokens = $row;
      $append = '~:public';
      $type = 'public';
    }
    else {
      //Fetch profile. Fields returned will depend on the relationships between viewing/viewed users
      $authname = db_query("SELECT authname FROM {authmap} WHERE uid = :uid AND module = :module", array(':uid' => $uid, ':module' => 'linkedin'))->fetchField();
      $append = 'id=' . $authname;
      $type = 'auth';
    }
  }
  $tokens = (array) $tokens;
  $append .= _linkedin_build_fields_request($fields, $type);
  $url = $base_url . $append;
  $response = linkedin_get_fields($url, $tokens);

  if (isset($response['error']['status']) && ($response['error']['status'] == 401 || $response['error']['status'] == 403)) {
    // No relationships between users, switch back to public profile and retry
    $tokens = (array) $row;
    $append = '~:public';
    $append .= _linkedin_build_fields_request($fields, 'public');
    $url = $base_url . $append;
    $response = linkedin_get_fields($url, $tokens);
  }
  if (isset($response['person'])) {
    $response = $response['person'];
  }
  else {
    $response = $response['error'];
  }
  if (variable_get('linkedin_debug_mode', 0) == 1) {
    if (isset($response['error-code'])) {
      drupal_set_message(t('Linkedin debug : LinkedIn.com answered "@status : @message', array('@status' => $response['status'], '@message' => $response['message'])));
    }
  }
  return $response;
}

/*
 * Returns an array contening the fields requested.
 * @params
 * $url : full request url to a linkedin API ressource (see API doc for syntax)
 * $tokens : the user tokens, as an array containing keys 'token_key' and 'token_secret' with their value
 */

/**
 * @todo Please document this function.
 * @see http://drupal.org/node/1354
 */
function _linkedin_get_fields($url, $tokens) {
  //Get sure library is loaded before doing anything.
  linkedin_init();

  $signature = new OAuthSignatureMethod_HMAC_SHA1();
  $consumer_key = variable_get('linkedin_consumer_key', '');
  $consumer_secret = variable_get('linkedin_consumer_secret', '');
  $consumer = new OAuthConsumer($consumer_key, $consumer_secret, NULL);
  $token = new OAuthConsumer($tokens['token_key'], $tokens['token_secret'], 1);
  $request = OAuthRequest::from_consumer_and_token($consumer, $token, "GET", $url);
  $request->sign_request($signature, $consumer, $token);
  $header = $request->to_header("https://api.linkedin.com");
  $response = _linkedin_http_request($url, $header);
  parse_str($response);
  $response = _linkedin_parse_fields($response);
  if (isset($response['error-code'])) {
    $message = t('Linkedin debug : LinkedIn.com answered "@status : @message', array('@status' => $response['status'], '@message' => $response['message']));
    if (variable_get('linkedin_debug_mode', 0) == 1) {
      drupal_set_message($message, 'warning');
    }
    watchdog('warning', $message);
  }
  return $response;
}

/*
 * Let us 'put' data into user profile.
 * Usage :
 * $uid : the uid of the user we want to access infos
 * $api : the api we want to use to update. For now, only Share API is available
 * $body : The content to be sent.
 */

/**
 * @todo Please document this function.
 * @see http://drupal.org/node/1354
 */
function _linkedin_put_profile_field($uid, $body, $api = 'shares') {
  //Get sure library is loaded before doing anything.
  linkedin_init();

  $base_url = 'https://api.linkedin.com/v1/people/~/';
  $url = $base_url . $api;

  if ($api == 'shares') {
    $xml = '<share>';
    if (isset($body['comment'])) {
      $xml .= '<comment>' . $body['comment'] . '</comment>';
    }
    if (isset($body['title']) && isset($body['submitted-url'])) {
      $xml .= '<content>';
      $xml .= '<title>' . $body['title'] . '</title>';
      $xml .= '<submitted-url>' . $body['submitted-url'] . '</submitted-url>';
      if (isset($body['submitted-image-url'])) {
        $xml .= '<submitted-image-url>' . $body['submitted-image-url'] . '</submitted-image-url>';
      }
      if (isset($body['description'])) {
        $xml .= '<description>' . $body['description'] . '</description>';
      }
      $xml .= '</content>';
    }
    $xml .= '<visibility><code>anyone</code></visibility>';
    $xml .= '</share>';
  }
  else {
    // Unsupported update method
    $message = t('Linkedin debug : Unsupported update method "@method"', array('@method' => $api));
    if (variable_get('linkedin_debug_mode', 0) == 1) {
      drupal_set_message($message, 'warning');
    }
    watchdog('warning', $message);
    return;
  }

  $signature = new OAuthSignatureMethod_HMAC_SHA1();
  $consumer_key = variable_get('linkedin_consumer_key', '');
  $consumer_secret = variable_get('linkedin_consumer_secret', '');
  $consumer = new OAuthConsumer($consumer_key, $consumer_secret, NULL);
  $row = db_query("SELECT * FROM {linkedin_token} WHERE uid = :uid AND type = :type", array(':uid' => $uid, ':type' => 'access'))->fetchAssoc();
  $token = new OAuthConsumer($row['token_key'], $row['token_secret'], 1);
  $request = OAuthRequest::from_consumer_and_token($consumer, $token, 'POST', $url, array());
  $request->sign_request($signature, $consumer, $token);
  $header = $request->to_header();
  $response = _linkedin_http_request($url, $header, $xml);
  if (isset($response['error-code'])) {
    $message = t('Linkedin debug : LinkedIn.com answered "@status : @message', array('@status' => $response['status'], '@message' => $response['message']));
    if (variable_get('linkedin_debug_mode', 0) == 1) {
      drupal_set_message($message, 'warning');
    }
    watchdog('warning', $message);
  }
  return $response;
}

/*
 * Some internal helper functions...
 */

function _linkedin_http_request($url, $header, $body = NULL) {

  $ch = curl_init();

  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 1);
  curl_setopt($ch, CURLOPT_HTTPHEADER, array($header));
  curl_setopt($ch, CURLOPT_URL, $url);

  if ($body) {
    curl_setopt($ch, CURLOPT_POST, 1);
    if ($body == 'token_request') {
      curl_setopt($ch, CURLOPT_POSTFIELDS, '');
    }
    else {
      curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
      curl_setopt($ch, CURLOPT_HTTPHEADER, array($header, 'Content-Type: text/xml;charset=utf-8'));
      curl_setopt($ch, CURLOPT_POST, 1);
      curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
    }
  }

  $output = curl_exec($ch);
  curl_close($ch);
  return $output;
}

/*
 * Parser function. Based on xml2array() by Binny V A :  http://www.bin-co.com/php/scripts/xml2array/
 */

function _linkedin_parse_fields($contents) {
  if (!$contents) {
    return array();
  }

  if (!function_exists('xml_parser_create')) { //Get the XML parser of PHP - PHP must have this module for the parser to work
    if (variable_get('linkedin_debug_mode', 0) == 1) {
      drupal_set_message(t('Unable to find PHP parser. This module needs php-xml lib'), 'warning');
    }
    return array();
  }


  $parser = xml_parser_create('');
  xml_parser_set_option($parser, XML_OPTION_TARGET_ENCODING, "UTF-8"); // http://minutillo.com/steve/weblog/2004/6/17/php-xml-and-character-encodings-a-tale-of-sadness-rage-and-data-loss
  xml_parser_set_option($parser, XML_OPTION_CASE_FOLDING, 0);
  xml_parser_set_option($parser, XML_OPTION_SKIP_WHITE, 1);
  xml_parse_into_struct($parser, trim($contents), $xml_values);
  xml_parser_free($parser);

  if (!$xml_values) {
    return;
  }
  $xml_array = array();
  $parents = array();
  $opened_tags = array();
  $arr = array();

  $current = &$xml_array; //Reference
  //Go through the tags.
  $repeated_tag_index = array(); //Multiple tags with same name will be turned into an array
  foreach ($xml_values as $data) {
    unset($attributes, $value); //Remove existing values, or there will be trouble
    //This command will extract these variables into the foreach scope
    // tag(string), type(string), level(int), attributes(array).
    extract($data); //We could use the array by itself, but this cooler.

    $result = array();
    $attributes_data = array();

    if (isset($value)) {
      $result = $value;
    }
    //See tag status and do the needed.
    if ($type == "open") { //The starting of the tag '<tag>'
      $parent[$level - 1] = &$current;
      if (!is_array($current) or (!in_array($tag, array_keys($current)))) { //Insert New tag
        $current[$tag] = $result;
        if ($attributes_data) {
          $current[$tag . '_attr'] = $attributes_data;
        }
        $repeated_tag_index[$tag . '_' . $level] = 1;

        $current = &$current[$tag];
      }
      else { //There was another element with the same tag name
        if (isset($current[$tag][0])) { //If there is a 0th element it is already an array
          $current[$tag][$repeated_tag_index[$tag . '_' . $level]] = $result;
          $repeated_tag_index[$tag . '_' . $level]++;
        }
        else { //This section will make the value an array if multiple tags with the same name appear together
          $current[$tag] = array($current[$tag], $result); //This will combine the existing item and the new item together to make an array
          $repeated_tag_index[$tag . '_' . $level] = 2;

          if (isset($current[$tag . '_attr'])) { //The attribute of the last(0th) tag must be moved as well
            $current[$tag]['0_attr'] = $current[$tag . '_attr'];
            unset($current[$tag . '_attr']);
          }
        }
        $last_item_index = $repeated_tag_index[$tag . '_' . $level] - 1;
        $current = &$current[$tag][$last_item_index];
      }
    }
    elseif ($type == "complete") { //Tags that ends in 1 line '<tag />'
      //See if the key is already taken.
      if (!isset($current[$tag])) { //New Key
        $current[$tag] = $result;
        $repeated_tag_index[$tag . '_' . $level] = 1;
        if ($attributes_data) {
          $current[$tag . '_attr'] = $attributes_data;
        }
      }
      else { //If taken, put all things inside a list(array)
        if (isset($current[$tag][0]) && is_array($current[$tag])) { //If it is already an array...
          // ...push the new element into that array.
          $current[$tag][$repeated_tag_index[$tag . '_' . $level]] = $result;


          $repeated_tag_index[$tag . '_' . $level]++;
        }
        else { //If it is not an array...
          $current[$tag] = array($current[$tag], $result); //...Make it an array using using the existing value and the new value
          $repeated_tag_index[$tag . '_' . $level] = 2; //0 and 1 index is already taken
        }
      }
    }
    elseif ($type == 'close') { //End of tag '</tag>'
      $current = &$parent[$level - 1];
    }
  }

  return ($xml_array);
}

/*
 * Filter the requested fields to match the type of profile (public or auth)
 */

function _linkedin_build_fields_request($fields, $type = 'auth') {
  if (!empty($fields) || is_array($fields)) {
    $fieldslist = _linkedin_list_fields($type);
    $requested = '';
    foreach ($fields as $field) {
      if (in_array($field, $fieldslist)) {
        $requested .= $field . ',';
      }
    }
    $request = ':(' . trim($requested, ',') . ')';
  }
  return $request;
}

/*
 * Provides a list of available LinkedIn fields
 * $type : 'public' or 'auth'. Wether we need 'public' or 'standard' fields
 */

function _linkedin_list_fields($type = 'auth') {
  $fields = array(
    'id',
    'first-name',
    'last-name',
    'headline',
    'location',
    'industry',
    'summary',
    'specialties',
    'honors',
    'interests',
    'num-recommenders',
    'member-url-resources',
    'picture-url',
    'picture-urls::(original)',
    'public-profile-url',
    'positions',
    'educations',
    //          @TODO //          'site-standard-profile-request', //          'api-standard-profile-request', //          'api-public-profile-request', Deprecated ? //          'site-public-profile-request', Deprecated ? //          'member-url', // Deprecated ?
  );
  if ($type == 'auth') {
    $standard_fields = array(
      'distance',
      'current-status',
      'current-status-timestamp',
      'num-connections',
      'num-connections-capped',
      'associations',
      'phone-numbers',
      'im-accounts',
      'twitter-accounts',
      'date-of-birth',
      'main-address',
      //        @TODO //        'relation-to-viewer', //        'proposal-comments', //        'recommendations-received',
    );
    $fields = array_merge($fields, $standard_fields);
  }
  return $fields;
}
