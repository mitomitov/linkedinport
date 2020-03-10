<?php
    namespace OAuth2;

    class ExtendClient extends Client {
        public function getAccessToken($redirect = TRUE) {
    // Check whether the existing token has expired.
    // We take the expiration time to be shorter by 10 sec
    // in order to account for any delays during the request.
    // Usually a token is valid for 1 hour, so making
    // the expiration time shorter by 10 sec is insignificant.
    // However it should be kept in mind during the tests,
    // where the expiration time is much shorter.
    $expiration_time = $this->token['expiration_time'];
    //promqna ot men
    if ($expiration_time > (time() + 10) && $redirect == TRUE) {
      // The existing token can still be used.
      return $this->token['access_token'];
    }

    try {
      // Try to use refresh_token.
      $token = $this->getTokenRefreshToken();
    }
    catch (\Exception $e) {
      // Get a token.
      switch ($this->params['auth_flow']) {
        case 'client-credentials':
          $token = $this->getToken(array(
                     'grant_type' => 'client_credentials',
                     'scope' => $this->params['scope'],
                   ));
          break;

        case 'user-password':
          $token = $this->getToken(array(
                     'grant_type' => 'password',
                     'username' => $this->params['username'],
                     'password' => $this->params['password'],
                     'scope' => $this->params['scope'],
                   ));
          break;

        case 'server-side':
          if ($redirect) {
            $token = $this->getTokenServerSide();
          }
          else {
            $this->clearToken();

            return NULL;
          }
          break;

        default:
          throw new \Exception(t('Unknown authorization flow "!auth_flow". Suported values for auth_flow are: client-credentials, user-password, server-side.',
              array('!auth_flow' => $this->params['auth_flow'])));
      }
    }
    $token['expiration_time'] = REQUEST_TIME + $token['expires_in'];

    // Store the token (on session as well).
    $this->token = $token;
    static::storeToken($this->id, $token);

    // Redirect to the original path (if this is a redirection
    // from the server-side flow).
    static::redirect();

    // Return the token.
    return $token['access_token'];
  }
  
  /**
   * Get and return an access token for the grant_type given in $params.
   */
  protected function getToken($data) {
    if (array_key_exists('scope', $data) && is_null($data['scope'])) {
      unset($data['scope']);
    }


    $token_endpoint = $this->params['token_endpoint'];
  
    $data['client_id'] = $this->params['client_id'];
    $data['client_secret'] = $this->params['client_secret'];
  
    $options = array(
      'method' => 'POST',
      'data' => drupal_http_build_query($data),
      'headers' => array(
        'Content-Type' => 'application/x-www-form-urlencoded',
      ),
    );
    if ($this->params['skip-ssl-verification']) {
      $options['context'] = stream_context_create(array(
        'ssl' => array(
          'verify_peer' => FALSE,
          'verify_peer_name' => FALSE,
        ),
      ));
    }
    $result = drupal_http_request($token_endpoint, $options);

    if ($result->code != 200) {
      throw new \Exception(
        t("Failed to get ana access token of grant_type @grant_type.\nError: @result_error",
          array(
            '@grant_type' => $data['grant_type'],
            '@result_error' => $result->error,
          ))
      );
    }

    $token = drupal_json_decode($result->data);
    if (!isset($token['expires_in'])) {

      $token['expires_in'] = 3600;
    }

    return $token;
  }
  
    }