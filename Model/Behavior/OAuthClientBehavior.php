<?php

require_once ROOT. DS. 'Vendor'. DS. 'nihfo-vendors/php-oauth2-client/src/OAuth2/Client.php';
require_once ROOT. DS. 'Vendor'. DS. 'nihfo-vendors/php-oauth2-client/src/OAuth2/GrantType/IGrantType.php';
require_once ROOT. DS. 'Vendor'. DS. 'nihfo-vendors/php-oauth2-client/src/OAuth2/GrantType/AuthorizationCode.php';

/*
App::import(array('type' => 'Vendor', 'name' => 'VendorOAuthClient', 'file' => 	'PHP-OAuth2/src/OAuth2/Client.php'));
App::import(array('type' => 'Vendor', 'name' => 'IGrantType', 'file' => 		'PHP-OAuth2/src/OAuth2/GrantType/IGrantType.php'));
App::import(array('type' => 'Vendor', 'name' => 'AuthorizationCode', 'file' => 	'PHP-OAuth2/src/OAuth2/GrantType/AuthorizationCode.php'));

App::import('Vendor', 'Client', 'PHP-OAuth2/src/OAuth2/Client.php');
App::import('Vendor', 'PHP-OAuth2/src/OAuth2/GrantType/IGrantType.php');
App::import('Vendor', 'PHP-OAuth2/src/OAuth2/GrantType/AuthorizationCode.php');
*/
class OAuthClientBehavior extends ModelBehavior 
{
	public $settings = array();
	private $_defaults = array(
		'redirectUrl' => array('plugin' => false, 'controller' => 'users', 'action' => 'login', 'admin' => false, 'prefix' => false),
	);
	
	private $OAuthClient = false; // holds the vendor class to interact with facebook
	
	private $clientId = false;
	private $clientSecret = false;
	private $serverURI = false;
	private $authorizationPath = '/oauth/authorize.oauth';
	private $logoutPath = '/users/logout';
	private $tokenPath = '/oauth/token.oauth';
	private $userinfoPath = '/oauth/userinfo.oauth';
	
	public $redirectUrl = false;
	private $accessToken = false;
	private $code = false;
	
	
	public function setup(Model $Model, $config = array())
	{
		$this->settings[$Model->alias] = array_merge($this->_defaults, $config);
		
		$Model->oacError = false;
		
		$this->clientId = Configure::read('OAuth.clientId');
		$this->clientSecret = Configure::read('OAuth.clientSecret');
		$this->serverURI = Configure::read('OAuth.serverURI');

		$this->OAuthClient = new OAuth2\Client($this->clientId, $this->clientSecret);
	}
	
	public function OAC_getLoginUrl(Model $Model, $redirect_uri = array())
	{
		if($redirect_uri)
		{
			$this->OAC_setRedirectUrl($Model, $redirect_uri);
		}
		
		return $this->OAuthClient->getAuthenticationUrl($this->serverURI. $this->authorizationPath, $this->OAC_getRedirectUrl($Model));
	}
	
	public function OAC_Login(Model $Model, $code = false)
	{
		$Model->oacErrorRedirect = false;
		$this->OAC_setCode($Model, $code);
		if(!$oac_user = $this->OAC_getUser($Model))
		{
			if(!$Model->oacError)
				$Model->oacError = __('(1) Unable to get your information from the OAuth Server.');
			return false;
		}
		
		// see if the org groups are being passed to us, if so update them
		if(isset($oac_user['orgGroups']) and is_array($oac_user['orgGroups']) and isset($Model->OrgGroup))
		{
			foreach($oac_user['orgGroups'] as $orgGroup)
			{
				if(!isset($orgGroup['OrgGroup']['id']))
					continue;
				
				$Model->OrgGroup->id = $orgGroup['OrgGroup']['id'];
				$Model->OrgGroup->data = $orgGroup['OrgGroup'];
				$Model->OrgGroup->save($Model->OrgGroup->data);
			}
			unset($oac_user['orgGroups']);
		}
		
		$conditions = array();
		
		if(isset($oac_user['email']) and $oac_user['email'])
		{
			$conditions['email'] = strtolower($oac_user['email']);
		}
		
		if(isset($oac_user['adaccount']) and $oac_user['adaccount'])
		{
			$conditions['adaccount'] = strtolower($oac_user['adaccount']);
		}
		
		if(!$conditions)
		{
			$Model->oacError = __('(2) Unable to get your information from the OAuth Server.');
			return false;
		}
		
		$user = $Model->find('first', array(
			'recursive' => -1,
			'conditions' => array('OR' => $conditions),
		));
		
		// add the user
		if(!$user)
		{
			/// add the user based on the oac_user info
			$Model->create();
			$Model->data = $oac_user;
			$Model->save($Model->data);
		}
		// update the user info
		else
		{
			// remove some local settings
			if(isset($oac_user['paginate_items']))
				unset($oac_user['paginate_items']);
			
			if(isset($user['User']['created']))
				unset($user['User']['created']);
			
			if(isset($user['User']['modified']))
				unset($user['User']['modified']);
			
			if(isset($user['User']['lastlogin']))
				unset($user['User']['lastlogin']);
			
			$Model->id = $user['User']['id'];
			$Model->data['User'] = array_merge($user['User'], $oac_user);
			$Model->save($Model->data);
		}
		
		$user = $Model->find('first', array(
			'recursive' => -1,
			'conditions' => array('id' => $Model->id),
		));
		
		if(!$user['User']['active'])
		{
			$Model->oacError = __('Your account is not locally active.');
			return false;
		}
		return $user['User'];
	}
	
	public function OAC_getUser(Model $Model, $code = false)
	{
		$Model->oacError = false;
		$Model->oacErrorRedirect = false;
		
		$params = array('code' => $this->OAC_getCode($Model), 'redirect_uri' => $this->OAC_getRedirectUrl($Model));
		$headers = array();
		if(isset($_SERVER['HTTP_COOKIE']))
			$headers['cookie'] = $_SERVER['HTTP_COOKIE'];
		$response = $this->OAuthClient->getAccessToken($this->serverURI. $this->tokenPath, 'authorization_code', $params, $headers);
		
		// see if we have an error
		if(isset($response['result']['error']))
		{
			$Model->oacError = __('An error occured while trying to authenticate you. (%s)', $response['result']['error']);
			if(isset($response['result']['error_description']))
			{
				$Model->oacError = __('(%s) %s', $response['result']['error'], $response['result']['error_description']);
				if(preg_match('/expired/i', $response['result']['error_description']))
				{
					$Model->oacErrorRedirect = true;
				}
			}
			
			return false;
		}
		
		if(!isset($response['result']['access_token']))
		{
			$Model->oacErrorRedirect = true;
			$Model->oacError = __('Unknown Access Token.');
			return false;
		}
		
		$this->OAuthClient->setAccessToken($response['result']['access_token']);
		$user_info = $this->OAuthClient->fetch($this->serverURI. $this->userinfoPath, array(), 'GET', $headers);
		return $user_info['result'];
	}
	
	public function OAC_setRedirectUrl(Model $Model, $redirectUrl = false)
	{
		$this->redirectUrl = $redirectUrl;
	}
	
	public function OAC_getRedirectUrl(Model $Model, $implode = true)
	{
		if(!$this->redirectUrl)
			$this->OAC_setRedirectUrl($Model, $this->settings[$Model->alias]['redirectUrl']);
		
		$redirectUrl = $this->redirectUrl;
		
		if($implode and is_array($redirectUrl))
		{
			$redirectUrl = Router::url($redirectUrl, true);
		}
		
		return $redirectUrl;
	}
	
	public function OAC_setCode(Model $Model, $code = false)
	{
		$this->code = $code;
	}
	
	public function OAC_getCode(Model $Model, $code = false)
	{
		return $this->code;
	}
	
	public function OAC_setState(Model $Model, $state = false)
	{
		$this->state = $state;
	}
	
	public function OAC_getState(Model $Model, $state = false)
	{
		return $this->state;
	}
	
	public function OAC_getLogoutUrl(Model $Model)
	{
		return $this->OAuthClient->getAuthenticationUrl($this->serverURI. $this->logoutPath, $this->OAC_getRedirectUrl($Model));
	}
}