<?php

App::uses('Router', 'Routing');
App::uses('Component', 'Controller');
App::uses('AuthComponent', 'Controller');


class OAuthClientComponent extends Component
{
	public $Controller = null;
	
	public $defaults = array(
		'serverLogout' => true,
	);

	public function initialize(Controller $Controller) 
	{
		$this->Controller = & $Controller;
		$this->settings = array_merge($this->defaults, $this->settings);
	}
	
	public function OAC_Login()
	{
		// if they're already logged in
		if ($this->Controller->Auth->user('id'))
		{
			return $this->Controller->redirect($this->Controller->Auth->redirect());
		}
		
		if(!$this->Controller->Session->read('OAuthClient.redirect'))
		{
			$this->Controller->Session->write('OAuthClient.redirect', $this->Controller->Auth->redirect());
		}
		
		$modelClass = $this->Controller->modelClass;
		
		
		// oauth login redirected back to us
		if($this->Controller->request->query('code'))
		{
			// login the user and update their information that we get from the oauth server
			if(!$login_info = $this->Controller->{$modelClass}->OAC_Login($this->Controller->request->query('code')))
			{
				CakeLog::write('oauth_client', $this->Controller->{$modelClass}->oacError);
			
				if(isset($this->Controller->{$modelClass}->oacErrorRedirect) and $this->Controller->{$modelClass}->oacErrorRedirect)
				{
					$this->Controller->Flash->error(__('Error: %s', $this->Controller->{$modelClass}->oacError));
					$redirect = $this->Controller->Session->read('OAuthClient.redirect');
					return $this->Controller->redirect($redirect);
				}
				
				throw new UnauthorizedException($this->Controller->{$modelClass}->oacError);
			
			}
			
			if($this->Controller->Auth->login($login_info))
			{
				// Log their last login as now
				$this->Controller->{$modelClass}->lastLogin(AuthComponent::user('id'));
				$this->Controller->{$modelClass}->loginAttempt($this->Controller->request->data, true, AuthComponent::user('id'));
				$this->Controller->Flash->success(__('Welcome back, %s', (AuthComponent::user('name')?AuthComponent::user('name'):AuthComponent::user('email'))));
				
				$redirect = $this->Controller->Session->read('OAuthClient.redirect');
				$this->Controller->Session->delete('OAuthClient.redirect');
				return $this->Controller->redirect($redirect);
			}
		}
		
		// an error was reported by the server
		elseif($this->Controller->request->query('error'))
		{
			$this->Controller->{$modelClass}->oacError = __('An error occured while trying to authenticate you. (%s)', $this->Controller->request->query('error'));
			if($this->Controller->request->query('error_description'))
			{
				$this->Controller->{$modelClass}->oacError = __('(%s) %s', $this->Controller->request->query('error'), $this->Controller->request->query('error_description'));
			}
			
			throw new UnauthorizedException($this->Controller->{$modelClass}->oacError);
		}
		// redirect them to the oauth server for authorization
		else
		{
			$oac_login_url = $this->Controller->{$modelClass}->OAC_getLoginUrl();
			return $this->Controller->redirect($oac_login_url);
		}
	}
}