<?php

App::uses('OAuthClientAppController', 'OAuthClient.Controller');

class OAuthClientController extends OAuthClientAppController 
{
	public $uses = ['User', 'Client'];
	
	public function beforeFilter() 
	{
		$this->Auth->allow(['index']);
		
		$this->RequestHandler->setContent('oauth', 'application/json');
		return parent::beforeFilter();
	}
	
	public function index()
	{
		$start = time();
		$data = [
			'code' => 200,
			'name' => 'initial',
			'message' => 'Initial data settings',
			'time_start' => 0,
			'time_end' => 0,
			'time_diff' => 0,
		];
		
		if(!$this->request->is('post'))
		{
			throw new MethodNotAllowedException('Request much be a POST');
		}
		
		///// authenticate that this is indeed the accounts portal talking to me
		// make sure it sent the id and secret
		if(!isset($this->request->data['client_id']) or !isset($this->request->data['client_secret']))
		{
			throw new BadRequestException('The request is missing the Client ID and/or the Client Secret');
		}
		
		// validate the id and secret
		$config = Configure::read('OAuth');
		
		if(!isset($config['clientId']) or !isset($config['clientSecret']))
		{
			throw new BadRequestException('The client is missing its Client ID and/or the Client Secret in the config.');
		}
		if($config['clientId'] != $this->request->data['client_id'])
		{
			throw new UnauthorizedException('Invalid Client ID');
		}
		if($config['clientSecret'] != $this->request->data['client_secret'])
		{
			throw new UnauthorizedException('Invalid Client Secret');
		}
		
		// make sure they're sending us requests
		if(!isset($this->request->data['requests']))
		{
			throw new NotFoundException('No requests were sent to this Client.');
		}
		
		if(!is_array($this->request->data['requests']))
		{
			throw new BadRequestException('The requests are not in the proper format (must be an array).');
		}
		
		$total = 0;
		$updated = 0;
		foreach($this->request->data['requests'] as $model => $modelData)
		{
			// only allow minipulation of the models that are allowed to be access by this controller
			if(!isset($this->{$model}))
				continue;
			
			if(!$this->{$model}->primaryKey)
				continue;
			
			if(!is_array($modelData))
				$modelData = $this->Common->objectToArray(json_decode($modelData));
			
			// update each record
			foreach($modelData as $i => $modelRecord)
			{
				$total++;
				if(!isset($modelRecord[$model][$this->{$model}->primaryKey]))
					continue;
				
				$this->{$model}->id = $modelRecord[$model][$this->{$model}->primaryKey];
				$this->{$model}->data = $modelRecord[$model];
				if($this->{$model}->save($this->{$model}->data))
				{
					$updated++;
				}
			}
		}
		
		$data['name'] = 'success';
		$data['message'] = __('Updated records. total: %s, updated: %s', $total, $updated);
		
		$end = time();
		$diff = $end - $start;
		$data['time_start'] = $start;
		$data['time_end'] = $end;
		$data['time_diff'] = $diff;
		
		$this->set($data);
		$this->set('_serialize', array_keys($data));
	}
}