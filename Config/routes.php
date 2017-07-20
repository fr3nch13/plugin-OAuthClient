<?php

Router::connect('/oauth_client/:action/*', array('controller' => 'OAuthClient', 'plugin' => 'o_auth_client'));