<?php
/**
 * @version		$Id$
 * @package		Joomla
 * @subpackage	JFramework
 * @author    	Antonio Musarra <antonio.musarra@gmail.com>
 * @copyright	Copyright (C) 2010 Antonio Musarra. All rights reserved.
 * @license		http://www.gnu.org/copyleft/gpl.html GNU/GPL
 * @link		http://musarra.wordpress.com
 */

// Check to ensure this file is included in Joomla!
defined( '_JEXEC' ) or die( 'Restricted access' );

jimport('joomla.plugin.plugin');
jimport('joomla.error.log');

/**
 * SugarCRM Authentication Plugin Over SOAP
 *
 * @package		Joomla
 * @subpackage	JFramework
 * @since 1.5
 */
class plgAuthenticationSugarCRMOverSoap extends JPlugin
{
	/**
	 * Constructor
	 *
	 * For php4 compatability we must not use the __constructor as a constructor for plugins
	 * because func_get_args ( void ) returns a copy of all passed arguments NOT references.
	 * This causes problems with cross-referencing necessary for the observer design pattern.
	 *
	 * @param	object	$subject	The object to observe
	 * @param	array	$config		An array that holds the plugin configuration
	 * @since	1.5
	 */
	function plgAuthenticationSugarCRMOverSoap(& $subject, $config)
	{
		parent::__construct($subject, $config);
	}

	/**
	 * This method should handle any authentication and report back to the subject
	 *
	 * @access	public
	 * @param	array	$credentials	Array holding the user credentials
	 * @param	array	$options		Array of extra options
	 * @param	object	$response		Authentication response object
	 * @return	boolean
	 * @since	1.5
	 */
	function onAuthenticate( $credentials, $options, &$response )
	{
		/*
		 * Here you would do whatever you need for an authentication routine with the credentials
		 *
		 * In this example the mixed variable $return would be set to false
		 * if the authentication routine fails or an integer userid of the authenticated
		 * user if the routine passes
		 */

		// Initialize variables
		$userdetails = null;
		$sugarcrm_session_id = null;
		$sugarcrm_user_id = null;
		$sugarcrmPortalUserAPI = $this->params->get('PortalUserAPI');
		$sugarcrmPortalUserAPIPassword = $this->params->get('PortalUserAPIPassword');
		
		$jlog = &JLog::getInstance('sugarcrmauth.log');
		$jSession = &JSession::getInstance('none', array());
		
		// For JLog
		$response->type = 'SUGARCRM_SOAP';

		// Load plugin params info
		$sugarcrm_checkportal = (boolean)$this->params->get('CheckPortalEnabled');
		$sugarcrm_debug = (boolean) $this->params->get('DebugEnabled');

		// SugarCRM SOAP does not like Blank passwords (tries to Anon Bind which is bad)
		if (empty($credentials['password']))
		{
			$response->status = JAUTHENTICATE_STATUS_FAILURE;
			$response->error_message = 'SugarCRM SOAP can not have blank password';
			$jlog->addEntry(array('comment' => $response->error_message, 'status' => $response->status));
			return false;
		}

		// If SugarCRM Pro and Ent password must be hashed (md5)
		if ($this->params->get('SugarCRMEd') == '1' || $this->params->get('SugarCRMEd') == '2') {
			$credentials['password'] = md5($credentials['password']);
			$sugarcrmPortalUserAPIPassword = md5($sugarcrmPortalUserAPIPassword);
		}

		// Set WSDL Cache
		ini_set("soap.wsdl_cache_enabled", $this->params->get('WSDLCache'));

		try {
			// Setup SOAP Client and Call Login SOAP Operation
			$client = new SoapClient($this->params->get('SoapEndPoint'), array('trace' => 1));
			if ($sugarcrm_checkportal) {
				if (empty($sugarcrmPortalUserAPI) || empty($sugarcrmPortalUserAPIPassword)) {
					$response->status = JAUTHENTICATE_STATUS_FAILURE;
					$response->error_message = 'SugarCRM Portal API can not have blank User API or Password';
					$jlog->addEntry(array('comment' => $response->error_message, 'status' => $response->status));
					return false;
				}
				$portal_auth = array('user_name' => $sugarcrmPortalUserAPI, 'password' => $sugarcrmPortalUserAPIPassword,
									'version' => '');
				$contact_portal_auth = array('user_name' => $credentials['username'], 'password' => $credentials['password'],
											'version' => '');
				$auth_result = $client->portal_login_contact($portal_auth, $contact_portal_auth, $this->params->get('ApplicationName'));
				
			} else {
				$auth_array = array('user_name' => $credentials['username'], 'password' => $credentials['password'],
				'version' => '');
				$auth_result = $client->login($auth_array, $this->params->get('ApplicationName'));
			}

			if ($sugarcrm_debug) {
				$jlog->addEntry(array('comment' => $client->__getLastRequest(), 'status' =>  '0'));
				$jlog->addEntry(array('comment' => $client->__getLastResponseHeaders(), 'status' =>  '0'));
				$jlog->addEntry(array('comment' => $client->__getLastResponse(), 'status' =>  '0'));
			}

			// Check SugarCRM Login Action && Lookup User Data
			if ($auth_result->error->number != "0" || $auth_result->id == "-1") {
				$response->status			= JAUTHENTICATE_STATUS_FAILURE;
				$response->error_message	= $auth_result->error->number . " - " . $auth_result->error->name . " - " .$auth_result->error->description;
				$jlog->addEntry(array('comment' => $response->error_message, 'status' => $response->status));
				return false;
			}

			// Save SugarCRM Users Session ID
			$sugarcrm_session_id = $auth_result->id;

			// Save SugarCRM User ID
			if ($sugarcrm_checkportal) {
				$result = $client->portal_get_sugar_contact_id($auth_result->id);
				$sugarcrm_user_id = $result->id;
			}
			else
				$sugarcrm_user_id = $client->get_user_id($auth_result->id);
			

			if ($sugarcrm_debug) {
				$jlog->addEntry(array('comment' => $client->__getLastRequest(), 'status' =>  '0'));
				$jlog->addEntry(array('comment' => $client->__getLastResponseHeaders(), 'status' =>  '0'));
				$jlog->addEntry(array('comment' => $client->__getLastResponse(), 'status' =>  '0'));
				$jlog->addEntry(array('comment' => 'SugarCRM SessionID: ' . $sugarcrm_session_id, 'status' =>  '0'));
				$jlog->addEntry(array('comment' => 'SugarCRM UserID or Contact ID: ' . $sugarcrm_user_id, 'status' =>  '0'));
			}

			// Admin not login
			if ($sugarcrm_user_id <> "1") {
				// Get SugarCRM User Data
				if ($sugarcrm_checkportal)
					$user_data = $client->portal_get_entry($auth_result->id,'Contacts',$sugarcrm_user_id);
				else 
					$user_data = $client->get_entry($auth_result->id,'Users',$sugarcrm_user_id);
					
				if ($user_data->error->number <> 0) {
					$response->status			= JAUTHENTICATE_STATUS_FAILURE;
					$response->error_message	= $user_data->error->number . " - " . $user_data->error->name . " - " . $user_data->error->description;
					$jlog->addEntry(array('comment' => $response->error_message, 'status' => $response->status));
					return false;

				} else {
					$response->status			= JAUTHENTICATE_STATUS_SUCCESS;
					$response->error_message	= '';

					foreach ($user_data->entry_list[0]->name_value_list as $key => $value) {
						if ($value->name == 'first_name')
						$response->fullname = $value->value . " ";
						if ($value->name == 'last_name')
						$response->fullname .= $value->value;
						if ($value->name == 'email1')
						$response->email = $value->value;
					}

					if ($sugarcrm_debug) {
						$jlog->addEntry(array('comment' => $client->__getLastRequest(), 'status' =>  '0'));
						$jlog->addEntry(array('comment' => $client->__getLastResponseHeaders(), 'status' =>  '0'));
						$jlog->addEntry(array('comment' => $client->__getLastResponse(), 'status' =>  '0'));
					}
					
					$jlog->addEntry(array('comment' => 'Login on SugarCRM Success', 'status' =>  JAUTHENTICATE_STATUS_SUCCESS));

					// Set SugarCRM Session Token
					$jSession->set('session.sugarcrm_token', $sugarcrm_session_id);
					
					return true;
				}
			} else {
				$response->status			= JAUTHENTICATE_STATUS_FAILURE;
				$response->error_message	= "Admin user not login from Joomla CMS";
				$jlog->addEntry(array('comment' => $response->error_message, 'status' => $response->status));
				return false;
			}
		} catch (Exception $e) {
			$response->status			= JAUTHENTICATE_STATUS_FAILURE;
			$response->error_message	= $e->getMessage();
			$jlog->addEntry(array('comment' => $e->getMessage(), 'status' => $e->getCode()));
			$jlog->addEntry(array('comment' => $client->__getLastRequest(), 'status' => JAUTHENTICATE_STATUS_FAILURE));
			$jlog->addEntry(array('comment' => $client->__getLastResponse(), 'status' => JAUTHENTICATE_STATUS_FAILURE));
			return false;
		}
	}
}
