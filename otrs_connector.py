#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Phantom App imports
from urllib import response
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from otrs_consts import *
import os
import requests
import json
from pyotrs import Client, Ticket, Article, DynamicField

from django.http import HttpResponse, JsonResponse
from phantom_common.install_info import get_rest_base_url
REST_BASE_URL = get_rest_base_url()

def handle_request(request, path_parts):
    import rpdb; rpdb.set_trace()
    return JsonResponse({
        'success': True,
        'messages': "messages"
    })

class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))

class OtrsConnector(BaseConnector):
    def __init__(self):
        # Call the BaseConnectors init first
        super(OtrsConnector, self).__init__()

        self._state = None
        self.config = None

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to API")
        try:
            ret_val = self.client.session_restore_or_create()
        except Exception as exc:
            ret_val = False
        
        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed.")
            return action_result.set_status(phantom.APP_ERROR)

        # Return success
        self.save_progress("Test Connectivity Passed.")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _create_article(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        try:
            # Add an action result object to self (BaseConnector) to represent the action for this param
            # action_result = self.add_action_result(ActionResult(dict(param)))
            subject = param.get('article_subject', '')
            body = param.get('article_body', '')

            article = Article(
                {
                    'Subject'   : subject,
                    'Body'      : body, 
                    'MimeType'  : 'text/html'
                    }
                )

            # action_result.add_data(article.to_dct())
            ret_val = True
        except:
            ret_val = False
                    
        if phantom.is_fail(ret_val):
            raise Exception("Article creation failed.") 

        # action_result.set_status(phantom.APP_SUCCESS)
        return article

    def _handle_create_ticket(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        title = param.get('ticket_title', '')
        customer_username = param.get('ticket_customer_username', '')
        state = param.get('ticket_state', '')
        queue = param.get('ticket_queue', '')
        type_id = param.get('ticket_type_id', '')
        priority = param.get('ticket_priority', None)
        dynamic_fields = json.loads(param.get('dynamic_fields', '{}'))
        if priority:
            priority_id = self._priority_mapping(priority)
        else:
            priority_id = None        
        
        try:
            article = self._create_article(param)
        except Exception as e:
            action_result.add_data({"Exception": repr(e)})
            return action_result.set_status(phantom.APP_ERROR)
        
        ticket = Ticket.create_basic(
            Title        = title,
            Queue        = queue,
            State        = state,
            PriorityID   = priority_id,
            CustomerUser = customer_username,
            TypeID       = type_id
        )
        try:
            if self.client.session_restore_or_create():
                df = [DynamicField(k, dynamic_fields[k]) for k in dynamic_fields]
                created_ticket = self.client.ticket_create(ticket, article, dynamic_fields=df)
                action_result.add_data(created_ticket)
                ret_val = True
        except:
            ret_val = False

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_ticket(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ticket_id = param['ticket_id']
        ticket_owner = param.get('ticket_owner', '')
        if not ticket_owner:
            ticket_owner = self._username
        ticket_queue = param.get('ticket_queue', '')

        dynamic_fields = json.loads(param.get('dynamic_fields', '{}'))

        priority = param.get('ticket_priority', None)
        if priority:
            priority_id = self._priority_mapping(priority)
        else:
            priority_id = None
        
        lock = param.get('lock', None)
        if lock:
            lock_id = self._lock_mapping(lock)
        else:
            lock_id = None

        state = param.get('ticket_state', None)
        subject = param.get('article_subject', '')
        body = param.get('article_body', '')
        
        article = None
        if subject and body:
            try:
                article = self._create_article(param)
            except Exception as e:
                action_result.add_data({"Exception": repr(e)})
                return action_result.set_status(phantom.APP_ERROR)

        try:
            self.client.session_restore_or_create()
            df = [DynamicField(k, dynamic_fields[k]) for k in dynamic_fields]
            response = self.client.ticket_update(ticket_id, article=article, dynamic_fields=df, State=state, LockID=lock_id, PriorityID=priority_id, Queue=ticket_queue, Owner=ticket_owner)
            if response:
                ret_val = True
            else:
                ret_val = False
        except:
            ret_val = False
               
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR)
        action_result.add_data(response)
                       
        return action_result.set_status(phantom.APP_SUCCESS)

    def _set_ticket_pending(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ticket_id = param['ticket_id']
        new_state = param['new_state']
        pending_days = int(param['pending_days'])
        pending_hours = int(param['pending_hours'])

        try:
            self.client.session_restore_or_create()
            response = self.client.ticket_update_set_pending(ticket_id, new_state, pending_days, pending_hours)
            ret_val = True
        except:
            ret_val = False
               
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR)
        action_result.add_data(response)
        
        return action_result.set_status(phantom.APP_SUCCESS)

    def _priority_mapping(self, input):
        PRIORITY_MAPPING = {
                "INFO": "1", 
                "LOW": "2",
                "MEDIUM": "3",
                "HIGH": "4",
                "CRITICAL": "5"
        }

        priority = None
        try:
            # check if the input string starts with an integer
            priority = int(input[0])
        except ValueError:
            pass

        if not priority:
            try:
                # otherwise try to map the string to a known priority value
                priority = int(PRIORITY_MAPPING[input])
            except KeyError:
                raise ValueError("Invalid input")
            

        if priority > 0 and priority < 6:
            return priority
        
        raise IndexError(f"Invalid Priority: {priority}. Needs to be between 1 and 5.")

    def _lock_mapping(self, input):
        LOCK_MAPPING = {
                "UNLOCK": "1", 
                "LOCK": "2",
                "TMP LOCK": "3",
        }

        lock = None
        try:
            # check if the input string starts with an integer
            lock = int(input[0])
        except ValueError:
            pass

        if not lock:
            try:
                # otherwise try to map the string to a known priority value
                lock = int(LOCK_MAPPING[input])
            except KeyError:
                raise ValueError("Invalid input")
            

        if lock > 0 and lock < 4:
            return lock
        
        raise IndexError(f"Invalid Lock: {lock}. Needs to be between 1 and 3.")

    def _get_ticket(self, ticket_id):
        # Returns a Ticket object: <class 'pyotrs.lib.Ticket'>
        if self.client.session_restore_or_create():
            return self.client.ticket_get_by_id(ticket_id, articles=True)         

    def _ticket_locked(self, ticket_id):
        # Checks if ticket is locked
        if self.client.session_restore_or_create():
            tkt = self._get_ticket(ticket_id)
            if tkt.fields['Lock'] == 'lock':
                return True
            elif tkt.fields['Lock'] == 'unlock':
                return False
            raise KeyError("Could not get ticket Lock status")

    def _handle_search_ticket(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        
        try:
            self.client.session_restore_or_create()
            # Example
            # # Get my ticket (e.g. State:'new' or 'open'、Queue:'Raw'、OwnerIDs: 28)
            # ticket_ids = client.ticket_search(States=['new', 'open'], Queues=['Raw'], OwnerIDs=[28])
            
            # DOCS HERE:
            # https://pyotrs.readthedocs.io/en/latest/readme.html#search-for-tickets
            
            queues = param.get('queues', [])
            owner = param.get('owner', [])
            states = param.get('states', [])
            ticket_ids = self.client.ticket_search(Queues=queues, Owner=owner, States=states)
            action_result.add_data(ticket_ids)
            ret_val = True
        except:
            ret_val = False
               
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR)
        
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_ticket(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            ticket_id = param['ticket_id']  # made ticket_id mandatory on the JSON file
            ticket = self._get_ticket(ticket_id)
            action_result.add_data(ticket.to_dct())
            ret_val = True
        except:
            ret_val = False
        
               
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR)
        
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'create_ticket':
            ret_val = self._handle_create_ticket(param)

        if action_id == 'update_ticket':
            ret_val = self._handle_update_ticket(param)

        if action_id == 'set_ticket_pending':
            ret_val = self._set_ticket_pending(param)

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        if action_id == 'search_ticket':
            ret_val = self._handle_search_ticket(param)
            
        if action_id == 'get_ticket':
            ret_val = self._handle_get_ticket(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        self.config = self.get_config()
        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        try:
            self._base_url = self.config['base_url']
            self._username = self.config['username']
            self._password = self.config['password']
            self._https_verify = self.config['https_verify']

            self.client = Client(self._base_url,
                username=self._username,
                password=self._password,
                https_verify=self._https_verify)
            return phantom.APP_SUCCESS
        except Exception:
            return phantom.APP_ERROR

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = OtrsConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = OtrsConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])
        
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
