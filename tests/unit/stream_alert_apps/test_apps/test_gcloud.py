"""
Copyright 2017-present, Airbnb Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import json
import os
import socket
import ssl
from datetime import datetime, timedelta

import apiclient
import oauth2client
from mock import Mock, mock_open, patch
from moto import mock_ssm
from nose.tools import assert_equal, assert_false, assert_items_equal, assert_true, raises

from stream_alert.apps._apps.gcloud import GCloudAuditLogApp

from tests.unit.stream_alert_apps.test_helpers import get_event, put_mock_params
from tests.unit.stream_alert_shared.test_config import get_mock_lambda_context


@mock_ssm
@patch.object(GCloudAuditLogApp, '_type', Mock(return_value='activity'))
@patch.object(GCloudAuditLogApp, 'type', Mock(return_value='type'))
class TestGCloudAuditLogApp(object):
    """Test class for the GCloudAuditLogApp"""
    # pylint: disable=protected-access

    @patch.dict(os.environ, {'AWS_ACCESS_KEY_ID': 'dummy-access-key'})
    @patch.dict(os.environ, {'AWS_SECRET_ACCESS_KEY': 'dummy-access-key-secret'})
    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    def setup(self):
        """Setup before each method"""
        # pylint: disable=attribute-defined-outside-init
        self._test_app_name = 'gcloud_activity'
        put_mock_params(self._test_app_name)
        self._event = get_event(self._test_app_name)
        self._context = get_mock_lambda_context(self._test_app_name)
        self._app = GCloudAuditLogApp(self._event, self._context)

    def test_sleep(self):
        """GCloudAuditLogApp - Sleep Seconds"""
        assert_equal(self._app._sleep_seconds(), 1)

    def test_required_auth_info(self):
        """GCloudAuditLogApp - Required Auth Info"""
        assert_items_equal(self._app.required_auth_info().keys(),
                           {'delegation_email', 'keyfile'})

    @patch('oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_dict',
           Mock(return_value=True))
    def test_keyfile_validator(self):
        """GCloudAuditLogApp - Keyfile Validation, Success"""
        validation_function = self._app.required_auth_info()['keyfile']['format']
        data = {'test': 'keydata'}
        mocker = mock_open(read_data=json.dumps(data))
        with patch('__builtin__.open', mocker):
            loaded_keydata = validation_function('fakepath')
            assert_equal(loaded_keydata, data)

    @patch('oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_dict')
    def test_keyfile_validator_failure(self, cred_mock):
        """GCloudAuditLogApp - Keyfile Validation, Failure"""
        validation_function = self._app.required_auth_info()['keyfile']['format']
        cred_mock.return_value = False
        mocker = mock_open(read_data=json.dumps({'test': 'keydata'}))
        with patch('__builtin__.open', mocker):
            assert_false(validation_function('fakepath'))
            cred_mock.assert_called()

    @patch('oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_dict')
    def test_keyfile_validator_bad_json(self, cred_mock):
        """GCloudAuditLogApp - Keyfile Validation, Bad JSON"""
        validation_function = self._app.required_auth_info()['keyfile']['format']
        mocker = mock_open(read_data='invalid json')
        with patch('__builtin__.open', mocker):
            assert_false(validation_function('fakepath'))
            cred_mock.assert_not_called()

    @patch('oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_dict',
           Mock(return_value=True))
    def test_load_credentials(self):
        """GCloudAuditLogApp - Load Credentials, Success"""
        assert_true(self._app._load_credentials('fakedata'))

    @patch('oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_dict')
    def test_load_credentials_bad(self, cred_mock):
        """GCloudAuditLogApp - Load Credentials, ValueError"""
        cred_mock.side_effect = ValueError('Bad things happened')
        assert_false(self._app._load_credentials('fakedata'))

    @patch('stream_alert.apps._apps.gcloud.GCloudAuditLogApp._load_credentials', Mock())
    @patch('stream_alert.apps._apps.gcloud.apiclient.discovery.build')
    def test_create_service(self, build_mock):
        """GCloudAuditLogApp - Create Service, Success"""
        build_mock.return_value.entries.return_value = True
        assert_true(self._app._create_service())

    @patch('logging.Logger.debug')
    def test_create_service_exists(self, log_mock):
        """GCloudAuditLogApp - Create Service, Exists"""
        self._app._log_service = True
        assert_true(self._app._create_service())
        log_mock.assert_called_with('[%s] Service already instantiated', self._app)

    @patch('stream_alert.apps._apps.gcloud.GCloudAuditLogApp._load_credentials',
           Mock(return_value=False))
    def test_create_service_fail_creds(self):
        """GCloudAuditLogApp - Create Service, Credential Failure"""
        assert_false(self._app._create_service())

    @patch('stream_alert.apps._apps.gcloud.GCloudAuditLogApp._load_credentials', Mock())
    @patch('logging.Logger.exception')
    @patch('stream_alert.apps._apps.gcloud.apiclient.discovery.build')
    def test_create_service_api_error(self, build_mock, log_mock):
        """GCloudAuditLogApp - Create Service, Google API Error"""
        build_mock.side_effect = apiclient.errors.Error('This is bad')
        assert_false(self._app._create_service())
        log_mock.assert_called_with('[%s] Failed to build discovery service', self._app)

    @patch('stream_alert.apps._apps.gcloud.GCloudAuditLogApp._load_credentials', Mock())
    @patch('logging.Logger.exception')
    @patch('stream_alert.apps._apps.gcloud.apiclient.discovery.build')
    def test_create_service_ssl_error(self, build_mock, log_mock):
        """GCloudAuditLogApp - Create Service, SSL Handshake Error"""
        build_mock.side_effect = ssl.SSLError('_ssl.c:574: The handshake operation timed out')
        assert_false(self._app._create_service())
        log_mock.assert_called_with('[%s] Failed to build discovery service', self._app)

    @patch('stream_alert.apps._apps.gcloud.GCloudAuditLogApp._load_credentials', Mock())
    @patch('logging.Logger.exception')
    @patch('stream_alert.apps._apps.gcloud.apiclient.discovery.build')
    def test_create_service_socket_error(self, build_mock, log_mock):
        """GCloudAuditLogApp - Create Service, Socket Timeout"""
        build_mock.side_effect = socket.timeout('timeout: timed out')
        assert_false(self._app._create_service())
        log_mock.assert_called_with('[%s] Failed to build discovery service', self._app)

    def test_gather_logs(self):
        """GCloudAuditLogApp - Gather Logs, Success"""
        with patch.object(self._app, '_log_service') as service_mock:
            payload = {
                'nextPageToken': 'the next page\'s token',
                'entries': self._get_sample_logs(10)
            }
            service_mock.list.return_value.execute.return_value = payload

            assert_equal(len(self._app._gather_logs()), 10)
            assert_equal(self._app._last_timestamp, '2011-06-17T15:39:18.460000Z')
            assert_equal(self._app._context['last_event_ids'], [-12345678901234567890])

    @patch('stream_alert.apps._apps.gcloud.GCloudAuditLogApp._create_service',
           Mock(return_value=True))
    @patch('logging.Logger.exception')
    def test_gather_logs_http_error(self, log_mock):
        """GCloudAuditLogApp - Gather Logs, Google API HTTP Error"""
        with patch.object(self._app, '_log_service') as service_mock:
            error = apiclient.errors.HttpError('response', bytes('bad'))
            service_mock.list.return_value.execute.side_effect = error
            assert_false(self._app._gather_logs())
            log_mock.assert_called_with('[%s] Failed to execute activities listing', self._app)

    @patch('stream_alert.apps._apps.gcloud.GCloudAuditLogApp._create_service',
           Mock(return_value=True))
    @patch('logging.Logger.exception')
    def test_gather_logs_token_error(self, log_mock):
        """GCloudAuditLogApp - Gather Logs, Google API Token Error"""
        with patch.object(self._app, '_log_service') as service_mock:
            error = oauth2client.client.HttpAccessTokenRefreshError('bad', status=502)
            service_mock.list.return_value.execute.side_effect = error
            assert_false(self._app._gather_logs())
            log_mock.assert_called_with('[%s] Failed to execute activities listing', self._app)

    @patch('stream_alert.apps._apps.gcloud.GCloudAuditLogApp._create_service',
           Mock(return_value=True))
    @patch('logging.Logger.exception')
    def test_gather_logs_ssl_error(self, log_mock):
        """GCloudAuditLogApp - Gather Logs, SSL Handshake Error"""
        with patch.object(self._app, '_log_service') as service_mock:
            error = ssl.SSLError('_ssl.c:574: The handshake operation timed out')
            service_mock.list.return_value.execute.side_effect = error
            assert_false(self._app._gather_logs())
            log_mock.assert_called_with('[%s] Failed to execute activities listing', self._app)

    @patch('stream_alert.apps._apps.gcloud.GCloudAuditLogApp._create_service',
           Mock(return_value=True))
    @patch('logging.Logger.exception')
    def test_gather_logs_socket_error(self, log_mock):
        """GCloudAuditLogApp - Gather Logs, Socket Timeout"""
        with patch.object(self._app, '_log_service') as service_mock:
            error = socket.timeout('timeout: timed out')
            service_mock.list.return_value.execute.side_effect = error
            assert_false(self._app._gather_logs())
            log_mock.assert_called_with('[%s] Failed to execute activities listing', self._app)

    @patch('stream_alert.apps._apps.gcloud.GCloudAuditLogApp._load_credentials',
           Mock(return_value=False))
    def test_gather_logs_no_service(self):
        """GCloudAuditLogApp - Gather Logs, No Service"""
        with patch.object(self._app, '_log_service') as service_mock:
            self._app._log_service = False
            assert_false(self._app._gather_logs())
            service_mock.list.assert_not_called()

    @patch('stream_alert.apps._apps.gcloud.GCloudAuditLogApp._create_service',
           Mock(return_value=True))
    @patch('logging.Logger.error')
    def test_gather_logs_no_results(self, log_mock):
        """GCloudAuditLogApp - Gather Logs, No Results From API"""
        with patch.object(self._app, '_log_service') as service_mock:
            service_mock.list.return_value.execute.return_value = None
            assert_false(self._app._gather_logs())
            log_mock.assert_called_with(
                '[%s] No results received from the G Cloud API request', self._app
            )

    @patch('stream_alert.apps._apps.gcloud.GCloudAuditLogApp._create_service',
           Mock(return_value=True))
    @patch('logging.Logger.info')
    def test_gather_logs_empty_items(self, log_mock):
        """GCloudAuditLogApp - Gather Logs, Empty Log Entry List"""
        with patch.object(self._app, '_log_service') as service_mock:
            payload = {
                'nextPageToken': 'the next page\'s token',
                'entries': []
            }
            service_mock.list.return_value.execute.return_value = payload
            assert_false(self._app._gather_logs())
            log_mock.assert_called_with(
                '[%s] No logs in response from G Cloud API request', self._app
            )

    def test_gather_logs_remove_duplicate_events(self):
        """GCloudAuditLogApp - Gather Logs, Remove duplicate events"""
        with patch.object(self._app, '_log_service') as service_mock:
            payload = {
                'nextPageToken': None,
                'entries': self._get_sample_logs(10)
            }
            service_mock.list.return_value.execute.return_value = payload
            self._app._context['last_event_ids'] = [
                -12345678901234567890 + 9,
                -12345678901234567890 + 8
            ]

            assert_equal(len(self._app._gather_logs()), 8)
            assert_equal(self._app._last_timestamp, '2011-06-17T15:39:18.460000Z')
            assert_equal(self._app._more_to_poll, False)
            assert_equal(self._app._context['last_event_ids'], [-12345678901234567890])


    @staticmethod
    def _get_sample_logs(count):
        """Helper function for returning sample gcloud audit (admin activity) logs"""

        def _get_timestamp(start_timestamp, subtract_seconds):
            timestamp = datetime.strptime(start_timestamp, GCloudAuditLogApp.date_formatter())
            timestamp -= timedelta(seconds=subtract_seconds)
            return timestamp.strftime(GCloudAuditLogApp.date_formatter())

        return [{
            "timestamp": _get_timestamp('2011-06-17T15:39:18.460000Z', index),
            "insertId": -12345678901234567890L + index,
            "textPayload": "hello world: %s " % index,
        } for index in range(count)]

@raises(NotImplementedError)
def test_type_not_implemented():
    """GCloudAuditLogApp - Subclass Type Not Implemented"""
    # pylint: disable=protected-access,abstract-method
    class GSuiteFakeApp(GCloudAuditLogApp):
        """Fake GSuiteReports app that should raise a NotImplementedError"""

    GSuiteFakeApp._type()
