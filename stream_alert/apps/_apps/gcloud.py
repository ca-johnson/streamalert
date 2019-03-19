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
import logging
import json
import re
import socket
import ssl

import apiclient
from oauth2client import client, service_account

from . import AppIntegration, StreamAlertApp, get_logger

LOGGER = get_logger(__name__)


# Disable noisy google api client logger
logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)


class GCloudAuditLogApp(AppIntegration):
    """G Cloud Audit Log base app integration. This is subclassed for various log types"""
    _SCOPES = ['https://www.googleapis.com/auth/logging.read']
    # A tuple of uncaught exceptions that the googleapiclient can raise
    _GOOGLE_API_EXCEPTIONS = (apiclient.errors.Error, client.Error, socket.timeout,
                              ssl.SSLError)

    # The maximum number of unique event ids to store that occur on the most
    # recent timestamp. These are used to de-duplicate events in the next poll.
    # This is limited by AWS SSM parameter store maximum of 4096 characters.
    _MAX_EVENT_IDS = 100


    def __init__(self, event, context):
        super(GCloudAuditLogApp, self).__init__(event, context)
        self._log_service = None
        self._last_event_timestamp = None
        self._next_page_token = None
        self._last_run_event_ids = []

        # The resources to get audit logs for, valid formats include:
        # projects/[PROJECT_ID]
        # organizations/[ORGANIZATION_ID]
        # billingAccounts/[BILLING_ACCOUNT_ID]
        # folders/[FOLDER_ID]
        # self._resource = self._config['resources'] # ???


    @classmethod
    def _type(cls):
        raise NotImplementedError('Subclasses should implement the _type method')

    @classmethod
    def service(cls):
        return 'gcloud'

    @classmethod
    def date_formatter(cls):
        """Return a format string for a date, ie: 2010-10-28T10:26:35.000Z"""
        return '%Y-%m-%dT%H:%M:%S.%fZ'

    @classmethod
    def _load_credentials(cls, keydata):
        """Load ServiceAccountCredentials from Google service account JSON keyfile

        Args:
            keydata (dict): The loaded keyfile data from a Google service account
                JSON file

        Returns:
            oauth2client.service_account.ServiceAccountCredentials: Instance of
                service account credentials for this discovery service
        """
        try:
            creds = service_account.ServiceAccountCredentials.from_json_keyfile_dict(
                keydata, scopes=cls._SCOPES)
        except (ValueError, KeyError):
            # This has the potential to raise errors. See: https://tinyurl.com/y8q5e9rm
            LOGGER.exception('[%s] Could not generate credentials from keyfile', cls.type())
            return False

        return creds

    def _create_service(self):
        """GCloud requests must be signed with the keyfile

        Returns:
            bool: True if the Google API discovery service was successfully established or False
                if any errors occurred during the creation of the Google discovery service,
        """
        # Is this in the right place?
        # self._log_name = "cloudaudit.googleapis.com%2F{}".format(self._type())

        LOGGER.debug('[%s] Creating log entries service', self)

        if self._log_service:
            LOGGER.debug('[%s] Service already instantiated', self)
            return True

        creds = self._load_credentials(self._config.auth['keyfile'])
        if not creds:
            return False


        # gcloud_logging.Client(project="firm-scout-180414")

        delegation = creds.create_delegated(self._config.auth['delegation_email'])
        try:
            resource = apiclient.discovery.build('logging', 'v2', credentials=delegation)
        except self._GOOGLE_API_EXCEPTIONS:
            LOGGER.exception('[%s] Failed to build discovery service', self)
            return False

        # The google discovery service 'Resource' class that is returned by
        # 'discovery.build' dynamically loads methods/attributes, so pylint will complain
        # about no 'entries' member existing without the below pylint comment
        self._log_service = resource.entries()  # pylint: disable=no-member

        return True

    def _gather_logs(self):
        """Gather the G Cloud Audit Logs of this log type

        Returns:
            bool or list: If the execution fails for some reason, return False.
                Otherwise, return a list of audit log entries for this log type.
        """
        if not self._create_service():
            return False

        # Cache the last event timestamp so it can be used for future requests
        if not self._next_page_token:
            self._last_event_timestamp = self._last_timestamp
            self._last_run_event_ids = self._context.get('last_event_ids', [])

        LOGGER.debug('[%s] Querying entries since %s', self, self._last_event_timestamp)
        LOGGER.debug('[%s] Using next page token: %s', self, self._next_page_token)
        LOGGER.debug('[%s] Last run event ids: %s', self, self._last_run_event_ids)

        # https://developers.google.com/resources/api-libraries/documentation/logging/v2/python/latest/logging_v2.entries.html#list
        entries_list = self._log_service.list(
            body={
                # orderBy
                # pageSize
                # https://cloud.google.com/logging/docs/view/advanced-filters
                'filter': 'logName = {log_name} AND timestamp >= "{last_event}"'.format(**{
                    'log_name': ("cloudaudit.googleapis.com%2F{}".format(self._type())),
                    'last_event': self._last_event_timestamp,
                    }),
                'resourceNames': ["projects/firm-scout-180414"],
                'pageToken': self._next_page_token
            },
        )

        try:
            results = entries_list.execute()
        except self._GOOGLE_API_EXCEPTIONS:
            LOGGER.exception('[%s] Failed to execute activities listing', self)
            return False

        if not results:
            LOGGER.error('[%s] No results received from the G Cloud API request', self)
            return False

        # Remove duplicate events present in the last time period.
        entries = [
            entry for entry in results.get('entries', [])
            if entry['insertId'] not in set(self._last_run_event_ids)
        ]
        if not entries:
            LOGGER.info('[%s] No logs in response from G Cloud API request', self)
            return False

        self._last_timestamp = entries[-1]['timestamp']
        LOGGER.debug('[%s] Caching last timestamp: %s', self, self._last_timestamp)
        # Store the event ids with the most recent timestamp to de-duplicate them next time
        next_run_event_ids = [
            entry['insertId']
            for entry in entries
            if entry['timestamp'] == self._last_timestamp
        ]
        self._context['last_event_ids'] = next_run_event_ids[:self._MAX_EVENT_IDS]
        if len(next_run_event_ids) > self._MAX_EVENT_IDS:
            LOGGER.warning('[%s] More than %d next_run_event_ids. Unable to de-duplicate: %s',
                           self, self._MAX_EVENT_IDS, next_run_event_ids[self._MAX_EVENT_IDS:])

        self._next_page_token = results.get('nextPageToken')
        self._more_to_poll = bool(self._next_page_token)

        return entries

    @classmethod
    def _required_auth_info(cls):
        # Use a validation function to ensure the file the user provides is valid
        def keyfile_validator(keyfile):
            """A JSON formatted (not p12) Google service account private key file key"""
            try:
                with open(keyfile.strip(), 'r') as json_keyfile:
                    keydata = json.load(json_keyfile)
            except (IOError, ValueError):
                return False

            if not cls._load_credentials(keydata):
                return False

            return keydata

        return {
            'keyfile':
                {
                    'description': ('the path on disk to the JSON formatted Google '
                                    'service account private key file'),
                    'format': keyfile_validator
                },
            'delegation_email':
                {
                    'description': 'the service account user email to delegate access to',
                    'format': re.compile(r'^[A-Za-z0-9-_.+]+@[A-Za-z0-9-.]+\.[A-Za-z]{2,}$')
                }
            }

    def _sleep_seconds(self):
        """Return the number of seconds this polling function should sleep for
        between requests to avoid failed requests. The Google Cloud Audit Log API allows for
        1 entries.list API call per second

        Resource(s):
            https://cloud.google.com/logging/quotas#logging_usage_limits

        Returns:
            int: Number of seconds that this function should sleep for between requests
        """
        return 1


@StreamAlertApp
class GCloudAdminAuditLogs(GCloudAuditLogApp):
    """G Cloud Admin Audit Log app integration"""

    @classmethod
    def _type(cls):
        return 'activity'


@StreamAlertApp
class GCloudSystemEventAuditLogs(GCloudAuditLogApp):
    """G Cloud System Event Audit Log app integration"""

    @classmethod
    def _type(cls):
        return 'system_event'


@StreamAlertApp
class GCloudDataAccessAuditLogs(GCloudAuditLogApp):
    """G Cloud Data Access Audit Log app integration"""

    @classmethod
    def _type(cls):
        return 'data_access'
