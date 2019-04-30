#  Copyright 2017 NOKIA
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

from __future__ import division

import base64
import httplib
import json
import logging
import math
import socket
import ssl
import time

LOG = logging.getLogger(__name__)
MAX_RETRIES = 5
MAX_RETRIES_503 = 5
REST_SUCCESS_CODES = range(200, 300)


class RESTProxyBaseException(Exception):
    message = "An unknown exception occurred."

    def __init__(self, **kwargs):
        try:
            super(RESTProxyBaseException, self).__init__(self.message % kwargs)
            self.msg = self.message % kwargs
        except Exception:
            if self.use_fatal_exceptions():
                raise
            else:
                super(RESTProxyBaseException, self).__init__(self.message)

    def __unicode__(self):
        return unicode(self.msg)

    def use_fatal_exceptions(self):
        return False


class RESTProxyError(RESTProxyBaseException):
    def __init__(self, message, error_code=None):
        self.code = 0
        if error_code:
            self.code = error_code

        if message is None:
            message = "None"

        if self.code == 409:
            self.message = message
        else:
            self.message = "Error in REST call to VSD: %s" % message
        super(RESTProxyError, self).__init__()


class RESTProxyServer(object):
    def __init__(self, server, base_uri, serverssl,
                 serverauth, auth_resource,
                 organization, servertimeout=30):
        try:
            server_ip, port = server.split(":")
        except ValueError:
            server_ip = server
            port = None
        self.server = server_ip
        self.port = int(port) if port else None
        self.base_uri = base_uri
        self.serverssl = serverssl
        self.serverauth = serverauth
        self.auth_resource = auth_resource
        self.organization = organization
        self.timeout = servertimeout
        self.retry = 0
        self.retry_503 = 0
        self.auth = None
        self.success_codes = REST_SUCCESS_CODES
        self.generate_nuage_auth()

    def _rest_call(self, action, resource, data, extra_headers=None):
        if self.retry >= MAX_RETRIES:
            LOG.error('RESTProxy: Max retries exceeded')
            # Get ready for the next set of operation
            self.retry = 0
            return 0, None, None, None, {}
        uri = self.base_uri + resource
        body = json.dumps(data)
        headers = {}
        headers['Content-type'] = 'application/json'
        headers['X-Nuage-Organization'] = self.organization
        if self.auth:
            headers['Authorization'] = self.auth
        conn = None
        if extra_headers:
            headers.update(extra_headers)

        LOG.debug('Request uri: %s', uri)
        LOG.debug('Request headers: %s', headers)
        LOG.debug('Request body: %s', body)

        if self.serverssl:
            if hasattr(ssl, '_create_unverified_context'):
                # pylint: disable=no-member
                # pylint: disable=unexpected-keyword-arg
                conn = httplib.HTTPSConnection(
                    self.server, self.port, timeout=self.timeout,
                    context=ssl._create_unverified_context())
                # pylint: enable=no-member
                # pylint: enable=unexpected-keyword-arg
            else:
                conn = httplib.HTTPSConnection(
                    self.server, self.port, timeout=self.timeout)

            if conn is None:
                LOG.error('RESTProxy: Could not establish HTTPS '
                          'connection')
                return 0, None, None, None, {}
        else:
            conn = httplib.HTTPConnection(
                self.server, self.port, timeout=self.timeout)
            if conn is None:
                LOG.error('RESTProxy: Could not establish HTTP '
                          'connection')
                return 0, None, None, None, {}

        try:
            conn.request(action, uri, body, headers)
            response = conn.getresponse()
            respstr = response.read()
            respdata = respstr
            LOG.debug('Response status is %(st)s and reason is %(res)s',
                      {'st': response.status,
                       'res': response.reason})
            LOG.debug('Response data is %s', respstr)
            if response.status in self.success_codes:
                try:
                    respdata = json.loads(respstr)
                except ValueError:
                    # response was not JSON, ignore the exception
                    pass
            ret = (response.status, response.reason, respstr, respdata,
                   dict(response.getheaders()))
        except (socket.timeout, socket.error) as e:
            LOG.error('ServerProxy: %(action)s failure, %(e)r', locals())
            # retry
            self.retry += 1
            return self._rest_call(action, resource, data, extra_headers)
        conn.close()
        if response.status == 503:
            if self.retry_503 < MAX_RETRIES_503:
                time.sleep(1)
                self.retry_503 += 1
                LOG.debug('VSD unavailable. Retrying')
                return self._rest_call(action, resource, data,
                                       extra_headers=extra_headers)
            else:
                LOG.debug('After 5 retries VSD is unavailable. Bailing out')
        self.retry = 0
        self.retry_503 = 0
        return ret

    def generate_nuage_auth(self):
        data = ''
        encoded_auth = base64.encodestring(self.serverauth).strip()
        self.auth = 'Basic ' + encoded_auth
        resp = self._rest_call('GET', self.auth_resource, data)
        if resp[0] in self.success_codes and resp[3][0]['APIKey']:
            respkey = resp[3][0]['APIKey']
        else:
            if resp[0] == 0:
                assert 0, 'Could not establish conn with REST server. Abort'
            else:
                assert 0, 'Could not authenticate to REST server. Abort'
        uname = self.serverauth.split(':')[0]
        new_uname_pass = uname + ':' + respkey
        auth = 'Basic ' + base64.encodestring(new_uname_pass).strip()
        self.auth = auth

    def rest_call(self, action, resource, data, extra_headers=None):
        if action.lower() == 'get':
            return self.get(resource, data=data, extra_headers=extra_headers)
        response = self._rest_call(action, resource, data,
                                   extra_headers=extra_headers)
        '''
        If at all authentication expires with VSD, re-authenticate.
        '''
        if response[0] == 401 and response[1] == 'Unauthorized':
            self.generate_nuage_auth()
            return self._rest_call(action, resource, data,
                                   extra_headers=extra_headers)
        return response

    def get(self, resource, data='', extra_headers=None, page_size=500):
        extra_headers = extra_headers or {}
        response = self._get_page(resource, data, extra_headers, page_size, 0)
        headers = response[4]
        if response[0] in REST_SUCCESS_CODES and 'x-nuage-count' in headers:
            total_objects = int(headers['x-nuage-count'])
            total_pages = int(math.ceil(total_objects / page_size))
            result = response[3]
            for page in range(1, total_pages):
                response = self._get_page(resource, data, extra_headers,
                                          page_size, page)
                if response[0] not in REST_SUCCESS_CODES:
                    return response
                result.extend(response[3])
            return response[0], response[1], response[2], result, headers
        else:
            return response

    def put(self, resource, data, extra_headers=None):
        response = self.rest_call('PUT', resource, data,
                                  extra_headers=extra_headers)
        if response[0] in REST_SUCCESS_CODES:
            return
        else:
            errors = json.loads(response[3])
            if response[0] == 503:
                msg = 'VSD temporarily unavailable, ' + str(errors['errors'])
            else:
                msg = str(
                    errors['errors'][0]['descriptions'][0]['description'])
            raise RESTProxyError(msg, error_code=response[0])

    def _get_page(self, resource, data, extra_headers, page_size, page):
        extra_headers['X-Nuage-Page'] = page
        extra_headers['X-Nuage-PageSize'] = page_size
        response = self._rest_call('GET', resource, data,
                                   extra_headers=extra_headers)
        if response[0] == 401 and response[1] == 'Unauthorized':
            self.generate_nuage_auth()
            response = self._rest_call('GET', resource, data,
                                       extra_headers=extra_headers)
        return response
