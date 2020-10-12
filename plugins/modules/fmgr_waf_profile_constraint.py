#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2020 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_waf_profile_constraint
short_description: WAF HTTP protocol restrictions.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.10"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded

options:
    bypass_validation:
        description: only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    workspace_locking_adom:
        description: the adom to lock for FortiManager running in workspace mode, the value can be global and others including root
        required: false
        type: str
    workspace_locking_timeout:
        description: the maximum time in seconds to wait for other user to release the workspace lock
        required: false
        type: int
        default: 300
    state:
        description: the directive to create, update or delete an object
        type: str
        required: true
        choices:
          - present
          - absent
    rc_succeeded:
        description: the rc codes list with which the conditions to succeed will be overriden
        type: list
        required: false
    rc_failed:
        description: the rc codes list with which the conditions to fail will be overriden
        type: list
        required: false
    adom:
        description: the parameter (adom) in requested url
        type: str
        required: true
    profile:
        description: the parameter (profile) in requested url
        type: str
        required: true
    waf_profile_constraint:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            content-length:
                description: no description
                type: dict
                required: false
                suboptions:
                    action:
                        type: str
                        description: 'Action.'
                        choices:
                            - 'allow'
                            - 'block'
                    length:
                        type: int
                        description: 'Length of HTTP content in bytes (0 to 2147483647).'
                    log:
                        type: str
                        description: 'Enable/disable logging.'
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        type: str
                        description: 'Severity.'
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: 'Enable/disable the constraint.'
                        choices:
                            - 'disable'
                            - 'enable'
            exception:
                description: no description
                type: list
                suboptions:
                    address:
                        type: str
                        description: 'Host address.'
                    content-length:
                        type: str
                        description: 'HTTP content length in request.'
                        choices:
                            - 'disable'
                            - 'enable'
                    header-length:
                        type: str
                        description: 'HTTP header length in request.'
                        choices:
                            - 'disable'
                            - 'enable'
                    hostname:
                        type: str
                        description: 'Enable/disable hostname check.'
                        choices:
                            - 'disable'
                            - 'enable'
                    id:
                        type: int
                        description: 'Exception ID.'
                    line-length:
                        type: str
                        description: 'HTTP line length in request.'
                        choices:
                            - 'disable'
                            - 'enable'
                    malformed:
                        type: str
                        description: 'Enable/disable malformed HTTP request check.'
                        choices:
                            - 'disable'
                            - 'enable'
                    max-cookie:
                        type: str
                        description: 'Maximum number of cookies in HTTP request.'
                        choices:
                            - 'disable'
                            - 'enable'
                    max-header-line:
                        type: str
                        description: 'Maximum number of HTTP header line.'
                        choices:
                            - 'disable'
                            - 'enable'
                    max-range-segment:
                        type: str
                        description: 'Maximum number of range segments in HTTP range line.'
                        choices:
                            - 'disable'
                            - 'enable'
                    max-url-param:
                        type: str
                        description: 'Maximum number of parameters in URL.'
                        choices:
                            - 'disable'
                            - 'enable'
                    method:
                        type: str
                        description: 'Enable/disable HTTP method check.'
                        choices:
                            - 'disable'
                            - 'enable'
                    param-length:
                        type: str
                        description: 'Maximum length of parameter in URL, HTTP POST request or HTTP body.'
                        choices:
                            - 'disable'
                            - 'enable'
                    pattern:
                        type: str
                        description: 'URL pattern.'
                    regex:
                        type: str
                        description: 'Enable/disable regular expression based pattern match.'
                        choices:
                            - 'disable'
                            - 'enable'
                    url-param-length:
                        type: str
                        description: 'Maximum length of parameter in URL.'
                        choices:
                            - 'disable'
                            - 'enable'
                    version:
                        type: str
                        description: 'Enable/disable HTTP version check.'
                        choices:
                            - 'disable'
                            - 'enable'
            header-length:
                description: no description
                type: dict
                required: false
                suboptions:
                    action:
                        type: str
                        description: 'Action.'
                        choices:
                            - 'allow'
                            - 'block'
                    length:
                        type: int
                        description: 'Length of HTTP header in bytes (0 to 2147483647).'
                    log:
                        type: str
                        description: 'Enable/disable logging.'
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        type: str
                        description: 'Severity.'
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: 'Enable/disable the constraint.'
                        choices:
                            - 'disable'
                            - 'enable'
            hostname:
                description: no description
                type: dict
                required: false
                suboptions:
                    action:
                        type: str
                        description: 'Action.'
                        choices:
                            - 'allow'
                            - 'block'
                    log:
                        type: str
                        description: 'Enable/disable logging.'
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        type: str
                        description: 'Severity.'
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: 'Enable/disable the constraint.'
                        choices:
                            - 'disable'
                            - 'enable'
            line-length:
                description: no description
                type: dict
                required: false
                suboptions:
                    action:
                        type: str
                        description: 'Action.'
                        choices:
                            - 'allow'
                            - 'block'
                    length:
                        type: int
                        description: 'Length of HTTP line in bytes (0 to 2147483647).'
                    log:
                        type: str
                        description: 'Enable/disable logging.'
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        type: str
                        description: 'Severity.'
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: 'Enable/disable the constraint.'
                        choices:
                            - 'disable'
                            - 'enable'
            malformed:
                description: no description
                type: dict
                required: false
                suboptions:
                    action:
                        type: str
                        description: 'Action.'
                        choices:
                            - 'allow'
                            - 'block'
                    log:
                        type: str
                        description: 'Enable/disable logging.'
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        type: str
                        description: 'Severity.'
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: 'Enable/disable the constraint.'
                        choices:
                            - 'disable'
                            - 'enable'
            max-cookie:
                description: no description
                type: dict
                required: false
                suboptions:
                    action:
                        type: str
                        description: 'Action.'
                        choices:
                            - 'allow'
                            - 'block'
                    log:
                        type: str
                        description: 'Enable/disable logging.'
                        choices:
                            - 'disable'
                            - 'enable'
                    max-cookie:
                        type: int
                        description: 'Maximum number of cookies in HTTP request (0 to 2147483647).'
                    severity:
                        type: str
                        description: 'Severity.'
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: 'Enable/disable the constraint.'
                        choices:
                            - 'disable'
                            - 'enable'
            max-header-line:
                description: no description
                type: dict
                required: false
                suboptions:
                    action:
                        type: str
                        description: 'Action.'
                        choices:
                            - 'allow'
                            - 'block'
                    log:
                        type: str
                        description: 'Enable/disable logging.'
                        choices:
                            - 'disable'
                            - 'enable'
                    max-header-line:
                        type: int
                        description: 'Maximum number HTTP header lines (0 to 2147483647).'
                    severity:
                        type: str
                        description: 'Severity.'
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: 'Enable/disable the constraint.'
                        choices:
                            - 'disable'
                            - 'enable'
            max-range-segment:
                description: no description
                type: dict
                required: false
                suboptions:
                    action:
                        type: str
                        description: 'Action.'
                        choices:
                            - 'allow'
                            - 'block'
                    log:
                        type: str
                        description: 'Enable/disable logging.'
                        choices:
                            - 'disable'
                            - 'enable'
                    max-range-segment:
                        type: int
                        description: 'Maximum number of range segments in HTTP range line (0 to 2147483647).'
                    severity:
                        type: str
                        description: 'Severity.'
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: 'Enable/disable the constraint.'
                        choices:
                            - 'disable'
                            - 'enable'
            max-url-param:
                description: no description
                type: dict
                required: false
                suboptions:
                    action:
                        type: str
                        description: 'Action.'
                        choices:
                            - 'allow'
                            - 'block'
                    log:
                        type: str
                        description: 'Enable/disable logging.'
                        choices:
                            - 'disable'
                            - 'enable'
                    max-url-param:
                        type: int
                        description: 'Maximum number of parameters in URL (0 to 2147483647).'
                    severity:
                        type: str
                        description: 'Severity.'
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: 'Enable/disable the constraint.'
                        choices:
                            - 'disable'
                            - 'enable'
            method:
                description: no description
                type: dict
                required: false
                suboptions:
                    action:
                        type: str
                        description: 'Action.'
                        choices:
                            - 'allow'
                            - 'block'
                    log:
                        type: str
                        description: 'Enable/disable logging.'
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        type: str
                        description: 'Severity.'
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: 'Enable/disable the constraint.'
                        choices:
                            - 'disable'
                            - 'enable'
            param-length:
                description: no description
                type: dict
                required: false
                suboptions:
                    action:
                        type: str
                        description: 'Action.'
                        choices:
                            - 'allow'
                            - 'block'
                    length:
                        type: int
                        description: 'Maximum length of parameter in URL, HTTP POST request or HTTP body in bytes (0 to 2147483647).'
                    log:
                        type: str
                        description: 'Enable/disable logging.'
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        type: str
                        description: 'Severity.'
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: 'Enable/disable the constraint.'
                        choices:
                            - 'disable'
                            - 'enable'
            url-param-length:
                description: no description
                type: dict
                required: false
                suboptions:
                    action:
                        type: str
                        description: 'Action.'
                        choices:
                            - 'allow'
                            - 'block'
                    length:
                        type: int
                        description: 'Maximum length of URL parameter in bytes (0 to 2147483647).'
                    log:
                        type: str
                        description: 'Enable/disable logging.'
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        type: str
                        description: 'Severity.'
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: 'Enable/disable the constraint.'
                        choices:
                            - 'disable'
                            - 'enable'
            version:
                description: no description
                type: dict
                required: false
                suboptions:
                    action:
                        type: str
                        description: 'Action.'
                        choices:
                            - 'allow'
                            - 'block'
                    log:
                        type: str
                        description: 'Enable/disable logging.'
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        type: str
                        description: 'Severity.'
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: 'Enable/disable the constraint.'
                        choices:
                            - 'disable'
                            - 'enable'

'''

EXAMPLES = '''
 - hosts: fortimanager-inventory
   collections:
     - fortinet.fortimanager
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:
    - name: WAF HTTP protocol restrictions.
      fmgr_waf_profile_constraint:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         profile: <your own value>
         waf_profile_constraint:
            content-length:
               action: <value in [allow, block]>
               length: <value of integer>
               log: <value in [disable, enable]>
               severity: <value in [low, medium, high]>
               status: <value in [disable, enable]>
            exception:
              -
                  address: <value of string>
                  content-length: <value in [disable, enable]>
                  header-length: <value in [disable, enable]>
                  hostname: <value in [disable, enable]>
                  id: <value of integer>
                  line-length: <value in [disable, enable]>
                  malformed: <value in [disable, enable]>
                  max-cookie: <value in [disable, enable]>
                  max-header-line: <value in [disable, enable]>
                  max-range-segment: <value in [disable, enable]>
                  max-url-param: <value in [disable, enable]>
                  method: <value in [disable, enable]>
                  param-length: <value in [disable, enable]>
                  pattern: <value of string>
                  regex: <value in [disable, enable]>
                  url-param-length: <value in [disable, enable]>
                  version: <value in [disable, enable]>
            header-length:
               action: <value in [allow, block]>
               length: <value of integer>
               log: <value in [disable, enable]>
               severity: <value in [low, medium, high]>
               status: <value in [disable, enable]>
            hostname:
               action: <value in [allow, block]>
               log: <value in [disable, enable]>
               severity: <value in [low, medium, high]>
               status: <value in [disable, enable]>
            line-length:
               action: <value in [allow, block]>
               length: <value of integer>
               log: <value in [disable, enable]>
               severity: <value in [low, medium, high]>
               status: <value in [disable, enable]>
            malformed:
               action: <value in [allow, block]>
               log: <value in [disable, enable]>
               severity: <value in [low, medium, high]>
               status: <value in [disable, enable]>
            max-cookie:
               action: <value in [allow, block]>
               log: <value in [disable, enable]>
               max-cookie: <value of integer>
               severity: <value in [low, medium, high]>
               status: <value in [disable, enable]>
            max-header-line:
               action: <value in [allow, block]>
               log: <value in [disable, enable]>
               max-header-line: <value of integer>
               severity: <value in [low, medium, high]>
               status: <value in [disable, enable]>
            max-range-segment:
               action: <value in [allow, block]>
               log: <value in [disable, enable]>
               max-range-segment: <value of integer>
               severity: <value in [low, medium, high]>
               status: <value in [disable, enable]>
            max-url-param:
               action: <value in [allow, block]>
               log: <value in [disable, enable]>
               max-url-param: <value of integer>
               severity: <value in [low, medium, high]>
               status: <value in [disable, enable]>
            method:
               action: <value in [allow, block]>
               log: <value in [disable, enable]>
               severity: <value in [low, medium, high]>
               status: <value in [disable, enable]>
            param-length:
               action: <value in [allow, block]>
               length: <value of integer>
               log: <value in [disable, enable]>
               severity: <value in [low, medium, high]>
               status: <value in [disable, enable]>
            url-param-length:
               action: <value in [allow, block]>
               length: <value of integer>
               log: <value in [disable, enable]>
               severity: <value in [low, medium, high]>
               status: <value in [disable, enable]>
            version:
               action: <value in [allow, block]>
               log: <value in [disable, enable]>
               severity: <value in [low, medium, high]>
               status: <value in [disable, enable]>

'''

RETURN = '''
request_url:
    description: The full url requested
    returned: always
    type: str
    sample: /sys/login/user
response_code:
    description: The status of api request
    returned: always
    type: int
    sample: 0
response_message:
    description: The descriptive message of the api response
    type: str
    returned: always
    sample: OK.

'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_galaxy_version
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_parameter_bypass


def main():
    jrpc_urls = [
        '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint',
        '/pm/config/global/obj/waf/profile/{profile}/constraint'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/{constraint}',
        '/pm/config/global/obj/waf/profile/{profile}/constraint/{constraint}'
    ]

    url_params = ['adom', 'profile']
    module_primary_key = None
    module_arg_spec = {
        'bypass_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'workspace_locking_adom': {
            'type': 'str',
            'required': False
        },
        'workspace_locking_timeout': {
            'type': 'int',
            'required': False,
            'default': 300
        },
        'rc_succeeded': {
            'required': False,
            'type': 'list'
        },
        'rc_failed': {
            'required': False,
            'type': 'list'
        },
        'adom': {
            'required': True,
            'type': 'str'
        },
        'profile': {
            'required': True,
            'type': 'str'
        },
        'waf_profile_constraint': {
            'required': False,
            'type': 'dict',
            'options': {
                'content-length': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'action': {
                            'required': False,
                            'choices': [
                                'allow',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'length': {
                            'required': False,
                            'type': 'int'
                        },
                        'log': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'severity': {
                            'required': False,
                            'choices': [
                                'low',
                                'medium',
                                'high'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'exception': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'address': {
                            'required': False,
                            'type': 'str'
                        },
                        'content-length': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'header-length': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'hostname': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'type': 'int'
                        },
                        'line-length': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'malformed': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'max-cookie': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'max-header-line': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'max-range-segment': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'max-url-param': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'method': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'param-length': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'pattern': {
                            'required': False,
                            'type': 'str'
                        },
                        'regex': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'url-param-length': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'version': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'header-length': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'action': {
                            'required': False,
                            'choices': [
                                'allow',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'length': {
                            'required': False,
                            'type': 'int'
                        },
                        'log': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'severity': {
                            'required': False,
                            'choices': [
                                'low',
                                'medium',
                                'high'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'hostname': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'action': {
                            'required': False,
                            'choices': [
                                'allow',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'log': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'severity': {
                            'required': False,
                            'choices': [
                                'low',
                                'medium',
                                'high'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'line-length': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'action': {
                            'required': False,
                            'choices': [
                                'allow',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'length': {
                            'required': False,
                            'type': 'int'
                        },
                        'log': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'severity': {
                            'required': False,
                            'choices': [
                                'low',
                                'medium',
                                'high'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'malformed': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'action': {
                            'required': False,
                            'choices': [
                                'allow',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'log': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'severity': {
                            'required': False,
                            'choices': [
                                'low',
                                'medium',
                                'high'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'max-cookie': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'action': {
                            'required': False,
                            'choices': [
                                'allow',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'log': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'max-cookie': {
                            'required': False,
                            'type': 'int'
                        },
                        'severity': {
                            'required': False,
                            'choices': [
                                'low',
                                'medium',
                                'high'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'max-header-line': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'action': {
                            'required': False,
                            'choices': [
                                'allow',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'log': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'max-header-line': {
                            'required': False,
                            'type': 'int'
                        },
                        'severity': {
                            'required': False,
                            'choices': [
                                'low',
                                'medium',
                                'high'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'max-range-segment': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'action': {
                            'required': False,
                            'choices': [
                                'allow',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'log': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'max-range-segment': {
                            'required': False,
                            'type': 'int'
                        },
                        'severity': {
                            'required': False,
                            'choices': [
                                'low',
                                'medium',
                                'high'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'max-url-param': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'action': {
                            'required': False,
                            'choices': [
                                'allow',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'log': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'max-url-param': {
                            'required': False,
                            'type': 'int'
                        },
                        'severity': {
                            'required': False,
                            'choices': [
                                'low',
                                'medium',
                                'high'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'method': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'action': {
                            'required': False,
                            'choices': [
                                'allow',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'log': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'severity': {
                            'required': False,
                            'choices': [
                                'low',
                                'medium',
                                'high'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'param-length': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'action': {
                            'required': False,
                            'choices': [
                                'allow',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'length': {
                            'required': False,
                            'type': 'int'
                        },
                        'log': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'severity': {
                            'required': False,
                            'choices': [
                                'low',
                                'medium',
                                'high'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'url-param-length': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'action': {
                            'required': False,
                            'choices': [
                                'allow',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'length': {
                            'required': False,
                            'type': 'int'
                        },
                        'log': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'severity': {
                            'required': False,
                            'choices': [
                                'low',
                                'medium',
                                'high'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'version': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'action': {
                            'required': False,
                            'choices': [
                                'allow',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'log': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'severity': {
                            'required': False,
                            'choices': [
                                'low',
                                'medium',
                                'high'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'waf_profile_constraint'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_partial_curd()
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
