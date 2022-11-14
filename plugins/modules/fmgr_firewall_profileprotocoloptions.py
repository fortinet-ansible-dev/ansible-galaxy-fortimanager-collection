#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2021 Fortinet, Inc.
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
module: fmgr_firewall_profileprotocoloptions
short_description: no description
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
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
    enable_log:
        description: Enable/Disable logging for task
        required: false
        type: bool
        default: false
    proposed_method:
        description: The overridden method for the underlying Json RPC request
        required: false
        type: str
        choices:
          - update
          - set
          - add
    bypass_validation:
        description: |
          only set to True when module schema diffs with FortiManager API structure,
           module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    workspace_locking_adom:
        description: |
          the adom to lock for FortiManager running in workspace mode, the value can be global and others including root
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
    firewall_profileprotocoloptions:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: no description
            name:
                type: str
                description: no description
            oversize-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            replacemsg-group:
                type: str
                description: no description
            rpc-over-http:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            switching-protocols-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            feature-set:
                type: str
                description: no description
                choices:
                    - 'proxy'
                    - 'flow'
            cifs:
                description: no description
                type: dict
                required: false
                suboptions:
                    domain-controller:
                        type: str
                        description: no description
                    file-filter:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            entries:
                                description: no description
                                type: list
                                suboptions:
                                    action:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'log'
                                            - 'block'
                                    comment:
                                        type: str
                                        description: no description
                                    direction:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'any'
                                            - 'incoming'
                                            - 'outgoing'
                                    file-type:
                                        description: no description
                                        type: str
                                    filter:
                                        type: str
                                        description: no description
                                    protocol:
                                        description: no description
                                        type: list
                                        choices:
                                         - cifs
                            log:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            status:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                    options:
                        description: no description
                        type: list
                        choices:
                         - oversize
                    oversize-limit:
                        type: int
                        description: no description
                    ports:
                        description: no description
                        type: int
                    scan-bzip2:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    server-credential-type:
                        type: str
                        description: no description
                        choices:
                            - 'none'
                            - 'credential-replication'
                            - 'credential-keytab'
                    server-keytab:
                        description: no description
                        type: list
                        suboptions:
                            keytab:
                                type: str
                                description: no description
                            password:
                                description: no description
                                type: str
                            principal:
                                type: str
                                description: no description
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    tcp-window-maximum:
                        type: int
                        description: no description
                    tcp-window-minimum:
                        type: int
                        description: no description
                    tcp-window-size:
                        type: int
                        description: no description
                    tcp-window-type:
                        type: str
                        description: no description
                        choices:
                            - 'system'
                            - 'static'
                            - 'dynamic'
                            - 'auto-tuning'
                    uncompressed-nest-limit:
                        type: int
                        description: no description
                    uncompressed-oversize-limit:
                        type: int
                        description: no description
            dns:
                description: no description
                type: dict
                required: false
                suboptions:
                    ports:
                        description: no description
                        type: int
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
            ftp:
                description: no description
                type: dict
                required: false
                suboptions:
                    comfort-amount:
                        type: int
                        description: no description
                    comfort-interval:
                        type: int
                        description: no description
                    inspect-all:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        description: no description
                        type: list
                        choices:
                         - clientcomfort
                         - no-content-summary
                         - oversize
                         - splice
                         - bypass-rest-command
                         - bypass-mode-command
                    oversize-limit:
                        type: int
                        description: no description
                    ports:
                        description: no description
                        type: int
                    scan-bzip2:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl-offloaded:
                        type: str
                        description: no description
                        choices:
                            - 'no'
                            - 'yes'
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    uncompressed-nest-limit:
                        type: int
                        description: no description
                    uncompressed-oversize-limit:
                        type: int
                        description: no description
                    stream-based-uncompressed-limit:
                        type: int
                        description: no description
                    tcp-window-maximum:
                        type: int
                        description: no description
                    tcp-window-minimum:
                        type: int
                        description: no description
                    tcp-window-size:
                        type: int
                        description: no description
                    tcp-window-type:
                        type: str
                        description: no description
                        choices:
                            - 'system'
                            - 'static'
                            - 'dynamic'
                            - 'auto-tuning'
            http:
                description: no description
                type: dict
                required: false
                suboptions:
                    block-page-status-code:
                        type: int
                        description: no description
                    comfort-amount:
                        type: int
                        description: no description
                    comfort-interval:
                        type: int
                        description: no description
                    fortinet-bar:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    fortinet-bar-port:
                        type: int
                        description: no description
                    inspect-all:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        description: no description
                        type: list
                        choices:
                         - oversize
                         - chunkedbypass
                         - clientcomfort
                         - no-content-summary
                         - servercomfort
                    oversize-limit:
                        type: int
                        description: no description
                    ports:
                        description: no description
                        type: int
                    post-lang:
                        description: no description
                        type: list
                        choices:
                         - jisx0201
                         - jisx0208
                         - jisx0212
                         - gb2312
                         - ksc5601-ex
                         - euc-jp
                         - sjis
                         - iso2022-jp
                         - iso2022-jp-1
                         - iso2022-jp-2
                         - euc-cn
                         - ces-gbk
                         - hz
                         - ces-big5
                         - euc-kr
                         - iso2022-jp-3
                         - iso8859-1
                         - tis620
                         - cp874
                         - cp1252
                         - cp1251
                    proxy-after-tcp-handshake:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    range-block:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    retry-count:
                        type: int
                        description: no description
                    scan-bzip2:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl-offloaded:
                        type: str
                        description: no description
                        choices:
                            - 'no'
                            - 'yes'
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    stream-based-uncompressed-limit:
                        type: int
                        description: no description
                    streaming-content-bypass:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    strip-x-forwarded-for:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    switching-protocols:
                        type: str
                        description: no description
                        choices:
                            - 'bypass'
                            - 'block'
                    tcp-window-maximum:
                        type: int
                        description: no description
                    tcp-window-minimum:
                        type: int
                        description: no description
                    tcp-window-size:
                        type: int
                        description: no description
                    tcp-window-type:
                        type: str
                        description: no description
                        choices:
                            - 'system'
                            - 'static'
                            - 'dynamic'
                            - 'auto-tuning'
                    tunnel-non-http:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    uncompressed-nest-limit:
                        type: int
                        description: no description
                    uncompressed-oversize-limit:
                        type: int
                        description: no description
                    unknown-http-version:
                        type: str
                        description: no description
                        choices:
                            - 'best-effort'
                            - 'reject'
                            - 'tunnel'
                    address-ip-rating:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    h2c:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
            imap:
                description: no description
                type: dict
                required: false
                suboptions:
                    inspect-all:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        description: no description
                        type: list
                        choices:
                         - oversize
                         - fragmail
                         - no-content-summary
                    oversize-limit:
                        type: int
                        description: no description
                    ports:
                        description: no description
                        type: int
                    proxy-after-tcp-handshake:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    scan-bzip2:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl-offloaded:
                        type: str
                        description: no description
                        choices:
                            - 'no'
                            - 'yes'
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    uncompressed-nest-limit:
                        type: int
                        description: no description
                    uncompressed-oversize-limit:
                        type: int
                        description: no description
            mail-signature:
                description: no description
                type: dict
                required: false
                suboptions:
                    signature:
                        type: str
                        description: no description
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
            mapi:
                description: no description
                type: dict
                required: false
                suboptions:
                    options:
                        description: no description
                        type: list
                        choices:
                         - fragmail
                         - oversize
                         - no-content-summary
                    oversize-limit:
                        type: int
                        description: no description
                    ports:
                        description: no description
                        type: int
                    scan-bzip2:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    uncompressed-nest-limit:
                        type: int
                        description: no description
                    uncompressed-oversize-limit:
                        type: int
                        description: no description
            nntp:
                description: no description
                type: dict
                required: false
                suboptions:
                    inspect-all:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        description: no description
                        type: list
                        choices:
                         - oversize
                         - no-content-summary
                         - splice
                    oversize-limit:
                        type: int
                        description: no description
                    ports:
                        description: no description
                        type: int
                    proxy-after-tcp-handshake:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    scan-bzip2:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    uncompressed-nest-limit:
                        type: int
                        description: no description
                    uncompressed-oversize-limit:
                        type: int
                        description: no description
            pop3:
                description: no description
                type: dict
                required: false
                suboptions:
                    inspect-all:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        description: no description
                        type: list
                        choices:
                         - oversize
                         - fragmail
                         - no-content-summary
                    oversize-limit:
                        type: int
                        description: no description
                    ports:
                        description: no description
                        type: int
                    proxy-after-tcp-handshake:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    scan-bzip2:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl-offloaded:
                        type: str
                        description: no description
                        choices:
                            - 'no'
                            - 'yes'
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    uncompressed-nest-limit:
                        type: int
                        description: no description
                    uncompressed-oversize-limit:
                        type: int
                        description: no description
            smtp:
                description: no description
                type: dict
                required: false
                suboptions:
                    inspect-all:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        description: no description
                        type: list
                        choices:
                         - oversize
                         - fragmail
                         - no-content-summary
                         - splice
                    oversize-limit:
                        type: int
                        description: no description
                    ports:
                        description: no description
                        type: int
                    proxy-after-tcp-handshake:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    scan-bzip2:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    server-busy:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl-offloaded:
                        type: str
                        description: no description
                        choices:
                            - 'no'
                            - 'yes'
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    uncompressed-nest-limit:
                        type: int
                        description: no description
                    uncompressed-oversize-limit:
                        type: int
                        description: no description
            ssh:
                description: no description
                type: dict
                required: false
                suboptions:
                    comfort-amount:
                        type: int
                        description: no description
                    comfort-interval:
                        type: int
                        description: no description
                    options:
                        description: no description
                        type: list
                        choices:
                         - oversize
                         - clientcomfort
                         - servercomfort
                    oversize-limit:
                        type: int
                        description: no description
                    scan-bzip2:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    uncompressed-nest-limit:
                        type: int
                        description: no description
                    uncompressed-oversize-limit:
                        type: int
                        description: no description
                    ssl-offloaded:
                        type: str
                        description: no description
                        choices:
                            - 'no'
                            - 'yes'
                    stream-based-uncompressed-limit:
                        type: int
                        description: no description
                    tcp-window-maximum:
                        type: int
                        description: no description
                    tcp-window-minimum:
                        type: int
                        description: no description
                    tcp-window-size:
                        type: int
                        description: no description
                    tcp-window-type:
                        type: str
                        description: no description
                        choices:
                            - 'system'
                            - 'static'
                            - 'dynamic'
                            - 'auto-tuning'

'''

EXAMPLES = '''
 - hosts: fortimanager00
   collections:
     - fortinet.fortimanager
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:
    - name: Configure protocol options.
      fmgr_firewall_profileprotocoloptions:
         bypass_validation: False
         adom: ansible
         state: present
         firewall_profileprotocoloptions:
            comment: 'ansible-comment'
            name: 'ansible-test'

 - name: gathering fortimanager facts
   hosts: fortimanager00
   gather_facts: no
   connection: httpapi
   collections:
     - fortinet.fortimanager
   vars:
     ansible_httpapi_use_ssl: True
     ansible_httpapi_validate_certs: False
     ansible_httpapi_port: 443
   tasks:
    - name: retrieve all the profile protocol options
      fmgr_fact:
        facts:
            selector: 'firewall_profileprotocoloptions'
            params:
                adom: 'ansible'
                profile-protocol-options: 'your_value'
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
        '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options',
        '/pm/config/global/obj/firewall/profile-protocol-options'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}',
        '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'forticloud_access_token': {
            'type': 'str',
            'required': False,
            'no_log': True
        },
        'proposed_method': {
            'type': 'str',
            'required': False,
            'choices': [
                'set',
                'update',
                'add'
            ]
        },
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
        'state': {
            'type': 'str',
            'required': True,
            'choices': [
                'present',
                'absent'
            ]
        },
        'adom': {
            'required': True,
            'type': 'str'
        },
        'firewall_profileprotocoloptions': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            },
            'options': {
                'comment': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'name': {
                    'required': True,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'oversize-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'replacemsg-group': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'rpc-over-http': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'switching-protocols-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'feature-set': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'proxy',
                        'flow'
                    ],
                    'type': 'str'
                },
                'cifs': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'domain-controller': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'file-filter': {
                            'required': False,
                            'type': 'dict',
                            'options': {
                                'entries': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': False,
                                        '7.2.0': False
                                    },
                                    'type': 'list',
                                    'options': {
                                        'action': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': False,
                                                '7.2.0': False
                                            },
                                            'choices': [
                                                'log',
                                                'block'
                                            ],
                                            'type': 'str'
                                        },
                                        'comment': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': False,
                                                '7.2.0': False
                                            },
                                            'type': 'str'
                                        },
                                        'direction': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': False,
                                                '7.2.0': False
                                            },
                                            'choices': [
                                                'any',
                                                'incoming',
                                                'outgoing'
                                            ],
                                            'type': 'str'
                                        },
                                        'file-type': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': False,
                                                '7.2.0': False
                                            },
                                            'type': 'str'
                                        },
                                        'filter': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': False,
                                                '7.2.0': False
                                            },
                                            'type': 'str'
                                        },
                                        'protocol': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': False,
                                                '7.2.0': False
                                            },
                                            'type': 'list',
                                            'choices': [
                                                'cifs'
                                            ]
                                        }
                                    }
                                },
                                'log': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': False,
                                        '7.2.0': False
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'status': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': False,
                                        '7.2.0': False
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                }
                            }
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'oversize'
                            ]
                        },
                        'oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'ports': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'scan-bzip2': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'server-credential-type': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'none',
                                'credential-replication',
                                'credential-keytab'
                            ],
                            'type': 'str'
                        },
                        'server-keytab': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'options': {
                                'keytab': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'password': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'principal': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                }
                            }
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'tcp-window-maximum': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-minimum': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-size': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-type': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'system',
                                'static',
                                'dynamic',
                                'auto-tuning'
                            ],
                            'type': 'str'
                        },
                        'uncompressed-nest-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'uncompressed-oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'dns': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'ports': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'ftp': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'comfort-amount': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'comfort-interval': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'inspect-all': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'clientcomfort',
                                'no-content-summary',
                                'oversize',
                                'splice',
                                'bypass-rest-command',
                                'bypass-mode-command'
                            ]
                        },
                        'oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'ports': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'scan-bzip2': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'ssl-offloaded': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'no',
                                'yes'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'uncompressed-nest-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'uncompressed-oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'stream-based-uncompressed-limit': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-maximum': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-minimum': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-size': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-type': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'system',
                                'static',
                                'dynamic',
                                'auto-tuning'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'http': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'block-page-status-code': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'comfort-amount': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'comfort-interval': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'fortinet-bar': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': False,
                                '7.2.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'fortinet-bar-port': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': False,
                                '7.2.0': False
                            },
                            'type': 'int'
                        },
                        'inspect-all': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'oversize',
                                'chunkedbypass',
                                'clientcomfort',
                                'no-content-summary',
                                'servercomfort'
                            ]
                        },
                        'oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'ports': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'post-lang': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'jisx0201',
                                'jisx0208',
                                'jisx0212',
                                'gb2312',
                                'ksc5601-ex',
                                'euc-jp',
                                'sjis',
                                'iso2022-jp',
                                'iso2022-jp-1',
                                'iso2022-jp-2',
                                'euc-cn',
                                'ces-gbk',
                                'hz',
                                'ces-big5',
                                'euc-kr',
                                'iso2022-jp-3',
                                'iso8859-1',
                                'tis620',
                                'cp874',
                                'cp1252',
                                'cp1251'
                            ]
                        },
                        'proxy-after-tcp-handshake': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'range-block': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'retry-count': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'scan-bzip2': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'ssl-offloaded': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'no',
                                'yes'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'stream-based-uncompressed-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'streaming-content-bypass': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'strip-x-forwarded-for': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'switching-protocols': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'bypass',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'tcp-window-maximum': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-minimum': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-size': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-type': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'system',
                                'static',
                                'dynamic',
                                'auto-tuning'
                            ],
                            'type': 'str'
                        },
                        'tunnel-non-http': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'uncompressed-nest-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'uncompressed-oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'unknown-http-version': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'best-effort',
                                'reject',
                                'tunnel'
                            ],
                            'type': 'str'
                        },
                        'address-ip-rating': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'h2c': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'imap': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'inspect-all': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'oversize',
                                'fragmail',
                                'no-content-summary'
                            ]
                        },
                        'oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'ports': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'proxy-after-tcp-handshake': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'scan-bzip2': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'ssl-offloaded': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'no',
                                'yes'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'uncompressed-nest-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'uncompressed-oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'mail-signature': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'signature': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'mapi': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'fragmail',
                                'oversize',
                                'no-content-summary'
                            ]
                        },
                        'oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'ports': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'scan-bzip2': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'uncompressed-nest-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'uncompressed-oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'nntp': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'inspect-all': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'oversize',
                                'no-content-summary',
                                'splice'
                            ]
                        },
                        'oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'ports': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'proxy-after-tcp-handshake': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'scan-bzip2': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'uncompressed-nest-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'uncompressed-oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'pop3': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'inspect-all': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'oversize',
                                'fragmail',
                                'no-content-summary'
                            ]
                        },
                        'oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'ports': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'proxy-after-tcp-handshake': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'scan-bzip2': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'ssl-offloaded': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'no',
                                'yes'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'uncompressed-nest-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'uncompressed-oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'smtp': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'inspect-all': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'oversize',
                                'fragmail',
                                'no-content-summary',
                                'splice'
                            ]
                        },
                        'oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'ports': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'proxy-after-tcp-handshake': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'scan-bzip2': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'server-busy': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'ssl-offloaded': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'no',
                                'yes'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'uncompressed-nest-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'uncompressed-oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'ssh': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'comfort-amount': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'comfort-interval': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'oversize',
                                'clientcomfort',
                                'servercomfort'
                            ]
                        },
                        'oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'scan-bzip2': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'uncompressed-nest-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'uncompressed-oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'ssl-offloaded': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'no',
                                'yes'
                            ],
                            'type': 'str'
                        },
                        'stream-based-uncompressed-limit': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-maximum': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-minimum': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-size': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-type': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'system',
                                'static',
                                'dynamic',
                                'auto-tuning'
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_profileprotocoloptions'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        connection.set_option('forticloud_access_token',
                              module.params['forticloud_access_token'] if 'forticloud_access_token' in module.params else None)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
