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
module: fmgr_pkg_firewall_proxypolicy
short_description: Configure proxy policies.
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
    pkg:
        description: the parameter (pkg) in requested url
        type: str
        required: true
    pkg_firewall_proxypolicy:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: 'Accept or deny traffic matching the policy parameters.'
                choices:
                    - 'accept'
                    - 'deny'
                    - 'redirect'
            application-list:
                type: str
                description: 'Name of an existing Application list.'
            av-profile:
                type: str
                description: 'Name of an existing Antivirus profile.'
            comments:
                type: str
                description: 'Optional comments.'
            disclaimer:
                type: str
                description: 'Web proxy disclaimer setting: by domain, policy, or user.'
                choices:
                    - 'disable'
                    - 'domain'
                    - 'policy'
                    - 'user'
            dlp-sensor:
                type: str
                description: 'Name of an existing DLP sensor.'
            dstaddr:
                type: str
                description: 'Destination address objects.'
            dstaddr-negate:
                type: str
                description: 'When enabled, destination addresses match against any address EXCEPT the specified destination addresses.'
                choices:
                    - 'disable'
                    - 'enable'
            dstaddr6:
                type: str
                description: 'IPv6 destination address objects.'
            dstintf:
                type: str
                description: 'Destination interface names.'
            global-label:
                type: str
                description: 'Global web-based manager visible label.'
            groups:
                type: str
                description: 'Names of group objects.'
            http-tunnel-auth:
                type: str
                description: 'Enable/disable HTTP tunnel authentication.'
                choices:
                    - 'disable'
                    - 'enable'
            icap-profile:
                type: str
                description: 'Name of an existing ICAP profile.'
            internet-service:
                type: str
                description: 'Enable/disable use of Internet Services for this policy. If enabled, destination address and service are not used.'
                choices:
                    - 'disable'
                    - 'enable'
            internet-service-custom:
                type: str
                description: 'Custom Internet Service name.'
            internet-service-id:
                type: str
                description: 'Internet Service ID.'
            internet-service-negate:
                type: str
                description: 'When enabled, Internet Services match against any internet service EXCEPT the selected Internet Service.'
                choices:
                    - 'disable'
                    - 'enable'
            ips-sensor:
                type: str
                description: 'Name of an existing IPS sensor.'
            label:
                type: str
                description: 'VDOM-specific GUI visible label.'
            logtraffic:
                type: str
                description: 'Enable/disable logging traffic through the policy.'
                choices:
                    - 'disable'
                    - 'all'
                    - 'utm'
            logtraffic-start:
                type: str
                description: 'Enable/disable policy log traffic start.'
                choices:
                    - 'disable'
                    - 'enable'
            mms-profile:
                type: str
                description: 'Name of an existing MMS profile.'
            policyid:
                type: int
                description: 'Policy ID.'
            poolname:
                type: str
                description: 'Name of IP pool object.'
            profile-group:
                type: str
                description: 'Name of profile group.'
            profile-protocol-options:
                type: str
                description: 'Name of an existing Protocol options profile.'
            profile-type:
                type: str
                description: 'Determine whether the firewall policy allows security profile groups or single profiles only.'
                choices:
                    - 'single'
                    - 'group'
            proxy:
                type: str
                description: 'Type of explicit proxy.'
                choices:
                    - 'explicit-web'
                    - 'transparent-web'
                    - 'ftp'
                    - 'wanopt'
                    - 'ssh'
                    - 'ssh-tunnel'
            redirect-url:
                type: str
                description: 'Redirect URL for further explicit web proxy processing.'
            replacemsg-override-group:
                type: str
                description: 'Authentication replacement message override group.'
            scan-botnet-connections:
                type: str
                description: 'Enable/disable scanning of connections to Botnet servers.'
                choices:
                    - 'disable'
                    - 'block'
                    - 'monitor'
            schedule:
                type: str
                description: 'Name of schedule object.'
            service:
                type: str
                description: 'Name of service objects.'
            service-negate:
                type: str
                description: 'When enabled, services match against any service EXCEPT the specified destination services.'
                choices:
                    - 'disable'
                    - 'enable'
            spamfilter-profile:
                type: str
                description: 'Name of an existing Spam filter profile.'
            srcaddr:
                type: str
                description: 'Source address objects (must be set when using Web proxy).'
            srcaddr-negate:
                type: str
                description: 'When enabled, source addresses match against any address EXCEPT the specified source addresses.'
                choices:
                    - 'disable'
                    - 'enable'
            srcaddr6:
                type: str
                description: 'IPv6 source address objects.'
            srcintf:
                type: str
                description: 'Source interface names.'
            ssl-ssh-profile:
                type: str
                description: 'Name of an existing SSL SSH profile.'
            status:
                type: str
                description: 'Enable/disable the active status of the policy.'
                choices:
                    - 'disable'
                    - 'enable'
            tags:
                type: str
                description: 'Names of object-tags applied to address. Tags need to be preconfigured in config system object-tag. Separate multiple tags wit...'
            transparent:
                type: str
                description: 'Enable to use the IP address of the client to connect to the server.'
                choices:
                    - 'disable'
                    - 'enable'
            users:
                type: str
                description: 'Names of user objects.'
            utm-status:
                type: str
                description: 'Enable the use of UTM profiles/sensors/lists.'
                choices:
                    - 'disable'
                    - 'enable'
            uuid:
                type: str
                description: 'Universally Unique Identifier (UUID; automatically assigned but can be manually reset).'
            waf-profile:
                type: str
                description: 'Name of an existing Web application firewall profile.'
            webcache:
                type: str
                description: 'Enable/disable web caching.'
                choices:
                    - 'disable'
                    - 'enable'
            webcache-https:
                type: str
                description: 'Enable/disable web caching for HTTPS (Requires deep-inspection enabled in ssl-ssh-profile).'
                choices:
                    - 'disable'
                    - 'enable'
            webfilter-profile:
                type: str
                description: 'Name of an existing Web filter profile.'
            webproxy-forward-server:
                type: str
                description: 'Name of web proxy forward server.'
            webproxy-profile:
                type: str
                description: 'Name of web proxy profile.'

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
    - name: Configure proxy policies.
      fmgr_pkg_firewall_proxypolicy:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         pkg: <your own value>
         state: <value in [present, absent]>
         pkg_firewall_proxypolicy:
            action: <value in [accept, deny, redirect]>
            application-list: <value of string>
            av-profile: <value of string>
            comments: <value of string>
            disclaimer: <value in [disable, domain, policy, ...]>
            dlp-sensor: <value of string>
            dstaddr: <value of string>
            dstaddr-negate: <value in [disable, enable]>
            dstaddr6: <value of string>
            dstintf: <value of string>
            global-label: <value of string>
            groups: <value of string>
            http-tunnel-auth: <value in [disable, enable]>
            icap-profile: <value of string>
            internet-service: <value in [disable, enable]>
            internet-service-custom: <value of string>
            internet-service-id: <value of string>
            internet-service-negate: <value in [disable, enable]>
            ips-sensor: <value of string>
            label: <value of string>
            logtraffic: <value in [disable, all, utm]>
            logtraffic-start: <value in [disable, enable]>
            mms-profile: <value of string>
            policyid: <value of integer>
            poolname: <value of string>
            profile-group: <value of string>
            profile-protocol-options: <value of string>
            profile-type: <value in [single, group]>
            proxy: <value in [explicit-web, transparent-web, ftp, ...]>
            redirect-url: <value of string>
            replacemsg-override-group: <value of string>
            scan-botnet-connections: <value in [disable, block, monitor]>
            schedule: <value of string>
            service: <value of string>
            service-negate: <value in [disable, enable]>
            spamfilter-profile: <value of string>
            srcaddr: <value of string>
            srcaddr-negate: <value in [disable, enable]>
            srcaddr6: <value of string>
            srcintf: <value of string>
            ssl-ssh-profile: <value of string>
            status: <value in [disable, enable]>
            tags: <value of string>
            transparent: <value in [disable, enable]>
            users: <value of string>
            utm-status: <value in [disable, enable]>
            uuid: <value of string>
            waf-profile: <value of string>
            webcache: <value in [disable, enable]>
            webcache-https: <value in [disable, enable]>
            webfilter-profile: <value of string>
            webproxy-forward-server: <value of string>
            webproxy-profile: <value of string>

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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/proxy-policy'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/proxy-policy/{proxy-policy}'
    ]

    url_params = ['adom', 'pkg']
    module_primary_key = 'policyid'
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
        'pkg': {
            'required': True,
            'type': 'str'
        },
        'pkg_firewall_proxypolicy': {
            'required': False,
            'type': 'dict',
            'options': {
                'action': {
                    'required': False,
                    'choices': [
                        'accept',
                        'deny',
                        'redirect'
                    ],
                    'type': 'str'
                },
                'application-list': {
                    'required': False,
                    'type': 'str'
                },
                'av-profile': {
                    'required': False,
                    'type': 'str'
                },
                'comments': {
                    'required': False,
                    'type': 'str'
                },
                'disclaimer': {
                    'required': False,
                    'choices': [
                        'disable',
                        'domain',
                        'policy',
                        'user'
                    ],
                    'type': 'str'
                },
                'dlp-sensor': {
                    'required': False,
                    'type': 'str'
                },
                'dstaddr': {
                    'required': False,
                    'type': 'str'
                },
                'dstaddr-negate': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'dstaddr6': {
                    'required': False,
                    'type': 'str'
                },
                'dstintf': {
                    'required': False,
                    'type': 'str'
                },
                'global-label': {
                    'required': False,
                    'type': 'str'
                },
                'groups': {
                    'required': False,
                    'type': 'str'
                },
                'http-tunnel-auth': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'icap-profile': {
                    'required': False,
                    'type': 'str'
                },
                'internet-service': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'internet-service-custom': {
                    'required': False,
                    'type': 'str'
                },
                'internet-service-id': {
                    'required': False,
                    'type': 'str'
                },
                'internet-service-negate': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ips-sensor': {
                    'required': False,
                    'type': 'str'
                },
                'label': {
                    'required': False,
                    'type': 'str'
                },
                'logtraffic': {
                    'required': False,
                    'choices': [
                        'disable',
                        'all',
                        'utm'
                    ],
                    'type': 'str'
                },
                'logtraffic-start': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'mms-profile': {
                    'required': False,
                    'type': 'str'
                },
                'policyid': {
                    'required': True,
                    'type': 'int'
                },
                'poolname': {
                    'required': False,
                    'type': 'str'
                },
                'profile-group': {
                    'required': False,
                    'type': 'str'
                },
                'profile-protocol-options': {
                    'required': False,
                    'type': 'str'
                },
                'profile-type': {
                    'required': False,
                    'choices': [
                        'single',
                        'group'
                    ],
                    'type': 'str'
                },
                'proxy': {
                    'required': False,
                    'choices': [
                        'explicit-web',
                        'transparent-web',
                        'ftp',
                        'wanopt',
                        'ssh',
                        'ssh-tunnel'
                    ],
                    'type': 'str'
                },
                'redirect-url': {
                    'required': False,
                    'type': 'str'
                },
                'replacemsg-override-group': {
                    'required': False,
                    'type': 'str'
                },
                'scan-botnet-connections': {
                    'required': False,
                    'choices': [
                        'disable',
                        'block',
                        'monitor'
                    ],
                    'type': 'str'
                },
                'schedule': {
                    'required': False,
                    'type': 'str'
                },
                'service': {
                    'required': False,
                    'type': 'str'
                },
                'service-negate': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'spamfilter-profile': {
                    'required': False,
                    'type': 'str'
                },
                'srcaddr': {
                    'required': False,
                    'type': 'str'
                },
                'srcaddr-negate': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'srcaddr6': {
                    'required': False,
                    'type': 'str'
                },
                'srcintf': {
                    'required': False,
                    'type': 'str'
                },
                'ssl-ssh-profile': {
                    'required': False,
                    'type': 'str'
                },
                'status': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'tags': {
                    'required': False,
                    'type': 'str'
                },
                'transparent': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'users': {
                    'required': False,
                    'type': 'str'
                },
                'utm-status': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'uuid': {
                    'required': False,
                    'type': 'str'
                },
                'waf-profile': {
                    'required': False,
                    'type': 'str'
                },
                'webcache': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'webcache-https': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'webfilter-profile': {
                    'required': False,
                    'type': 'str'
                },
                'webproxy-forward-server': {
                    'required': False,
                    'type': 'str'
                },
                'webproxy-profile': {
                    'required': False,
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_proxypolicy'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_curd()
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
