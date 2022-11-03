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
module: fmgr_devprof_system_snmp_user
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
    devprof:
        description: the parameter (devprof) in requested url
        type: str
        required: true
    devprof_system_snmp_user:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            auth-proto:
                type: str
                description: no description
                choices:
                    - 'md5'
                    - 'sha'
                    - 'sha224'
                    - 'sha256'
                    - 'sha384'
                    - 'sha512'
            auth-pwd:
                description: description
                type: str
            events:
                description: description
                type: list
                choices:
                 - cpu-high
                 - mem-low
                 - log-full
                 - intf-ip
                 - vpn-tun-up
                 - vpn-tun-down
                 - ha-switch
                 - fm-conf-change
                 - ips-signature
                 - ips-anomaly
                 - temperature-high
                 - voltage-alert
                 - av-virus
                 - av-oversize
                 - av-pattern
                 - av-fragmented
                 - ha-hb-failure
                 - fan-failure
                 - ha-member-up
                 - ha-member-down
                 - ent-conf-change
                 - av-conserve
                 - av-bypass
                 - av-oversize-passed
                 - av-oversize-blocked
                 - ips-pkg-update
                 - fm-if-change
                 - power-supply-failure
                 - amc-bypass
                 - faz-disconnect
                 - bgp-established
                 - bgp-backward-transition
                 - wc-ap-up
                 - wc-ap-down
                 - fswctl-session-up
                 - fswctl-session-down
                 - ips-fail-open
                 - load-balance-real-server-down
                 - device-new
                 - enter-intf-bypass
                 - exit-intf-bypass
                 - per-cpu-high
                 - power-blade-down
                 - confsync_failure
                 - dhcp
                 - pool-usage
                 - power-redundancy-degrade
                 - power-redundancy-failure
                 - ospf-nbr-state-change
                 - ospf-virtnbr-state-change
                 - disk-failure
                 - disk-overload
            ha-direct:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: no description
            notify-hosts:
                description: description
                type: str
            notify-hosts6:
                type: str
                description: no description
            priv-proto:
                type: str
                description: no description
                choices:
                    - 'aes'
                    - 'des'
                    - 'aes256'
                    - 'aes256cisco'
            priv-pwd:
                description: description
                type: str
            queries:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            query-port:
                type: int
                description: no description
            security-level:
                type: str
                description: no description
                choices:
                    - 'no-auth-no-priv'
                    - 'auth-no-priv'
                    - 'auth-priv'
            source-ip:
                type: str
                description: no description
            source-ipv6:
                type: str
                description: no description
            status:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            trap-lport:
                type: int
                description: no description
            trap-rport:
                type: int
                description: no description
            trap-status:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            mib-view:
                type: str
                description: no description
            vdoms:
                description: description
                type: str

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
    - name: SNMP user configuration.
      fmgr_devprof_system_snmp_user:
         bypass_validation: False
         adom: ansible
         devprof: 'ansible-test' # system template name, could find it in FortiManager UI: Device Manager --> Provisioning Templates --> System Templates
         state: present
         devprof_system_snmp_user:
            auth-proto: md5
            auth-pwd: 'fortinet'
            events:
              - cpu-high
              - mem-low
              - log-full
              - intf-ip
              - vpn-tun-up
              - vpn-tun-down
              - ha-switch
              - fm-conf-change
              - ips-signature
              - ips-anomaly
              - temperature-high
              - voltage-alert
              - av-virus
              - av-oversize
              - av-pattern
              - av-fragmented
              - ha-hb-failure
              - fan-failure
              - ha-member-up
              - ha-member-down
              - ent-conf-change
              - av-conserve
              - av-bypass
              - av-oversize-passed
              - av-oversize-blocked
              - ips-pkg-update
              - fm-if-change
              - power-supply-failure
              - amc-bypass
              - faz-disconnect
              - bgp-established
              - bgp-backward-transition
              - wc-ap-up
              - wc-ap-down
              - fswctl-session-up
              - fswctl-session-down
              - ips-fail-open
              - load-balance-real-server-down
              - device-new
              - enter-intf-bypass
              - exit-intf-bypass
              - per-cpu-high
              - power-blade-down
              - confsync_failure
            ha-direct: disable
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
    - name: retrieve all the scripts
      fmgr_fact:
        facts:
            selector: 'devprof_system_snmp_user'
            params:
                adom: 'ansible'
                devprof: 'ansible-test' # system template name, could find it in FortiManager UI: Device Manager --> Provisioning Templates --> System Templates
                user: 'your_value'
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
        '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/user'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/user/{user}'
    ]

    url_params = ['adom', 'devprof']
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
        'devprof': {
            'required': True,
            'type': 'str'
        },
        'devprof_system_snmp_user': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            },
            'options': {
                'auth-proto': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'md5',
                        'sha',
                        'sha224',
                        'sha256',
                        'sha384',
                        'sha512'
                    ],
                    'type': 'str'
                },
                'auth-pwd': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'events': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'choices': [
                        'cpu-high',
                        'mem-low',
                        'log-full',
                        'intf-ip',
                        'vpn-tun-up',
                        'vpn-tun-down',
                        'ha-switch',
                        'fm-conf-change',
                        'ips-signature',
                        'ips-anomaly',
                        'temperature-high',
                        'voltage-alert',
                        'av-virus',
                        'av-oversize',
                        'av-pattern',
                        'av-fragmented',
                        'ha-hb-failure',
                        'fan-failure',
                        'ha-member-up',
                        'ha-member-down',
                        'ent-conf-change',
                        'av-conserve',
                        'av-bypass',
                        'av-oversize-passed',
                        'av-oversize-blocked',
                        'ips-pkg-update',
                        'fm-if-change',
                        'power-supply-failure',
                        'amc-bypass',
                        'faz-disconnect',
                        'bgp-established',
                        'bgp-backward-transition',
                        'wc-ap-up',
                        'wc-ap-down',
                        'fswctl-session-up',
                        'fswctl-session-down',
                        'ips-fail-open',
                        'load-balance-real-server-down',
                        'device-new',
                        'enter-intf-bypass',
                        'exit-intf-bypass',
                        'per-cpu-high',
                        'power-blade-down',
                        'confsync_failure',
                        'dhcp',
                        'pool-usage',
                        'power-redundancy-degrade',
                        'power-redundancy-failure',
                        'ospf-nbr-state-change',
                        'ospf-virtnbr-state-change',
                        'disk-failure',
                        'disk-overload'
                    ]
                },
                'ha-direct': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
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
                'name': {
                    'required': True,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'notify-hosts': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'notify-hosts6': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'priv-proto': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'aes',
                        'des',
                        'aes256',
                        'aes256cisco'
                    ],
                    'type': 'str'
                },
                'priv-pwd': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'queries': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
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
                'query-port': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'security-level': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'no-auth-no-priv',
                        'auth-no-priv',
                        'auth-priv'
                    ],
                    'type': 'str'
                },
                'source-ip': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'source-ipv6': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'status': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
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
                'trap-lport': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'trap-rport': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'trap-status': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
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
                'mib-view': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'vdoms': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'devprof_system_snmp_user'),
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
