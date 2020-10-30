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
module: fmgr_vpnmgr_node
short_description: VPN node for VPN Manager. Must specify vpntable and scope member.
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
    vpnmgr_node:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            add-route:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            assign-ip:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            assign-ip-from:
                type: str
                description: no description
                choices:
                    - 'range'
                    - 'usrgrp'
                    - 'dhcp'
                    - 'name'
            authpasswd:
                description: no description
                type: str
            authusr:
                type: str
                description: no description
            authusrgrp:
                type: str
                description: no description
            auto-configuration:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            automatic_routing:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            banner:
                type: str
                description: no description
            default-gateway:
                type: str
                description: no description
            dhcp-server:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            dns-mode:
                type: str
                description: no description
                choices:
                    - 'auto'
                    - 'manual'
            dns-service:
                type: str
                description: no description
                choices:
                    - 'default'
                    - 'specify'
                    - 'local'
            domain:
                type: str
                description: no description
            extgw:
                type: str
                description: no description
            extgw_hubip:
                type: str
                description: no description
            extgw_p2_per_net:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            extgwip:
                type: str
                description: no description
            hub_iface:
                type: str
                description: no description
            id:
                type: int
                description: no description
            iface:
                type: str
                description: no description
            ip-range:
                description: no description
                type: list
                suboptions:
                    end-ip:
                        type: str
                        description: no description
                    id:
                        type: int
                        description: no description
                    start-ip:
                        type: str
                        description: no description
            ipsec-lease-hold:
                type: int
                description: no description
            ipv4-dns-server1:
                type: str
                description: no description
            ipv4-dns-server2:
                type: str
                description: no description
            ipv4-dns-server3:
                type: str
                description: no description
            ipv4-end-ip:
                type: str
                description: no description
            ipv4-exclude-range:
                description: no description
                type: list
                suboptions:
                    end-ip:
                        type: str
                        description: no description
                    id:
                        type: int
                        description: no description
                    start-ip:
                        type: str
                        description: no description
            ipv4-netmask:
                type: str
                description: no description
            ipv4-split-include:
                type: str
                description: no description
            ipv4-start-ip:
                type: str
                description: no description
            ipv4-wins-server1:
                type: str
                description: no description
            ipv4-wins-server2:
                type: str
                description: no description
            local-gw:
                type: str
                description: no description
            localid:
                type: str
                description: no description
            mode-cfg:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            mode-cfg-ip-version:
                type: str
                description: no description
                choices:
                    - '4'
                    - '6'
            net-device:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            peer:
                type: str
                description: no description
            peergrp:
                type: str
                description: no description
            peerid:
                type: str
                description: no description
            peertype:
                type: str
                description: no description
                choices:
                    - 'any'
                    - 'one'
                    - 'dialup'
                    - 'peer'
                    - 'peergrp'
            protected_subnet:
                description: no description
                type: list
                suboptions:
                    addr:
                        type: str
                        description: no description
                    seq:
                        type: int
                        description: no description
            public-ip:
                type: str
                description: no description
            role:
                type: str
                description: no description
                choices:
                    - 'hub'
                    - 'spoke'
            route-overlap:
                type: str
                description: no description
                choices:
                    - 'use-old'
                    - 'use-new'
                    - 'allow'
            spoke-zone:
                type: str
                description: no description
            summary_addr:
                description: no description
                type: list
                suboptions:
                    addr:
                        type: str
                        description: no description
                    priority:
                        type: int
                        description: no description
                    seq:
                        type: int
                        description: no description
            tunnel-search:
                type: str
                description: no description
                choices:
                    - 'selectors'
                    - 'nexthop'
            unity-support:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            usrgrp:
                type: str
                description: no description
            vpn-interface-priority:
                type: int
                description: no description
            vpn-zone:
                type: str
                description: no description
            vpntable:
                type: str
                description: no description
            xauthtype:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'client'
                    - 'pap'
                    - 'chap'
                    - 'auto'
            scope member:
                description: no description
                type: list
                suboptions:
                    name:
                        type: str
                        description: 'name of scope member'
                    vdom:
                        type: str
                        description: 'vdom of scope member'

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
    - name: VPN node for VPN Manager. Must specify vpntable and scope member.
      fmgr_vpnmgr_node:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         vpnmgr_node:
            add-route: <value in [disable, enable]>
            assign-ip: <value in [disable, enable]>
            assign-ip-from: <value in [range, usrgrp, dhcp, ...]>
            authpasswd: <value of string>
            authusr: <value of string>
            authusrgrp: <value of string>
            auto-configuration: <value in [disable, enable]>
            automatic_routing: <value in [disable, enable]>
            banner: <value of string>
            default-gateway: <value of string>
            dhcp-server: <value in [disable, enable]>
            dns-mode: <value in [auto, manual]>
            dns-service: <value in [default, specify, local]>
            domain: <value of string>
            extgw: <value of string>
            extgw_hubip: <value of string>
            extgw_p2_per_net: <value in [disable, enable]>
            extgwip: <value of string>
            hub_iface: <value of string>
            id: <value of integer>
            iface: <value of string>
            ip-range:
              -
                  end-ip: <value of string>
                  id: <value of integer>
                  start-ip: <value of string>
            ipsec-lease-hold: <value of integer>
            ipv4-dns-server1: <value of string>
            ipv4-dns-server2: <value of string>
            ipv4-dns-server3: <value of string>
            ipv4-end-ip: <value of string>
            ipv4-exclude-range:
              -
                  end-ip: <value of string>
                  id: <value of integer>
                  start-ip: <value of string>
            ipv4-netmask: <value of string>
            ipv4-split-include: <value of string>
            ipv4-start-ip: <value of string>
            ipv4-wins-server1: <value of string>
            ipv4-wins-server2: <value of string>
            local-gw: <value of string>
            localid: <value of string>
            mode-cfg: <value in [disable, enable]>
            mode-cfg-ip-version: <value in [4, 6]>
            net-device: <value in [disable, enable]>
            peer: <value of string>
            peergrp: <value of string>
            peerid: <value of string>
            peertype: <value in [any, one, dialup, ...]>
            protected_subnet:
              -
                  addr: <value of string>
                  seq: <value of integer>
            public-ip: <value of string>
            role: <value in [hub, spoke]>
            route-overlap: <value in [use-old, use-new, allow]>
            spoke-zone: <value of string>
            summary_addr:
              -
                  addr: <value of string>
                  priority: <value of integer>
                  seq: <value of integer>
            tunnel-search: <value in [selectors, nexthop]>
            unity-support: <value in [disable, enable]>
            usrgrp: <value of string>
            vpn-interface-priority: <value of integer>
            vpn-zone: <value of string>
            vpntable: <value of string>
            xauthtype: <value in [disable, client, pap, ...]>
            scope member:
              -
                  name: <value of string>
                  vdom: <value of string>

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
        '/pm/config/adom/{adom}/obj/vpnmgr/node',
        '/pm/config/global/obj/vpnmgr/node'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}',
        '/pm/config/global/obj/vpnmgr/node/{node}'
    ]

    url_params = ['adom']
    module_primary_key = 'id'
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
        'vpnmgr_node': {
            'required': False,
            'type': 'dict',
            'options': {
                'add-route': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'assign-ip': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'assign-ip-from': {
                    'required': False,
                    'choices': [
                        'range',
                        'usrgrp',
                        'dhcp',
                        'name'
                    ],
                    'type': 'str'
                },
                'authpasswd': {
                    'required': False,
                    'type': 'str'
                },
                'authusr': {
                    'required': False,
                    'type': 'str'
                },
                'authusrgrp': {
                    'required': False,
                    'type': 'str'
                },
                'auto-configuration': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'automatic_routing': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'banner': {
                    'required': False,
                    'type': 'str'
                },
                'default-gateway': {
                    'required': False,
                    'type': 'str'
                },
                'dhcp-server': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'dns-mode': {
                    'required': False,
                    'choices': [
                        'auto',
                        'manual'
                    ],
                    'type': 'str'
                },
                'dns-service': {
                    'required': False,
                    'choices': [
                        'default',
                        'specify',
                        'local'
                    ],
                    'type': 'str'
                },
                'domain': {
                    'required': False,
                    'type': 'str'
                },
                'extgw': {
                    'required': False,
                    'type': 'str'
                },
                'extgw_hubip': {
                    'required': False,
                    'type': 'str'
                },
                'extgw_p2_per_net': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'extgwip': {
                    'required': False,
                    'type': 'str'
                },
                'hub_iface': {
                    'required': False,
                    'type': 'str'
                },
                'id': {
                    'required': True,
                    'type': 'int'
                },
                'iface': {
                    'required': False,
                    'type': 'str'
                },
                'ip-range': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'end-ip': {
                            'required': False,
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'type': 'int'
                        },
                        'start-ip': {
                            'required': False,
                            'type': 'str'
                        }
                    }
                },
                'ipsec-lease-hold': {
                    'required': False,
                    'type': 'int'
                },
                'ipv4-dns-server1': {
                    'required': False,
                    'type': 'str'
                },
                'ipv4-dns-server2': {
                    'required': False,
                    'type': 'str'
                },
                'ipv4-dns-server3': {
                    'required': False,
                    'type': 'str'
                },
                'ipv4-end-ip': {
                    'required': False,
                    'type': 'str'
                },
                'ipv4-exclude-range': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'end-ip': {
                            'required': False,
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'type': 'int'
                        },
                        'start-ip': {
                            'required': False,
                            'type': 'str'
                        }
                    }
                },
                'ipv4-netmask': {
                    'required': False,
                    'type': 'str'
                },
                'ipv4-split-include': {
                    'required': False,
                    'type': 'str'
                },
                'ipv4-start-ip': {
                    'required': False,
                    'type': 'str'
                },
                'ipv4-wins-server1': {
                    'required': False,
                    'type': 'str'
                },
                'ipv4-wins-server2': {
                    'required': False,
                    'type': 'str'
                },
                'local-gw': {
                    'required': False,
                    'type': 'str'
                },
                'localid': {
                    'required': False,
                    'type': 'str'
                },
                'mode-cfg': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'mode-cfg-ip-version': {
                    'required': False,
                    'choices': [
                        '4',
                        '6'
                    ],
                    'type': 'str'
                },
                'net-device': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'peer': {
                    'required': False,
                    'type': 'str'
                },
                'peergrp': {
                    'required': False,
                    'type': 'str'
                },
                'peerid': {
                    'required': False,
                    'type': 'str'
                },
                'peertype': {
                    'required': False,
                    'choices': [
                        'any',
                        'one',
                        'dialup',
                        'peer',
                        'peergrp'
                    ],
                    'type': 'str'
                },
                'protected_subnet': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'addr': {
                            'required': False,
                            'type': 'str'
                        },
                        'seq': {
                            'required': False,
                            'type': 'int'
                        }
                    }
                },
                'public-ip': {
                    'required': False,
                    'type': 'str'
                },
                'role': {
                    'required': False,
                    'choices': [
                        'hub',
                        'spoke'
                    ],
                    'type': 'str'
                },
                'route-overlap': {
                    'required': False,
                    'choices': [
                        'use-old',
                        'use-new',
                        'allow'
                    ],
                    'type': 'str'
                },
                'spoke-zone': {
                    'required': False,
                    'type': 'str'
                },
                'summary_addr': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'addr': {
                            'required': False,
                            'type': 'str'
                        },
                        'priority': {
                            'required': False,
                            'type': 'int'
                        },
                        'seq': {
                            'required': False,
                            'type': 'int'
                        }
                    }
                },
                'tunnel-search': {
                    'required': False,
                    'choices': [
                        'selectors',
                        'nexthop'
                    ],
                    'type': 'str'
                },
                'unity-support': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'usrgrp': {
                    'required': False,
                    'type': 'str'
                },
                'vpn-interface-priority': {
                    'required': False,
                    'type': 'int'
                },
                'vpn-zone': {
                    'required': False,
                    'type': 'str'
                },
                'vpntable': {
                    'required': False,
                    'type': 'str'
                },
                'xauthtype': {
                    'required': False,
                    'choices': [
                        'disable',
                        'client',
                        'pap',
                        'chap',
                        'auto'
                    ],
                    'type': 'str'
                },
                'scope member': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'name': {
                            'required': False,
                            'type': 'str'
                        },
                        'vdom': {
                            'required': False,
                            'type': 'str'
                        }
                    }
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpnmgr_node'),
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
