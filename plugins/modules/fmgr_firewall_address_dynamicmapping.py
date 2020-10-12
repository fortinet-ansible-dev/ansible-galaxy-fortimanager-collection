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
module: fmgr_firewall_address_dynamicmapping
short_description: no description
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
    address:
        description: the parameter (address) in requested url
        type: str
        required: true
    firewall_address_dynamicmapping:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            _scope:
                description: no description
                type: list
                suboptions:
                    name:
                        type: str
                        description: no description
                    vdom:
                        type: str
                        description: no description
            allow-routing:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            associated-interface:
                type: str
                description: no description
            cache-ttl:
                type: int
                description: no description
            color:
                type: int
                description: no description
            comment:
                description: no description
                type: dict
            country:
                type: str
                description: no description
            end-ip:
                type: str
                description: no description
            end-mac:
                type: str
                description: no description
            epg-name:
                type: str
                description: no description
            filter:
                type: str
                description: no description
            fqdn:
                type: str
                description: no description
            interface:
                type: str
                description: no description
            obj-id:
                type: str
                description: no description
            organization:
                type: str
                description: no description
            policy-group:
                type: str
                description: no description
            sdn:
                type: str
                description: no description
                choices:
                    - 'aci'
                    - 'aws'
                    - 'nsx'
                    - 'nuage'
                    - 'azure'
                    - 'gcp'
                    - 'oci'
                    - 'openstack'
            sdn-addr-type:
                type: str
                description: no description
                choices:
                    - 'private'
                    - 'public'
                    - 'all'
            sdn-tag:
                type: str
                description: no description
            start-ip:
                type: str
                description: no description
            start-mac:
                type: str
                description: no description
            subnet:
                type: str
                description: no description
            subnet-name:
                type: str
                description: no description
            tags:
                type: str
                description: no description
            tenant:
                type: str
                description: no description
            type:
                type: str
                description: no description
                choices:
                    - 'ipmask'
                    - 'iprange'
                    - 'fqdn'
                    - 'wildcard'
                    - 'geography'
                    - 'url'
                    - 'wildcard-fqdn'
                    - 'nsx'
                    - 'aws'
                    - 'dynamic'
                    - 'interface-subnet'
                    - 'mac'
            url:
                type: str
                description: no description
            uuid:
                type: str
                description: no description
            visibility:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            wildcard:
                type: str
                description: no description
            wildcard-fqdn:
                type: str
                description: no description

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
    - name: no description
      fmgr_firewall_address_dynamicmapping:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         address: <your own value>
         state: <value in [present, absent]>
         firewall_address_dynamicmapping:
            _scope:
              -
                  name: <value of string>
                  vdom: <value of string>
            allow-routing: <value in [disable, enable]>
            associated-interface: <value of string>
            cache-ttl: <value of integer>
            color: <value of integer>
            comment: <value of dict>
            country: <value of string>
            end-ip: <value of string>
            end-mac: <value of string>
            epg-name: <value of string>
            filter: <value of string>
            fqdn: <value of string>
            interface: <value of string>
            obj-id: <value of string>
            organization: <value of string>
            policy-group: <value of string>
            sdn: <value in [aci, aws, nsx, ...]>
            sdn-addr-type: <value in [private, public, all]>
            sdn-tag: <value of string>
            start-ip: <value of string>
            start-mac: <value of string>
            subnet: <value of string>
            subnet-name: <value of string>
            tags: <value of string>
            tenant: <value of string>
            type: <value in [ipmask, iprange, fqdn, ...]>
            url: <value of string>
            uuid: <value of string>
            visibility: <value in [disable, enable]>
            wildcard: <value of string>
            wildcard-fqdn: <value of string>

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
        '/pm/config/adom/{adom}/obj/firewall/address/{address}/dynamic_mapping',
        '/pm/config/global/obj/firewall/address/{address}/dynamic_mapping'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/address/{address}/dynamic_mapping/{dynamic_mapping}',
        '/pm/config/global/obj/firewall/address/{address}/dynamic_mapping/{dynamic_mapping}'
    ]

    url_params = ['adom', 'address']
    module_primary_key = 'complex:{{module}}["_scope"][0]["name"]+"/"+{{module}}["_scope"][0]["vdom"]'
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
        'address': {
            'required': True,
            'type': 'str'
        },
        'firewall_address_dynamicmapping': {
            'required': False,
            'type': 'dict',
            'options': {
                '_scope': {
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
                },
                'allow-routing': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'associated-interface': {
                    'required': False,
                    'type': 'str'
                },
                'cache-ttl': {
                    'required': False,
                    'type': 'int'
                },
                'color': {
                    'required': False,
                    'type': 'int'
                },
                'comment': {
                    'required': False,
                    'type': 'dict'
                },
                'country': {
                    'required': False,
                    'type': 'str'
                },
                'end-ip': {
                    'required': False,
                    'type': 'str'
                },
                'end-mac': {
                    'required': False,
                    'type': 'str'
                },
                'epg-name': {
                    'required': False,
                    'type': 'str'
                },
                'filter': {
                    'required': False,
                    'type': 'str'
                },
                'fqdn': {
                    'required': False,
                    'type': 'str'
                },
                'interface': {
                    'required': False,
                    'type': 'str'
                },
                'obj-id': {
                    'required': False,
                    'type': 'str'
                },
                'organization': {
                    'required': False,
                    'type': 'str'
                },
                'policy-group': {
                    'required': False,
                    'type': 'str'
                },
                'sdn': {
                    'required': False,
                    'choices': [
                        'aci',
                        'aws',
                        'nsx',
                        'nuage',
                        'azure',
                        'gcp',
                        'oci',
                        'openstack'
                    ],
                    'type': 'str'
                },
                'sdn-addr-type': {
                    'required': False,
                    'choices': [
                        'private',
                        'public',
                        'all'
                    ],
                    'type': 'str'
                },
                'sdn-tag': {
                    'required': False,
                    'type': 'str'
                },
                'start-ip': {
                    'required': False,
                    'type': 'str'
                },
                'start-mac': {
                    'required': False,
                    'type': 'str'
                },
                'subnet': {
                    'required': False,
                    'type': 'str'
                },
                'subnet-name': {
                    'required': False,
                    'type': 'str'
                },
                'tags': {
                    'required': False,
                    'type': 'str'
                },
                'tenant': {
                    'required': False,
                    'type': 'str'
                },
                'type': {
                    'required': False,
                    'choices': [
                        'ipmask',
                        'iprange',
                        'fqdn',
                        'wildcard',
                        'geography',
                        'url',
                        'wildcard-fqdn',
                        'nsx',
                        'aws',
                        'dynamic',
                        'interface-subnet',
                        'mac'
                    ],
                    'type': 'str'
                },
                'url': {
                    'required': False,
                    'type': 'str'
                },
                'uuid': {
                    'required': False,
                    'type': 'str'
                },
                'visibility': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'wildcard': {
                    'required': False,
                    'type': 'str'
                },
                'wildcard-fqdn': {
                    'required': False,
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_address_dynamicmapping'),
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
