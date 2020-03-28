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
module: fmgr_firewall_address_obj
short_description: Configure IPv4 addresses.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ clone delete get set update ] the following apis.
    - /pm/config/adom/{adom}/obj/firewall/address/{address}
    - /pm/config/global/obj/firewall/address/{address}
    - Examples include all parameters and values need to be adjusted to data sources before usage.

version_added: "2.10"
author:
    - Frank Shen (@fshen01)
    - Link Zheng (@zhengl)
notes:
    - There are only three top-level parameters where 'method' is always required
      while other two 'params' and 'url_params' can be optional
    - Due to the complexity of fortimanager api schema, the validation is done
      out of Ansible native parameter validation procedure.
    - The syntax of OPTIONS doen not comply with the standard Ansible argument
      specification, but with the structure of fortimanager API schema, we need
      a trivial transformation when we are filling the ansible playbook
options:
    url_params:
        description: the parameters in url path
        required: True
        type: dict
        suboptions:
            adom:
                type: str
                description: the domain prefix, the none and global are reserved
                choices:
                  - none
                  - global
                  - custom dom
            address:
                type: str
    schema_object0:
        methods: [clone, set, update]
        description: 'Configure IPv4 addresses.'
        api_categories: [api_tag0]
        api_tag0:
            data:
                allow-routing:
                    type: str
                    description: 'Enable/disable use of this address in the static route configuration.'
                    choices:
                        - 'disable'
                        - 'enable'
                associated-interface:
                    type: str
                    description: 'Network interface associated with address.'
                cache-ttl:
                    type: int
                    description: 'Defines the minimal TTL of individual IP addresses in FQDN cache measured in seconds.'
                color:
                    type: int
                    description: 'Color of icon on the GUI.'
                comment:
                    type: str
                country:
                    type: str
                    description: 'IP addresses associated to a specific country.'
                dynamic_mapping:
                    -
                        _scope:
                            -
                                name:
                                    type: str
                                vdom:
                                    type: str
                        allow-routing:
                            type: str
                            choices:
                                - 'disable'
                                - 'enable'
                        associated-interface:
                            type: str
                        cache-ttl:
                            type: int
                        color:
                            type: int
                        comment:
                            type: str
                        country:
                            type: str
                        end-ip:
                            type: str
                        end-mac:
                            type: str
                        epg-name:
                            type: str
                        filter:
                            type: str
                        fqdn:
                            type: str
                        interface:
                            type: str
                        obj-id:
                            type: str
                        organization:
                            type: str
                        policy-group:
                            type: str
                        sdn:
                            type: str
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
                            choices:
                                - 'private'
                                - 'public'
                                - 'all'
                        sdn-tag:
                            type: str
                        start-ip:
                            type: str
                        start-mac:
                            type: str
                        subnet:
                            type: str
                        subnet-name:
                            type: str
                        tags:
                            type: str
                        tenant:
                            type: str
                        type:
                            type: str
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
                        uuid:
                            type: str
                        visibility:
                            type: str
                            choices:
                                - 'disable'
                                - 'enable'
                        wildcard:
                            type: str
                        wildcard-fqdn:
                            type: str
                end-ip:
                    type: str
                    description: 'Final IP address (inclusive) in the range for the address.'
                epg-name:
                    type: str
                    description: 'Endpoint group name.'
                filter:
                    type: str
                    description: 'Match criteria filter.'
                fqdn:
                    type: str
                    description: 'Fully Qualified Domain Name address.'
                list:
                    -
                        ip:
                            type: str
                            description: 'IP.'
                name:
                    type: str
                    description: 'Address name.'
                obj-id:
                    type: str
                    description: 'Object ID for NSX.'
                organization:
                    type: str
                    description: 'Organization domain name (Syntax: organization/domain).'
                policy-group:
                    type: str
                    description: 'Policy group name.'
                sdn:
                    type: str
                    description: 'SDN.'
                    choices:
                        - 'aci'
                        - 'aws'
                        - 'nsx'
                        - 'nuage'
                        - 'azure'
                        - 'gcp'
                        - 'oci'
                        - 'openstack'
                sdn-tag:
                    type: str
                    description: 'SDN Tag.'
                start-ip:
                    type: str
                    description: 'First IP address (inclusive) in the range for the address.'
                subnet:
                    type: str
                    description: 'IP address and subnet mask of address.'
                subnet-name:
                    type: str
                    description: 'Subnet name.'
                tagging:
                    -
                        category:
                            type: str
                            description: 'Tag category.'
                        name:
                            type: str
                            description: 'Tagging entry name.'
                        tags:
                            -
                                type: str
                tenant:
                    type: str
                    description: 'Tenant.'
                type:
                    type: str
                    description: 'Type of address.'
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
                uuid:
                    type: str
                    description: 'Universally Unique Identifier (UUID; automatically assigned but can be manually reset).'
                visibility:
                    type: str
                    description: 'Enable/disable address visibility in the GUI.'
                    choices:
                        - 'disable'
                        - 'enable'
                wildcard:
                    type: str
                    description: 'IP address and wildcard netmask.'
                wildcard-fqdn:
                    type: str
                    description: 'Fully Qualified Domain Name with wildcard characters.'
    schema_object1:
        methods: [delete]
        description: 'Configure IPv4 addresses.'
        api_categories: [api_tag0]
        api_tag0:
    schema_object2:
        methods: [get]
        description: 'Configure IPv4 addresses.'
        api_categories: [api_tag0]
        api_tag0:
            option:
                type: str
                description:
                 - 'Set fetch option for the request. If no option is specified, by default the attributes of the object will be returned.'
                 - 'object member - Return a list of object members along with other attributes.'
                 - 'chksum - Return the check-sum value instead of attributes.'
                choices:
                    - 'object member'
                    - 'chksum'
                    - 'datasrc'

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

    - name: REQUESTING /PM/CONFIG/OBJ/FIREWALL/ADDRESS/{ADDRESS}
      fmgr_firewall_address_obj:
         method: <value in [clone, set, update]>
         url_params:
            adom: <value in [none, global, custom dom]>
            address: <value of string>
         params:
            -
               data:
                  allow-routing: <value in [disable, enable]>
                  associated-interface: <value of string>
                  cache-ttl: <value of integer>
                  color: <value of integer>
                  comment: <value of string>
                  country: <value of string>
                  dynamic_mapping:
                    -
                        _scope:
                          -
                              name: <value of string>
                              vdom: <value of string>
                        allow-routing: <value in [disable, enable]>
                        associated-interface: <value of string>
                        cache-ttl: <value of integer>
                        color: <value of integer>
                        comment: <value of string>
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
                  end-ip: <value of string>
                  epg-name: <value of string>
                  filter: <value of string>
                  fqdn: <value of string>
                  list:
                    -
                        ip: <value of string>
                  name: <value of string>
                  obj-id: <value of string>
                  organization: <value of string>
                  policy-group: <value of string>
                  sdn: <value in [aci, aws, nsx, ...]>
                  sdn-tag: <value of string>
                  start-ip: <value of string>
                  subnet: <value of string>
                  subnet-name: <value of string>
                  tagging:
                    -
                        category: <value of string>
                        name: <value of string>
                        tags:
                          - <value of string>
                  tenant: <value of string>
                  type: <value in [ipmask, iprange, fqdn, ...]>
                  uuid: <value of string>
                  visibility: <value in [disable, enable]>
                  wildcard: <value of string>
                  wildcard-fqdn: <value of string>

    - name: REQUESTING /PM/CONFIG/OBJ/FIREWALL/ADDRESS/{ADDRESS}
      fmgr_firewall_address_obj:
         method: <value in [get]>
         url_params:
            adom: <value in [none, global, custom dom]>
            address: <value of string>
         params:
            -
               option: <value in [object member, chksum, datasrc]>

'''

RETURN = '''
return_of_api_category_0:
   description: items returned for method:[clone, delete, set, update]
   returned: always
   suboptions:
      id:
         type: int
      result:
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/config/adom/{adom}/obj/firewall/address/{address}'
return_of_api_category_0:
   description: items returned for method:[get]
   returned: always
   suboptions:
      id:
         type: int
      result:
         data:
            allow-routing:
               type: str
               description: 'Enable/disable use of this address in the static route configuration.'
            associated-interface:
               type: str
               description: 'Network interface associated with address.'
            cache-ttl:
               type: int
               description: 'Defines the minimal TTL of individual IP addresses in FQDN cache measured in seconds.'
            color:
               type: int
               description: 'Color of icon on the GUI.'
            comment:
               type: str
            country:
               type: str
               description: 'IP addresses associated to a specific country.'
            dynamic_mapping:
               type: array
               suboptions:
                  _scope:
                     type: array
                     suboptions:
                        name:
                           type: str
                        vdom:
                           type: str
                  allow-routing:
                     type: str
                  associated-interface:
                     type: str
                  cache-ttl:
                     type: int
                  color:
                     type: int
                  comment:
                     type: str
                  country:
                     type: str
                  end-ip:
                     type: str
                  end-mac:
                     type: str
                  epg-name:
                     type: str
                  filter:
                     type: str
                  fqdn:
                     type: str
                  interface:
                     type: str
                  obj-id:
                     type: str
                  organization:
                     type: str
                  policy-group:
                     type: str
                  sdn:
                     type: str
                  sdn-addr-type:
                     type: str
                  sdn-tag:
                     type: str
                  start-ip:
                     type: str
                  start-mac:
                     type: str
                  subnet:
                     type: str
                  subnet-name:
                     type: str
                  tags:
                     type: str
                  tenant:
                     type: str
                  type:
                     type: str
                  url:
                     type: str
                  uuid:
                     type: str
                  visibility:
                     type: str
                  wildcard:
                     type: str
                  wildcard-fqdn:
                     type: str
            end-ip:
               type: str
               description: 'Final IP address (inclusive) in the range for the address.'
            epg-name:
               type: str
               description: 'Endpoint group name.'
            filter:
               type: str
               description: 'Match criteria filter.'
            fqdn:
               type: str
               description: 'Fully Qualified Domain Name address.'
            list:
               type: array
               suboptions:
                  ip:
                     type: str
                     description: 'IP.'
            name:
               type: str
               description: 'Address name.'
            obj-id:
               type: str
               description: 'Object ID for NSX.'
            organization:
               type: str
               description: 'Organization domain name (Syntax: organization/domain).'
            policy-group:
               type: str
               description: 'Policy group name.'
            sdn:
               type: str
               description: 'SDN.'
            sdn-tag:
               type: str
               description: 'SDN Tag.'
            start-ip:
               type: str
               description: 'First IP address (inclusive) in the range for the address.'
            subnet:
               type: str
               description: 'IP address and subnet mask of address.'
            subnet-name:
               type: str
               description: 'Subnet name.'
            tagging:
               type: array
               suboptions:
                  category:
                     type: str
                     description: 'Tag category.'
                  name:
                     type: str
                     description: 'Tagging entry name.'
                  tags:
                     type: array
                     suboptions:
                        type: str
            tenant:
               type: str
               description: 'Tenant.'
            type:
               type: str
               description: 'Type of address.'
            uuid:
               type: str
               description: 'Universally Unique Identifier (UUID; automatically assigned but can be manually reset).'
            visibility:
               type: str
               description: 'Enable/disable address visibility in the GUI.'
            wildcard:
               type: str
               description: 'IP address and wildcard netmask.'
            wildcard-fqdn:
               type: str
               description: 'Fully Qualified Domain Name with wildcard characters.'
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/config/adom/{adom}/obj/firewall/address/{address}'

'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FAIL_SOCKET_MSG
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import DEFAULT_RESULT_OBJ
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FMGRCommon
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FMGBaseException
from ansible_collections.fortinet.fortimanager.plugins.module_utils.fortimanager import FortiManagerHandler


def main():
    jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/address/{address}',
        '/pm/config/global/obj/firewall/address/{address}'
    ]

    url_schema = [
        {
            'name': 'adom',
            'type': 'string'
        },
        {
            'name': 'address',
            'type': 'string'
        }
    ]

    body_schema = {
        'schema_objects': {
            'object0': [
                {
                    'name': 'data',
                    'type': 'dict',
                    'dict': {
                        'allow-routing': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'associated-interface': {
                            'type': 'string'
                        },
                        'cache-ttl': {
                            'type': 'integer'
                        },
                        'color': {
                            'type': 'integer'
                        },
                        'comment': {
                            'type': 'string'
                        },
                        'country': {
                            'type': 'string'
                        },
                        'dynamic_mapping': {
                            'type': 'array',
                            'items': {
                                '_scope': {
                                    'type': 'array',
                                    'items': {
                                        'name': {
                                            'type': 'string'
                                        },
                                        'vdom': {
                                            'type': 'string'
                                        }
                                    }
                                },
                                'allow-routing': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'associated-interface': {
                                    'type': 'string'
                                },
                                'cache-ttl': {
                                    'type': 'integer'
                                },
                                'color': {
                                    'type': 'integer'
                                },
                                'comment': {
                                    'type': 'string'
                                },
                                'country': {
                                    'type': 'string'
                                },
                                'end-ip': {
                                    'type': 'string'
                                },
                                'end-mac': {
                                    'type': 'string'
                                },
                                'epg-name': {
                                    'type': 'string'
                                },
                                'filter': {
                                    'type': 'string'
                                },
                                'fqdn': {
                                    'type': 'string'
                                },
                                'interface': {
                                    'type': 'string'
                                },
                                'obj-id': {
                                    'type': 'string'
                                },
                                'organization': {
                                    'type': 'string'
                                },
                                'policy-group': {
                                    'type': 'string'
                                },
                                'sdn': {
                                    'type': 'string',
                                    'enum': [
                                        'aci',
                                        'aws',
                                        'nsx',
                                        'nuage',
                                        'azure',
                                        'gcp',
                                        'oci',
                                        'openstack'
                                    ]
                                },
                                'sdn-addr-type': {
                                    'type': 'string',
                                    'enum': [
                                        'private',
                                        'public',
                                        'all'
                                    ]
                                },
                                'sdn-tag': {
                                    'type': 'string'
                                },
                                'start-ip': {
                                    'type': 'string'
                                },
                                'start-mac': {
                                    'type': 'string'
                                },
                                'subnet': {
                                    'type': 'string'
                                },
                                'subnet-name': {
                                    'type': 'string'
                                },
                                'tags': {
                                    'type': 'string'
                                },
                                'tenant': {
                                    'type': 'string'
                                },
                                'type': {
                                    'type': 'string',
                                    'enum': [
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
                                    ]
                                },
                                'url': {
                                    'type': 'string'
                                },
                                'uuid': {
                                    'type': 'string'
                                },
                                'visibility': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'wildcard': {
                                    'type': 'string'
                                },
                                'wildcard-fqdn': {
                                    'type': 'string'
                                }
                            }
                        },
                        'end-ip': {
                            'type': 'string'
                        },
                        'epg-name': {
                            'type': 'string'
                        },
                        'filter': {
                            'type': 'string'
                        },
                        'fqdn': {
                            'type': 'string'
                        },
                        'list': {
                            'type': 'array',
                            'items': {
                                'ip': {
                                    'type': 'string'
                                }
                            }
                        },
                        'name': {
                            'type': 'string'
                        },
                        'obj-id': {
                            'type': 'string'
                        },
                        'organization': {
                            'type': 'string'
                        },
                        'policy-group': {
                            'type': 'string'
                        },
                        'sdn': {
                            'type': 'string',
                            'enum': [
                                'aci',
                                'aws',
                                'nsx',
                                'nuage',
                                'azure',
                                'gcp',
                                'oci',
                                'openstack'
                            ]
                        },
                        'sdn-tag': {
                            'type': 'string'
                        },
                        'start-ip': {
                            'type': 'string'
                        },
                        'subnet': {
                            'type': 'string'
                        },
                        'subnet-name': {
                            'type': 'string'
                        },
                        'tagging': {
                            'type': 'array',
                            'items': {
                                'category': {
                                    'type': 'string'
                                },
                                'name': {
                                    'type': 'string'
                                },
                                'tags': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
                                }
                            }
                        },
                        'tenant': {
                            'type': 'string'
                        },
                        'type': {
                            'type': 'string',
                            'enum': [
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
                            ]
                        },
                        'uuid': {
                            'type': 'string'
                        },
                        'visibility': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'wildcard': {
                            'type': 'string'
                        },
                        'wildcard-fqdn': {
                            'type': 'string'
                        }
                    },
                    'api_tag': 0
                },
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 0
                }
            ],
            'object1': [
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 0
                }
            ],
            'object2': [
                {
                    'name': 'option',
                    'type': 'dict',
                    'dict': {
                        'type': 'string',
                        'enum': [
                            'object member',
                            'chksum',
                            'datasrc'
                        ]
                    },
                    'api_tag': 0
                },
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 0
                }
            ]
        },
        'method_mapping': {
            'clone': 'object0',
            'delete': 'object1',
            'get': 'object2',
            'set': 'object0',
            'update': 'object0'
        }
    }

    module_arg_spec = {
        'loose_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'params': {
            'type': 'list',
            'required': False
        },
        'method': {
            'type': 'str',
            'required': True,
            'choices': [
                'clone',
                'delete',
                'get',
                'set',
                'update'
            ]
        },
        'url_params': {
            'type': 'dict',
            'required': False
        }
    }
    module = AnsibleModule(argument_spec=module_arg_spec,
                           supports_check_mode=False)
    method = module.params['method']
    loose_validation = module.params['loose_validation']

    fmgr = None
    payload = None
    response = DEFAULT_RESULT_OBJ

    if module._socket_path:
        connection = Connection(module._socket_path)
        tools = FMGRCommon()
        if loose_validation == False:
            tools.validate_module_params(module, body_schema)
        tools.validate_module_url_params(module, jrpc_urls, url_schema)
        full_url = tools.get_full_url_path(module, jrpc_urls)
        payload = tools.get_full_payload(module, full_url)
        fmgr = FortiManagerHandler(connection, module)
        fmgr.tools = tools
    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    try:
        response = fmgr._conn.send_request(method, payload)
        fmgr.govern_response(module=module, results=response,
                             msg='Operation Finished',
                             ansible_facts=fmgr.construct_ansible_facts(response, module.params, module.params))
    except Exception as e:
        raise FMGBaseException(e)

    module.exit_json(meta=response[1])


if __name__ == '__main__':
    main()
