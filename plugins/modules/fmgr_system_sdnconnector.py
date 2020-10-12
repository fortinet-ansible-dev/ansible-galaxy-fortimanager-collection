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
module: fmgr_system_sdnconnector
short_description: Configure connection to SDN Connector.
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
    system_sdnconnector:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            _local_cert:
                type: str
                description: no description
            access-key:
                type: str
                description: 'AWS access key ID.'
            azure-region:
                type: str
                description: 'Azure server region.'
                choices:
                    - 'global'
                    - 'china'
                    - 'germany'
                    - 'usgov'
                    - 'local'
            client-id:
                type: str
                description: 'Azure client ID (application ID).'
            client-secret:
                description: no description
                type: str
            compartment-id:
                type: str
                description: 'Compartment ID.'
            external-ip:
                description: no description
                type: list
                suboptions:
                    name:
                        type: str
                        description: 'External IP name.'
            gcp-project:
                type: str
                description: 'GCP project name.'
            key-passwd:
                description: no description
                type: str
            login-endpoint:
                type: str
                description: 'Azure Stack login enpoint.'
            name:
                type: str
                description: 'SDN connector name.'
            nic:
                description: no description
                type: list
                suboptions:
                    ip:
                        description: no description
                        type: list
                        suboptions:
                            name:
                                type: str
                                description: 'IP configuration name.'
                            public-ip:
                                type: str
                                description: 'Public IP name.'
                    name:
                        type: str
                        description: 'Network interface name.'
            nsx-cert-fingerprint:
                type: str
                description: 'NSX certificate fingerprint.'
            oci-cert:
                type: str
                description: 'OCI certificate.'
            oci-fingerprint:
                type: str
                description: no description
            oci-region:
                type: str
                description: 'OCI server region.'
                choices:
                    - 'phoenix'
                    - 'ashburn'
                    - 'frankfurt'
                    - 'london'
                    - 'toronto'
            password:
                description: no description
                type: str
            private-key:
                type: str
                description: 'Private key of GCP service account.'
            region:
                type: str
                description: 'AWS region name.'
            resource-group:
                type: str
                description: 'Azure resource group.'
            resource-url:
                type: str
                description: 'Azure Stack resource URL.'
            rest-interface:
                type: str
                description: 'Interface name for REST service to listen on.'
                choices:
                    - 'mgmt'
                    - 'sync'
            rest-password:
                description: no description
                type: str
            rest-sport:
                type: int
                description: 'REST service access port (1 - 65535).'
            rest-ssl:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            route:
                description: no description
                type: list
                suboptions:
                    name:
                        type: str
                        description: 'Route name.'
            route-table:
                description: no description
                type: list
                suboptions:
                    name:
                        type: str
                        description: 'Route table name.'
                    route:
                        description: no description
                        type: list
                        suboptions:
                            name:
                                type: str
                                description: 'Route name.'
                            next-hop:
                                type: str
                                description: 'Next hop address.'
            secret-key:
                description: no description
                type: str
            server:
                type: str
                description: 'Server address of the remote SDN connector.'
            server-port:
                type: int
                description: 'Port number of the remote SDN connector.'
            service-account:
                type: str
                description: 'GCP service account email.'
            status:
                type: str
                description: 'Enable/disable connection to the remote SDN connector.'
                choices:
                    - 'disable'
                    - 'enable'
            subscription-id:
                type: str
                description: 'Azure subscription ID.'
            tenant-id:
                type: str
                description: 'Tenant ID (directory ID).'
            type:
                type: str
                description: 'Type of SDN connector.'
                choices:
                    - 'aci'
                    - 'aws'
                    - 'nsx'
                    - 'nuage'
                    - 'azure'
                    - 'gcp'
                    - 'oci'
                    - 'openstack'
                    - 'kubernetes'
                    - 'vmware'
                    - 'acs'
                    - 'alicloud'
            update-interval:
                type: int
                description: 'Dynamic object update interval (0 - 3600 sec, 0 means disabled, default = 60).'
            use-metadata-iam:
                type: str
                description: 'Enable/disable using IAM role from metadata to call API.'
                choices:
                    - 'disable'
                    - 'enable'
            user-id:
                type: str
                description: 'User ID.'
            username:
                type: str
                description: 'Username of the remote SDN connector as login credentials.'
            vmx-image-url:
                type: str
                description: 'URL of web-hosted VMX image.'
            vmx-service-name:
                type: str
                description: 'VMX Service name.'
            vpc-id:
                type: str
                description: 'AWS VPC ID.'

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
    - name: Configure connection to SDN Connector.
      fmgr_system_sdnconnector:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         system_sdnconnector:
            _local_cert: <value of string>
            access-key: <value of string>
            azure-region: <value in [global, china, germany, ...]>
            client-id: <value of string>
            client-secret: <value of string>
            compartment-id: <value of string>
            external-ip:
              -
                  name: <value of string>
            gcp-project: <value of string>
            key-passwd: <value of string>
            login-endpoint: <value of string>
            name: <value of string>
            nic:
              -
                  ip:
                    -
                        name: <value of string>
                        public-ip: <value of string>
                  name: <value of string>
            nsx-cert-fingerprint: <value of string>
            oci-cert: <value of string>
            oci-fingerprint: <value of string>
            oci-region: <value in [phoenix, ashburn, frankfurt, ...]>
            password: <value of string>
            private-key: <value of string>
            region: <value of string>
            resource-group: <value of string>
            resource-url: <value of string>
            rest-interface: <value in [mgmt, sync]>
            rest-password: <value of string>
            rest-sport: <value of integer>
            rest-ssl: <value in [disable, enable]>
            route:
              -
                  name: <value of string>
            route-table:
              -
                  name: <value of string>
                  route:
                    -
                        name: <value of string>
                        next-hop: <value of string>
            secret-key: <value of string>
            server: <value of string>
            server-port: <value of integer>
            service-account: <value of string>
            status: <value in [disable, enable]>
            subscription-id: <value of string>
            tenant-id: <value of string>
            type: <value in [aci, aws, nsx, ...]>
            update-interval: <value of integer>
            use-metadata-iam: <value in [disable, enable]>
            user-id: <value of string>
            username: <value of string>
            vmx-image-url: <value of string>
            vmx-service-name: <value of string>
            vpc-id: <value of string>

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
        '/pm/config/adom/{adom}/obj/system/sdn-connector',
        '/pm/config/global/obj/system/sdn-connector'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}',
        '/pm/config/global/obj/system/sdn-connector/{sdn-connector}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
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
        'system_sdnconnector': {
            'required': False,
            'type': 'dict',
            'options': {
                '_local_cert': {
                    'required': False,
                    'type': 'str'
                },
                'access-key': {
                    'required': False,
                    'type': 'str'
                },
                'azure-region': {
                    'required': False,
                    'choices': [
                        'global',
                        'china',
                        'germany',
                        'usgov',
                        'local'
                    ],
                    'type': 'str'
                },
                'client-id': {
                    'required': False,
                    'type': 'str'
                },
                'client-secret': {
                    'required': False,
                    'type': 'str'
                },
                'compartment-id': {
                    'required': False,
                    'type': 'str'
                },
                'external-ip': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'name': {
                            'required': False,
                            'type': 'str'
                        }
                    }
                },
                'gcp-project': {
                    'required': False,
                    'type': 'str'
                },
                'key-passwd': {
                    'required': False,
                    'type': 'str'
                },
                'login-endpoint': {
                    'required': False,
                    'type': 'str'
                },
                'name': {
                    'required': True,
                    'type': 'str'
                },
                'nic': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'ip': {
                            'required': False,
                            'type': 'list',
                            'options': {
                                'name': {
                                    'required': False,
                                    'type': 'str'
                                },
                                'public-ip': {
                                    'required': False,
                                    'type': 'str'
                                }
                            }
                        },
                        'name': {
                            'required': False,
                            'type': 'str'
                        }
                    }
                },
                'nsx-cert-fingerprint': {
                    'required': False,
                    'type': 'str'
                },
                'oci-cert': {
                    'required': False,
                    'type': 'str'
                },
                'oci-fingerprint': {
                    'required': False,
                    'type': 'str'
                },
                'oci-region': {
                    'required': False,
                    'choices': [
                        'phoenix',
                        'ashburn',
                        'frankfurt',
                        'london',
                        'toronto'
                    ],
                    'type': 'str'
                },
                'password': {
                    'required': False,
                    'type': 'str'
                },
                'private-key': {
                    'required': False,
                    'type': 'str'
                },
                'region': {
                    'required': False,
                    'type': 'str'
                },
                'resource-group': {
                    'required': False,
                    'type': 'str'
                },
                'resource-url': {
                    'required': False,
                    'type': 'str'
                },
                'rest-interface': {
                    'required': False,
                    'choices': [
                        'mgmt',
                        'sync'
                    ],
                    'type': 'str'
                },
                'rest-password': {
                    'required': False,
                    'type': 'str'
                },
                'rest-sport': {
                    'required': False,
                    'type': 'int'
                },
                'rest-ssl': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'route': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'name': {
                            'required': False,
                            'type': 'str'
                        }
                    }
                },
                'route-table': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'name': {
                            'required': False,
                            'type': 'str'
                        },
                        'route': {
                            'required': False,
                            'type': 'list',
                            'options': {
                                'name': {
                                    'required': False,
                                    'type': 'str'
                                },
                                'next-hop': {
                                    'required': False,
                                    'type': 'str'
                                }
                            }
                        }
                    }
                },
                'secret-key': {
                    'required': False,
                    'type': 'str'
                },
                'server': {
                    'required': False,
                    'type': 'str'
                },
                'server-port': {
                    'required': False,
                    'type': 'int'
                },
                'service-account': {
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
                'subscription-id': {
                    'required': False,
                    'type': 'str'
                },
                'tenant-id': {
                    'required': False,
                    'type': 'str'
                },
                'type': {
                    'required': False,
                    'choices': [
                        'aci',
                        'aws',
                        'nsx',
                        'nuage',
                        'azure',
                        'gcp',
                        'oci',
                        'openstack',
                        'kubernetes',
                        'vmware',
                        'acs',
                        'alicloud'
                    ],
                    'type': 'str'
                },
                'update-interval': {
                    'required': False,
                    'type': 'int'
                },
                'use-metadata-iam': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'user-id': {
                    'required': False,
                    'type': 'str'
                },
                'username': {
                    'required': False,
                    'type': 'str'
                },
                'vmx-image-url': {
                    'required': False,
                    'type': 'str'
                },
                'vmx-service-name': {
                    'required': False,
                    'type': 'str'
                },
                'vpc-id': {
                    'required': False,
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_sdnconnector'),
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
