#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2023 Fortinet, Inc.
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
module: fmgr_system_csf
short_description: Add this device to a Security Fabric or set up a new Security Fabric on this device.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.3.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
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
    access_token:
        description: The token to access FortiManager without using username and password.
        required: false
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        required: false
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        required: false
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        required: false
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        required: false
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        required: false
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        required: false
        elements: int
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        required: false
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        required: false
        type: int
        default: 300
    system_csf:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            accept-auth-by-cert:
                type: str
                description:
                    - Accept connections with unknown certificates and ask admin for approval.
                    - disable - Do not accept SSL connections with unknown certificates.
                    - enable - Accept SSL connections without automatic certificate verification.
                choices:
                    - 'disable'
                    - 'enable'
            authorization-request-type:
                type: str
                description:
                    - Authorization request type.
                    - certificate - Request verification by certificate.
                    - serial - Request verification by serial number.
                choices:
                    - 'certificate'
                    - 'serial'
            certificate:
                type: str
                description: Certificate.
            configuration-sync:
                type: str
                description:
                    - Configuration sync mode.
                    - default - Synchronize configuration for IPAM, FortiAnalyzer, FortiSandbox, and Central Management to root node.
                    - local - Do not synchronize configuration with root node.
                choices:
                    - 'default'
                    - 'local'
            downstream-access:
                type: str
                description:
                    - Enable/disable downstream device access to this device&apos;s configuration and data.
                    - disable - Disable downstream device access to this device&apos;s configuration and data.
                    - enable - Enable downstream device access to this device&apos;s configuration and data.
                choices:
                    - 'disable'
                    - 'enable'
            downstream-accprofile:
                type: str
                description: Default access profile for requests from downstream devices.
            fabric-connector:
                type: list
                elements: dict
                description: no description
                suboptions:
                    accprofile:
                        type: str
                        description: Override access profile.
                    configuration-write-access:
                        type: str
                        description:
                            - Enable/disable downstream device write access to configuration.
                            - disable - Disable downstream device write access to configuration.
                            - enable - Enable downstream device write access to configuration.
                        choices:
                            - 'disable'
                            - 'enable'
                    serial:
                        type: str
                        description: Serial.
            fabric-object-unification:
                type: str
                description:
                    - Fabric CMDB Object Unification.
                    - local - Global CMDB objects will not be synchronized to and from this device.
                    - default - Global CMDB objects will be synchronized in Security Fabric.
                choices:
                    - 'local'
                    - 'default'
            fabric-workers:
                type: int
                description: Number of worker processes for Security Fabric daemon.
            file-mgmt:
                type: str
                description:
                    - Enable/disable Security Fabric daemon file management.
                    - disable - Disable daemon file management.
                    - enable - Enable daemon file management.
                choices:
                    - 'disable'
                    - 'enable'
            file-quota:
                type: int
                description: Maximum amount of memory that can be used by the daemon files
            file-quota-warning:
                type: int
                description: Warn when the set percentage of quota has been used.
            fixed-key:
                type: list
                elements: str
                description: no description
            forticloud-account-enforcement:
                type: str
                description:
                    - Fabric FortiCloud account unification.
                    - disable - Disable FortiCloud accound ID matching for Security Fabric.
                    - enable - Enable FortiCloud account ID matching for Security Fabric.
                choices:
                    - 'disable'
                    - 'enable'
            group-name:
                type: str
                description: Security Fabric group name.
            group-password:
                type: list
                elements: str
                description: no description
            log-unification:
                type: str
                description:
                    - Enable/disable broadcast of discovery messages for log unification.
                    - disable - Disable broadcast of discovery messages for log unification.
                    - enable - Enable broadcast of discovery messages for log unification.
                choices:
                    - 'disable'
                    - 'enable'
            saml-configuration-sync:
                type: str
                description:
                    - SAML setting configuration synchronization.
                    - local - Do not apply SAML configuration generated by root.
                    - default - SAML setting for fabric members is created by fabric root.
                choices:
                    - 'local'
                    - 'default'
            status:
                type: str
                description:
                    - Enable/disable Security Fabric.
                    - disable - Disable Security Fabric.
                    - enable - Enable Security Fabric.
                choices:
                    - 'disable'
                    - 'enable'
            trusted-list:
                type: list
                elements: dict
                description: no description
                suboptions:
                    action:
                        type: str
                        description:
                            - Security fabric authorization action.
                            - accept - Accept authorization request.
                            - deny - Deny authorization request.
                        choices:
                            - 'accept'
                            - 'deny'
                    authorization-type:
                        type: str
                        description:
                            - Authorization type.
                            - serial - Verify downstream by serial number.
                            - certificate - Verify downstream by certificate.
                        choices:
                            - 'serial'
                            - 'certificate'
                    certificate:
                        type: str
                        description: Certificate.
                    downstream-authorization:
                        type: str
                        description:
                            - Trust authorizations by this node&apos;s administrator.
                            - disable - Disable downstream authorization.
                            - enable - Enable downstream authorization.
                        choices:
                            - 'disable'
                            - 'enable'
                    ha-members:
                        type: str
                        description: HA members.
                    index:
                        type: int
                        description: Index of the downstream in tree.
                    name:
                        type: str
                        description: Name.
                    serial:
                        type: str
                        description: Serial.
            upstream:
                type: str
                description: IP/FQDN of the FortiGate upstream from this FortiGate in the Security Fabric.
            upstream-port:
                type: int
                description: The port number to use to communicate with the FortiGate upstream from this FortiGate in the Security Fabric

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
    - name: Add this device to a Security Fabric or set up a new Security Fabric on this device.
      fmgr_system_csf:
        bypass_validation: False
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        rc_succeeded: [0, -2, -3, ...]
        rc_failed: [-2, -3, ...]
        system_csf:
          accept-auth-by-cert: <value in [disable, enable]>
          authorization-request-type: <value in [certificate, serial]>
          certificate: <string>
          configuration-sync: <value in [default, local]>
          downstream-access: <value in [disable, enable]>
          downstream-accprofile: <string>
          fabric-connector:
            -
              accprofile: <string>
              configuration-write-access: <value in [disable, enable]>
              serial: <string>
          fabric-object-unification: <value in [local, default]>
          fabric-workers: <integer>
          file-mgmt: <value in [disable, enable]>
          file-quota: <integer>
          file-quota-warning: <integer>
          fixed-key: <list or string>
          forticloud-account-enforcement: <value in [disable, enable]>
          group-name: <string>
          group-password: <list or string>
          log-unification: <value in [disable, enable]>
          saml-configuration-sync: <value in [local, default]>
          status: <value in [disable, enable]>
          trusted-list:
            -
              action: <value in [accept, deny]>
              authorization-type: <value in [serial, certificate]>
              certificate: <string>
              downstream-authorization: <value in [disable, enable]>
              ha-members: <string>
              index: <integer>
              name: <string>
              serial: <string>
          upstream: <string>
          upstream-port: <integer>

'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_galaxy_version
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_parameter_bypass


def main():
    jrpc_urls = [
        '/cli/global/system/csf'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/csf/{csf}'
    ]

    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'access_token': {
            'type': 'str',
            'required': False,
            'no_log': True
        },
        'bypass_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
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
        'rc_succeeded': {
            'required': False,
            'type': 'list',
            'elements': 'int'
        },
        'rc_failed': {
            'required': False,
            'type': 'list',
            'elements': 'int'
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
        'system_csf': {
            'required': False,
            'type': 'dict',
            'revision': {
                '7.4.1': True
            },
            'options': {
                'accept-auth-by-cert': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'authorization-request-type': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'choices': [
                        'certificate',
                        'serial'
                    ],
                    'type': 'str'
                },
                'certificate': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'configuration-sync': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'choices': [
                        'default',
                        'local'
                    ],
                    'type': 'str'
                },
                'downstream-access': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'downstream-accprofile': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'fabric-connector': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'type': 'list',
                    'options': {
                        'accprofile': {
                            'required': False,
                            'revision': {
                                '7.4.1': True
                            },
                            'type': 'str'
                        },
                        'configuration-write-access': {
                            'required': False,
                            'revision': {
                                '7.4.1': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'serial': {
                            'required': False,
                            'revision': {
                                '7.4.1': True
                            },
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'fabric-object-unification': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'choices': [
                        'local',
                        'default'
                    ],
                    'type': 'str'
                },
                'fabric-workers': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'type': 'int'
                },
                'file-mgmt': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'file-quota': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'type': 'int'
                },
                'file-quota-warning': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'type': 'int'
                },
                'fixed-key': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'no_log': True,
                    'type': 'list',
                    'elements': 'str'
                },
                'forticloud-account-enforcement': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'group-name': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'group-password': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'no_log': True,
                    'type': 'list',
                    'elements': 'str'
                },
                'log-unification': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'saml-configuration-sync': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'choices': [
                        'local',
                        'default'
                    ],
                    'type': 'str'
                },
                'status': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'trusted-list': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'type': 'list',
                    'options': {
                        'action': {
                            'required': False,
                            'revision': {
                                '7.4.1': True
                            },
                            'choices': [
                                'accept',
                                'deny'
                            ],
                            'type': 'str'
                        },
                        'authorization-type': {
                            'required': False,
                            'revision': {
                                '7.4.1': True
                            },
                            'choices': [
                                'serial',
                                'certificate'
                            ],
                            'type': 'str'
                        },
                        'certificate': {
                            'required': False,
                            'revision': {
                                '7.4.1': True
                            },
                            'type': 'str'
                        },
                        'downstream-authorization': {
                            'required': False,
                            'revision': {
                                '7.4.1': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'ha-members': {
                            'required': False,
                            'revision': {
                                '7.4.1': True
                            },
                            'type': 'str'
                        },
                        'index': {
                            'required': False,
                            'revision': {
                                '7.4.1': True
                            },
                            'type': 'int'
                        },
                        'name': {
                            'required': False,
                            'revision': {
                                '7.4.1': True
                            },
                            'type': 'str'
                        },
                        'serial': {
                            'required': False,
                            'revision': {
                                '7.4.1': True
                            },
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'upstream': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'upstream-port': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'type': 'int'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_csf'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('access_token', module.params['access_token'] if 'access_token' in module.params else None)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        connection.set_option('forticloud_access_token',
                              module.params['forticloud_access_token'] if 'forticloud_access_token' in module.params else None)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_partial_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
