#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2024 Fortinet, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_firewall_address6template_subnetsegment
short_description: IPv6 subnet segments.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Starting in version 2.4.0, all input arguments are named using the underscore naming convention (snake_case).
      Please change the arguments such as "var-name" to "var_name".
      Old argument names are still available yet you will receive deprecation warnings.
      You can ignore this warning by setting deprecation_warnings=False in ansible.cfg.
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    address6-template:
        description: Deprecated, please use "address6_template"
        type: str
    address6_template:
        description: The parameter (address6-template) in requested url.
        type: str
    firewall_address6template_subnetsegment:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            bits:
                type: int
                description: Number of bits.
            exclusive:
                type: str
                description: Enable/disable exclusive value.
                choices:
                    - 'disable'
                    - 'enable'
            id:
                type: int
                description: Subnet segment ID.
                required: true
            name:
                type: str
                description: Subnet segment name.
            values:
                type: list
                elements: dict
                description: Values.
                suboptions:
                    name:
                        type: str
                        description: Subnet segment value name.
                    value:
                        type: str
                        description: Subnet segment value.
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: IPv6 subnet segments.
      fortinet.fortimanager.fmgr_firewall_address6template_subnetsegment:
        bypass_validation: false
        adom: ansible
        address6-template: "ansible-name" # name
        state: present
        firewall_address6template_subnetsegment:
          bits: 2
          exclusive: enable
          id: 1
          name: "ansible-name-sub"
          values:
            - name: "ansible-name-val"
              value: "ansible"

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the subnet segments in the IPv6 address template
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_address6template_subnetsegment"
          params:
            adom: "ansible"
            address6-template: "ansible-name" # name
            subnet-segment: "your_value"
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
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/address6-template/{address6-template}/subnet-segment',
        '/pm/config/global/obj/firewall/address6-template/{address6-template}/subnet-segment'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}',
        '/pm/config/global/obj/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}'
    ]

    url_params = ['adom', 'address6-template']
    module_primary_key = 'id'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'address6-template': {'type': 'str', 'api_name': 'address6_template'},
        'address6_template': {'type': 'str'},
        'firewall_address6template_subnetsegment': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'bits': {'type': 'int'},
                'exclusive': {'choices': ['disable', 'enable'], 'type': 'str'},
                'id': {'required': True, 'type': 'int'},
                'name': {'type': 'str'},
                'values': {'type': 'list', 'options': {'name': {'type': 'str'}, 'value': {'type': 'str'}}, 'elements': 'dict'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_address6template_subnetsegment'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_curd(argument_specs=module_arg_spec)

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
