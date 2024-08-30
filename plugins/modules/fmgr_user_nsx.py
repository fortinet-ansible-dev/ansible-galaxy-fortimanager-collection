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
module: fmgr_user_nsx
short_description: User nsx
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.1.0"
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
    user_nsx:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            fmgip:
                type: str
                description: Fmgip.
            fmguser:
                type: str
                description: Fmguser.
            name:
                type: str
                description: Name.
                required: true
            password:
                type: raw
                description: (list) Password.
            server:
                type: str
                description: Server.
            status:
                type: str
                description: Status.
                choices:
                    - 'disable'
                    - 'enable'
            user:
                type: str
                description: User.
            fmgpasswd:
                type: raw
                description: (list) Fmgpasswd.
            service-id:
                type: raw
                description: (list) Deprecated, please rename it to service_id. Service id.
            if-allgroup:
                type: str
                description: Deprecated, please rename it to if_allgroup. If allgroup.
                choices:
                    - 'disable'
                    - 'enable'
            service:
                type: list
                elements: dict
                description: Service.
                suboptions:
                    id:
                        type: str
                        description: Id.
                    integration:
                        type: str
                        description: Integration.
                        choices:
                            - 'east-west'
                            - 'north-south'
                    name:
                        type: str
                        description: Name.
                    ref-id:
                        type: str
                        description: Deprecated, please rename it to ref_id. Ref id.
            service-manager-id:
                type: str
                description: Deprecated, please rename it to service_manager_id. Service manager id.
            service-manager-rev:
                type: int
                description: Deprecated, please rename it to service_manager_rev. Service manager rev.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: User nsx
      fortinet.fortimanager.fmgr_user_nsx:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        user_nsx:
          fmgip: <string>
          fmguser: <string>
          name: <string>
          password: <list or string>
          server: <string>
          status: <value in [disable, enable]>
          user: <string>
          fmgpasswd: <list or string>
          service_id: <list or string>
          if_allgroup: <value in [disable, enable]>
          service:
            -
              id: <string>
              integration: <value in [east-west, north-south]>
              name: <string>
              ref_id: <string>
          service_manager_id: <string>
          service_manager_rev: <integer>
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
        '/pm/config/adom/{adom}/obj/user/nsx',
        '/pm/config/global/obj/user/nsx'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/user/nsx/{nsx}',
        '/pm/config/global/obj/user/nsx/{nsx}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'user_nsx': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'fmgip': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'fmguser': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'name': {'v_range': [['6.2.1', '']], 'required': True, 'type': 'str'},
                'password': {'v_range': [['6.2.1', '']], 'no_log': True, 'type': 'raw'},
                'server': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'status': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'user': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'fmgpasswd': {'v_range': [['6.2.2', '']], 'no_log': True, 'type': 'raw'},
                'service-id': {'v_range': [['6.2.2', '']], 'type': 'raw'},
                'if-allgroup': {'v_range': [['7.0.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'service': {
                    'v_range': [['7.0.4', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.0.4', '']], 'type': 'str'},
                        'integration': {'v_range': [['7.0.4', '']], 'choices': ['east-west', 'north-south'], 'type': 'str'},
                        'name': {'v_range': [['7.0.4', '']], 'type': 'str'},
                        'ref-id': {'v_range': [['7.0.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'service-manager-id': {'v_range': [['7.0.4', '']], 'type': 'str'},
                'service-manager-rev': {'v_range': [['7.0.4', '7.0.12'], ['7.2.1', '']], 'type': 'int'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_nsx'),
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
