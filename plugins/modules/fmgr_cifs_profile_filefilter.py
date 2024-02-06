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
module: fmgr_cifs_profile_filefilter
short_description: File filter.
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
    profile:
        description: The parameter (profile) in requested url.
        type: str
        required: true
    cifs_profile_filefilter:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            entries:
                type: list
                elements: dict
                description: No description.
                suboptions:
                    action:
                        type: str
                        description: Action taken for matched file.
                        choices:
                            - 'block'
                            - 'log'
                    comment:
                        type: str
                        description: Comment.
                    direction:
                        type: str
                        description: Match files transmitted in the sessions originating or reply direction.
                        choices:
                            - 'incoming'
                            - 'outgoing'
                            - 'any'
                    file-type:
                        type: raw
                        description: (list or str) Deprecated, please rename it to file_type.
                    filter:
                        type: str
                        description: Add a file filter.
                    protocol:
                        type: list
                        elements: str
                        description: No description.
                        choices:
                            - 'cifs'
            log:
                type: str
                description: Enable/disable file filter logging.
                choices:
                    - 'disable'
                    - 'enable'
            status:
                type: str
                description: Enable/disable file filter.
                choices:
                    - 'disable'
                    - 'enable'
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
    - name: File filter.
      fortinet.fortimanager.fmgr_cifs_profile_filefilter:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        profile: <your own value>
        cifs_profile_filefilter:
          entries:
            -
              action: <value in [block, log]>
              comment: <string>
              direction: <value in [incoming, outgoing, any]>
              file_type: <list or string>
              filter: <string>
              protocol:
                - cifs
          log: <value in [disable, enable]>
          status: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/cifs/profile/{profile}/file-filter',
        '/pm/config/global/obj/cifs/profile/{profile}/file-filter'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/cifs/profile/{profile}/file-filter/{file-filter}',
        '/pm/config/global/obj/cifs/profile/{profile}/file-filter/{file-filter}'
    ]

    url_params = ['adom', 'profile']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'cifs_profile_filefilter': {
            'type': 'dict',
            'v_range': [['6.2.0', '']],
            'options': {
                'entries': {
                    'v_range': [['6.2.0', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['6.2.0', '']], 'choices': ['block', 'log'], 'type': 'str'},
                        'comment': {'v_range': [['6.2.0', '']], 'type': 'str'},
                        'direction': {'v_range': [['6.2.0', '']], 'choices': ['incoming', 'outgoing', 'any'], 'type': 'str'},
                        'file-type': {'v_range': [['6.2.0', '']], 'type': 'raw'},
                        'filter': {'v_range': [['6.2.0', '']], 'type': 'str'},
                        'protocol': {'v_range': [['6.2.0', '']], 'type': 'list', 'choices': ['cifs'], 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'log': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'cifs_profile_filefilter'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    connection.set_option('access_token', module.params.get('access_token', None))
    connection.set_option('enable_log', module.params.get('enable_log', False))
    connection.set_option('forticloud_access_token', module.params.get('forticloud_access_token', None))
    fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_partial_curd(argument_specs=module_arg_spec)

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
