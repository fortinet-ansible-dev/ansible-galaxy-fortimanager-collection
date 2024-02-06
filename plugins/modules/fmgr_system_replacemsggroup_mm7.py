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
module: fmgr_system_replacemsggroup_mm7
short_description: Replacement message table entries.
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
    replacemsg-group:
        description: Deprecated, please use "replacemsg_group"
        type: str
    replacemsg_group:
        description: The parameter (replacemsg-group) in requested url.
        type: str
    system_replacemsggroup_mm7:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            add-smil:
                type: str
                description: Deprecated, please rename it to add_smil. Add message encapsulation
                choices:
                    - 'disable'
                    - 'enable'
            addr-type:
                type: str
                description: Deprecated, please rename it to addr_type. From address type
                choices:
                    - 'rfc2822-addr'
                    - 'number'
                    - 'short-code'
            allow-content-adaptation:
                type: str
                description: Deprecated, please rename it to allow_content_adaptation. Allow content adaptations
                choices:
                    - 'disable'
                    - 'enable'
            charset:
                type: str
                description: Character encoding used for replacement message
                choices:
                    - 'us-ascii'
                    - 'utf-8'
            class:
                type: str
                description: Message class
                choices:
                    - 'personal'
                    - 'advertisement'
                    - 'informational'
                    - 'auto'
                    - 'not-included'
            format:
                type: str
                description: Format flag.
                choices:
                    - 'none'
                    - 'text'
                    - 'html'
                    - 'wml'
            from:
                type: str
                description: From address
            from-sender:
                type: str
                description: Deprecated, please rename it to from_sender. Notification message sent from recipient
                choices:
                    - 'disable'
                    - 'enable'
            header:
                type: str
                description: Header flag.
                choices:
                    - 'none'
                    - 'http'
                    - '8bit'
            image:
                type: str
                description: Message string.
            message:
                type: str
                description: Deprecated, please rename it to fmgr_message. Message text
            msg-type:
                type: str
                description: Deprecated, please rename it to msg_type. Message type.
                required: true
            priority:
                type: str
                description: Message priority
                choices:
                    - 'low'
                    - 'normal'
                    - 'high'
                    - 'not-included'
            rsp-status:
                type: str
                description: Deprecated, please rename it to rsp_status. Response status
                choices:
                    - 'success'
                    - 'partial-success'
                    - 'client-err'
                    - 'oper-restrict'
                    - 'addr-err'
                    - 'addr-not-found'
                    - 'content-refused'
                    - 'msg-id-not-found'
                    - 'link-id-not-found'
                    - 'msg-fmt-corrupt'
                    - 'app-id-not-found'
                    - 'repl-app-id-not-found'
                    - 'srv-err'
                    - 'not-possible'
                    - 'msg-rejected'
                    - 'multiple-addr-not-supp'
                    - 'app-addr-not-supp'
                    - 'gen-service-err'
                    - 'improper-ident'
                    - 'unsupp-ver'
                    - 'unsupp-oper'
                    - 'validation-err'
                    - 'service-err'
                    - 'service-unavail'
                    - 'service-denied'
                    - 'app-denied'
            smil-part:
                type: str
                description: Deprecated, please rename it to smil_part. Message encapsulation text
            subject:
                type: str
                description: Subject text string
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
    - name: Replacement message table entries.
      fortinet.fortimanager.fmgr_system_replacemsggroup_mm7:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        replacemsg_group: <your own value>
        state: present # <value in [present, absent]>
        system_replacemsggroup_mm7:
          add_smil: <value in [disable, enable]>
          addr_type: <value in [rfc2822-addr, number, short-code]>
          allow_content_adaptation: <value in [disable, enable]>
          charset: <value in [us-ascii, utf-8]>
          class: <value in [personal, advertisement, informational, ...]>
          format: <value in [none, text, html, ...]>
          from: <string>
          from_sender: <value in [disable, enable]>
          header: <value in [none, http, 8bit]>
          image: <string>
          fmgr_message: <string>
          msg_type: <string>
          priority: <value in [low, normal, high, ...]>
          rsp_status: <value in [success, partial-success, client-err, ...]>
          smil_part: <string>
          subject: <string>
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
        '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm7',
        '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm7'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm7/{mm7}',
        '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm7/{mm7}'
    ]

    url_params = ['adom', 'replacemsg-group']
    module_primary_key = 'msg-type'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'replacemsg-group': {'type': 'str', 'api_name': 'replacemsg_group'},
        'replacemsg_group': {'type': 'str'},
        'system_replacemsggroup_mm7': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'add-smil': {'choices': ['disable', 'enable'], 'type': 'str'},
                'addr-type': {'choices': ['rfc2822-addr', 'number', 'short-code'], 'type': 'str'},
                'allow-content-adaptation': {'choices': ['disable', 'enable'], 'type': 'str'},
                'charset': {'choices': ['us-ascii', 'utf-8'], 'type': 'str'},
                'class': {'choices': ['personal', 'advertisement', 'informational', 'auto', 'not-included'], 'type': 'str'},
                'format': {'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                'from': {'type': 'str'},
                'from-sender': {'choices': ['disable', 'enable'], 'type': 'str'},
                'header': {'choices': ['none', 'http', '8bit'], 'type': 'str'},
                'image': {'type': 'str'},
                'message': {'type': 'str'},
                'msg-type': {'required': True, 'type': 'str'},
                'priority': {'choices': ['low', 'normal', 'high', 'not-included'], 'type': 'str'},
                'rsp-status': {
                    'choices': [
                        'success', 'partial-success', 'client-err', 'oper-restrict', 'addr-err', 'addr-not-found', 'content-refused', 'msg-id-not-found',
                        'link-id-not-found', 'msg-fmt-corrupt', 'app-id-not-found', 'repl-app-id-not-found', 'srv-err', 'not-possible', 'msg-rejected',
                        'multiple-addr-not-supp', 'app-addr-not-supp', 'gen-service-err', 'improper-ident', 'unsupp-ver', 'unsupp-oper',
                        'validation-err', 'service-err', 'service-unavail', 'service-denied', 'app-denied'
                    ],
                    'type': 'str'
                },
                'smil-part': {'type': 'str'},
                'subject': {'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_replacemsggroup_mm7'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    connection.set_option('access_token', module.params.get('access_token', None))
    connection.set_option('enable_log', module.params.get('enable_log', False))
    connection.set_option('forticloud_access_token', module.params.get('forticloud_access_token', None))
    fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_curd(argument_specs=module_arg_spec)

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
