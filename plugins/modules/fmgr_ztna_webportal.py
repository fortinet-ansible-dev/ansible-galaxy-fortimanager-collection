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
module: fmgr_ztna_webportal
short_description: Configure ztna web-portal.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.
version_added: "2.12.0"
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
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
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
    ztna_webportal:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auth_portal:
                aliases: ['auth-portal']
                type: str
                description: Enable/disable authentication portal.
                choices:
                    - 'disable'
                    - 'enable'
            auth_rule:
                aliases: ['auth-rule']
                type: list
                elements: str
                description: Authentication Rule.
            auth_virtual_host:
                aliases: ['auth-virtual-host']
                type: list
                elements: str
                description: Virtual host for authentication portal.
            bookmarks:
                type: list
                elements: str
                description: Bookmarks.
            clipboard:
                type: str
                description: Enable to support RDP/VPC clipboard functionality.
                choices:
                    - 'disable'
                    - 'enable'
            cookie_age:
                aliases: ['cookie-age']
                type: int
                description: Time in minutes that client web browsers should keep a cookie.
            customize_forticlient_download_url:
                aliases: ['customize-forticlient-download-url']
                type: str
                description: Enable support of customized download URL for FortiClient.
                choices:
                    - 'disable'
                    - 'enable'
            decrypted_traffic_mirror:
                aliases: ['decrypted-traffic-mirror']
                type: list
                elements: str
                description: Decrypted traffic mirror.
            default_window_height:
                aliases: ['default-window-height']
                type: int
                description: Screen height
            default_window_width:
                aliases: ['default-window-width']
                type: int
                description: Screen width
            display_bookmark:
                aliases: ['display-bookmark']
                type: str
                description: Enable to display the web portal bookmark widget.
                choices:
                    - 'disable'
                    - 'enable'
            display_history:
                aliases: ['display-history']
                type: str
                description: Enable to display the web portal user login history widget.
                choices:
                    - 'disable'
                    - 'enable'
            display_status:
                aliases: ['display-status']
                type: str
                description: Enable to display the web portal status widget.
                choices:
                    - 'disable'
                    - 'enable'
            focus_bookmark:
                aliases: ['focus-bookmark']
                type: str
                description: Enable to prioritize the placement of the bookmark section over the quick-connection section in the ztna web-portal.
                choices:
                    - 'disable'
                    - 'enable'
            forticlient_download:
                aliases: ['forticlient-download']
                type: str
                description: Enable/disable download option for FortiClient.
                choices:
                    - 'disable'
                    - 'enable'
            forticlient_download_method:
                aliases: ['forticlient-download-method']
                type: str
                description: Forticlient download method.
                choices:
                    - 'direct'
                    - 'ssl-vpn'
            heading:
                type: str
                description: Web portal heading message.
            host:
                type: list
                elements: str
                description: Virtual or real host name.
            log_blocked_traffic:
                aliases: ['log-blocked-traffic']
                type: str
                description: Enable/disable logging of blocked traffic.
                choices:
                    - 'disable'
                    - 'enable'
            macos_forticlient_download_url:
                aliases: ['macos-forticlient-download-url']
                type: str
                description: Download URL for Mac FortiClient.
            name:
                type: str
                description: ZTNA proxy name.
                required: true
            policy_auth_sso:
                aliases: ['policy-auth-sso']
                type: str
                description: Enable policy sso authentication.
                choices:
                    - 'disable'
                    - 'enable'
            theme:
                type: str
                description: Web portal color scheme.
                choices:
                    - 'melongene'
                    - 'mariner'
                    - 'neutrino'
                    - 'jade'
                    - 'graphite'
                    - 'dark-matter'
                    - 'onyx'
                    - 'eclipse'
                    - 'jet-stream'
                    - 'security-fabric'
            vip:
                type: list
                elements: str
                description: Virtual IP name.
            windows_forticlient_download_url:
                aliases: ['windows-forticlient-download-url']
                type: str
                description: Download URL for Windows FortiClient.
            vip6:
                type: list
                elements: str
                description: Virtual IPv6 name.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure ztna web-portal.
      fortinet.fortimanager.fmgr_ztna_webportal:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        ztna_webportal:
          name: "your value" # Required variable, string
          # auth_portal: <value in [disable, enable]>
          # auth_rule: <list or string>
          # auth_virtual_host: <list or string>
          # bookmarks: <list or string>
          # clipboard: <value in [disable, enable]>
          # cookie_age: <integer>
          # customize_forticlient_download_url: <value in [disable, enable]>
          # decrypted_traffic_mirror: <list or string>
          # default_window_height: <integer>
          # default_window_width: <integer>
          # display_bookmark: <value in [disable, enable]>
          # display_history: <value in [disable, enable]>
          # display_status: <value in [disable, enable]>
          # focus_bookmark: <value in [disable, enable]>
          # forticlient_download: <value in [disable, enable]>
          # forticlient_download_method: <value in [direct, ssl-vpn]>
          # heading: <string>
          # host: <list or string>
          # log_blocked_traffic: <value in [disable, enable]>
          # macos_forticlient_download_url: <string>
          # policy_auth_sso: <value in [disable, enable]>
          # theme: <value in [melongene, mariner, neutrino, ...]>
          # vip: <list or string>
          # windows_forticlient_download_url: <string>
          # vip6: <list or string>
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
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager, check_galaxy_version, check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    urls_list = [
        '/pm/config/adom/{adom}/obj/ztna/web-portal',
        '/pm/config/global/obj/ztna/web-portal'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'ztna_webportal': {
            'type': 'dict',
            'v_range': [['7.6.4', '']],
            'options': {
                'auth-portal': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-rule': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'auth-virtual-host': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'bookmarks': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'clipboard': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cookie-age': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'customize-forticlient-download-url': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'decrypted-traffic-mirror': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'default-window-height': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'default-window-width': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'display-bookmark': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'display-history': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'display-status': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'focus-bookmark': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'forticlient-download': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'forticlient-download-method': {'v_range': [['7.6.4', '']], 'choices': ['direct', 'ssl-vpn'], 'type': 'str'},
                'heading': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'host': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'log-blocked-traffic': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'macos-forticlient-download-url': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'name': {'v_range': [['7.6.4', '']], 'required': True, 'type': 'str'},
                'policy-auth-sso': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'theme': {
                    'v_range': [['7.6.4', '']],
                    'choices': ['melongene', 'mariner', 'neutrino', 'jade', 'graphite', 'dark-matter', 'onyx', 'eclipse', 'jet-stream', 'security-fabric'],
                    'type': 'str'
                },
                'vip': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'windows-forticlient-download-url': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'vip6': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'ztna_webportal'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
