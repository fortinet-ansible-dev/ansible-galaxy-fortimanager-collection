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
module: fmgr_devprof_system_global
short_description: Configure global attributes.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
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
    devprof:
        description: The parameter (devprof) in requested url.
        type: str
        required: true
    devprof_system_global:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            admin-https-redirect:
                type: str
                description: Deprecated, please rename it to admin_https_redirect. Enable/disable redirection of HTTP administration access to HTTPS.
                choices:
                    - 'disable'
                    - 'enable'
            admin-port:
                type: int
                description: Deprecated, please rename it to admin_port. Administrative access port for HTTP.
            admin-scp:
                type: str
                description: Deprecated, please rename it to admin_scp. Enable/disable using SCP to download the system configuration.
                choices:
                    - 'disable'
                    - 'enable'
            admin-sport:
                type: int
                description: Deprecated, please rename it to admin_sport. Administrative access port for HTTPS.
            admin-ssh-port:
                type: int
                description: Deprecated, please rename it to admin_ssh_port. Administrative access port for SSH.
            admin-ssh-v1:
                type: str
                description: Deprecated, please rename it to admin_ssh_v1. Enable/disable SSH v1 compatibility.
                choices:
                    - 'disable'
                    - 'enable'
            admin-telnet-port:
                type: int
                description: Deprecated, please rename it to admin_telnet_port. Administrative access port for TELNET.
            admintimeout:
                type: int
                description: Number of minutes before an idle administrator session times out
            gui-ipv6:
                type: str
                description: Deprecated, please rename it to gui_ipv6. Enable/disable IPv6 settings on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui-lines-per-page:
                type: int
                description: Deprecated, please rename it to gui_lines_per_page. Number of lines to display per page for web administration.
            gui-theme:
                type: str
                description: Deprecated, please rename it to gui_theme. Color scheme for the administration GUI.
                choices:
                    - 'blue'
                    - 'green'
                    - 'melongene'
                    - 'red'
                    - 'mariner'
                    - 'neutrino'
                    - 'jade'
                    - 'graphite'
                    - 'dark-matter'
                    - 'onyx'
                    - 'eclipse'
                    - 'retro'
                    - 'fpx'
                    - 'jet-stream'
                    - 'security-fabric'
            language:
                type: str
                description: GUI display language.
                choices:
                    - 'english'
                    - 'simch'
                    - 'japanese'
                    - 'korean'
                    - 'spanish'
                    - 'trach'
                    - 'french'
                    - 'portuguese'
            switch-controller:
                type: str
                description: Deprecated, please rename it to switch_controller. Enable/disable switch controller feature.
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
    - name: Configure global attributes.
      fortinet.fortimanager.fmgr_devprof_system_global:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        devprof: <your own value>
        devprof_system_global:
          admin_https_redirect: <value in [disable, enable]>
          admin_port: <integer>
          admin_scp: <value in [disable, enable]>
          admin_sport: <integer>
          admin_ssh_port: <integer>
          admin_ssh_v1: <value in [disable, enable]>
          admin_telnet_port: <integer>
          admintimeout: <integer>
          gui_ipv6: <value in [disable, enable]>
          gui_lines_per_page: <integer>
          gui_theme: <value in [blue, green, melongene, ...]>
          language: <value in [english, simch, japanese, ...]>
          switch_controller: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/devprof/{devprof}/system/global'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/devprof/{devprof}/system/global/{global}'
    ]

    url_params = ['adom', 'devprof']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'devprof': {'required': True, 'type': 'str'},
        'devprof_system_global': {
            'type': 'dict',
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
            'options': {
                'admin-https-redirect': {
                    'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'admin-port': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                'admin-scp': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'admin-sport': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                'admin-ssh-port': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                'admin-ssh-v1': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'admin-telnet-port': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '7.4.1']], 'type': 'int'},
                'admintimeout': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                'gui-ipv6': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-lines-per-page': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                'gui-theme': {
                    'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
                    'choices': [
                        'blue', 'green', 'melongene', 'red', 'mariner', 'neutrino', 'jade', 'graphite', 'dark-matter', 'onyx', 'eclipse', 'retro', 'fpx',
                        'jet-stream', 'security-fabric'
                    ],
                    'type': 'str'
                },
                'language': {
                    'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
                    'choices': ['english', 'simch', 'japanese', 'korean', 'spanish', 'trach', 'french', 'portuguese'],
                    'type': 'str'
                },
                'switch-controller': {
                    'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '7.2.0']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                }
            }

        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'devprof_system_global'),
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
