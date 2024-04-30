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
module: fmgr_user_fsso_dynamicmapping
short_description: Configure Fortinet Single Sign On
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
    fsso:
        description: The parameter (fsso) in requested url.
        type: str
        required: true
    user_fsso_dynamicmapping:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            _gui_meta:
                type: str
                description: No description.
            _scope:
                type: list
                elements: dict
                description: No description.
                suboptions:
                    name:
                        type: str
                        description: No description.
                    vdom:
                        type: str
                        description: No description.
            ldap-server:
                type: str
                description: Deprecated, please rename it to ldap_server.
            password:
                type: raw
                description: (list) No description.
            password2:
                type: raw
                description: (list) No description.
            password3:
                type: raw
                description: (list) No description.
            password4:
                type: raw
                description: (list) No description.
            password5:
                type: raw
                description: (list) No description.
            port:
                type: int
                description: No description.
            port2:
                type: int
                description: No description.
            port3:
                type: int
                description: No description.
            port4:
                type: int
                description: No description.
            port5:
                type: int
                description: No description.
            server:
                type: str
                description: No description.
            server2:
                type: str
                description: No description.
            server3:
                type: str
                description: No description.
            server4:
                type: str
                description: No description.
            server5:
                type: str
                description: No description.
            source-ip:
                type: str
                description: Deprecated, please rename it to source_ip.
            source-ip6:
                type: str
                description: Deprecated, please rename it to source_ip6.
            ssl:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
            ssl-trusted-cert:
                type: str
                description: Deprecated, please rename it to ssl_trusted_cert.
            type:
                type: str
                description: No description.
                choices:
                    - 'default'
                    - 'fortiems'
                    - 'fortinac'
                    - 'fortiems-cloud'
            user-info-server:
                type: raw
                description: (list or str) Deprecated, please rename it to user_info_server.
            ldap-poll:
                type: str
                description: Deprecated, please rename it to ldap_poll.
                choices:
                    - 'disable'
                    - 'enable'
            ldap-poll-filter:
                type: str
                description: Deprecated, please rename it to ldap_poll_filter.
            ldap-poll-interval:
                type: int
                description: Deprecated, please rename it to ldap_poll_interval.
            group-poll-interval:
                type: int
                description: Deprecated, please rename it to group_poll_interval.
            interface:
                type: str
                description: No description.
            interface-select-method:
                type: str
                description: Deprecated, please rename it to interface_select_method.
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            logon-timeout:
                type: int
                description: Deprecated, please rename it to logon_timeout. Interval in minutes to keep logons after FSSO server down.
            sni:
                type: str
                description: Server Name Indication.
            ssl-server-host-ip-check:
                type: str
                description: Deprecated, please rename it to ssl_server_host_ip_check. Enable/disable server host/IP verification.
                choices:
                    - 'disable'
                    - 'enable'
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
    - name: Configure dynamic mappings of Fortinet Single Sign On (FSSO) agent
      fortinet.fortimanager.fmgr_user_fsso_dynamicmapping:
        bypass_validation: false
        adom: ansible
        fsso: ansible-test-fsso # name
        state: present
        user_fsso_dynamicmapping:
          _scope:
            - name: FGT_AWS # need a valid device name
              vdom: root # need a valid vdom name under the device
          password: fortinet
          port: 9000
          server: ansible

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the dynamic mappings of Fortinet Single Sign On (FSSO) agent
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "user_fsso_dynamicmapping"
          params:
            adom: "ansible"
            fsso: "ansible-test-fsso" # name
            dynamic_mapping: "your_value"
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
        '/pm/config/adom/{adom}/obj/user/fsso/{fsso}/dynamic_mapping',
        '/pm/config/global/obj/user/fsso/{fsso}/dynamic_mapping'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/user/fsso/{fsso}/dynamic_mapping/{dynamic_mapping}',
        '/pm/config/global/obj/user/fsso/{fsso}/dynamic_mapping/{dynamic_mapping}'
    ]

    url_params = ['adom', 'fsso']
    module_primary_key = 'complex:{{module}}["_scope"][0]["name"]+"/"+{{module}}["_scope"][0]["vdom"]'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'fsso': {'required': True, 'type': 'str'},
        'user_fsso_dynamicmapping': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                '_gui_meta': {'type': 'str'},
                '_scope': {'type': 'list', 'options': {'name': {'type': 'str'}, 'vdom': {'type': 'str'}}, 'elements': 'dict'},
                'ldap-server': {'type': 'str'},
                'password': {'no_log': True, 'type': 'raw'},
                'password2': {'no_log': True, 'type': 'raw'},
                'password3': {'no_log': True, 'type': 'raw'},
                'password4': {'no_log': True, 'type': 'raw'},
                'password5': {'no_log': True, 'type': 'raw'},
                'port': {'type': 'int'},
                'port2': {'type': 'int'},
                'port3': {'type': 'int'},
                'port4': {'type': 'int'},
                'port5': {'type': 'int'},
                'server': {'type': 'str'},
                'server2': {'type': 'str'},
                'server3': {'type': 'str'},
                'server4': {'type': 'str'},
                'server5': {'type': 'str'},
                'source-ip': {'type': 'str'},
                'source-ip6': {'type': 'str'},
                'ssl': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-trusted-cert': {'type': 'str'},
                'type': {'choices': ['default', 'fortiems', 'fortinac', 'fortiems-cloud'], 'type': 'str'},
                'user-info-server': {'type': 'raw'},
                'ldap-poll': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ldap-poll-filter': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'ldap-poll-interval': {'v_range': [['6.2.1', '']], 'type': 'int'},
                'group-poll-interval': {'v_range': [['6.2.2', '']], 'type': 'int'},
                'interface': {'v_range': [['6.2.6', '6.2.12'], ['6.4.2', '']], 'type': 'str'},
                'interface-select-method': {'v_range': [['6.2.6', '6.2.12'], ['6.4.2', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'logon-timeout': {'v_range': [['6.4.7', '6.4.14'], ['7.0.1', '']], 'type': 'int'},
                'sni': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'ssl-server-host-ip-check': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_fsso_dynamicmapping'),
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
