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
module: fmgr_system_admin_ldap
short_description: LDAP server entry configuration.
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
    system_admin_ldap:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            adom:
                type: list
                elements: dict
                description: Adom.
                suboptions:
                    adom-name:
                        type: str
                        description: Deprecated, please rename it to adom_name. Admin domain names.
            adom-attr:
                type: str
                description: Deprecated, please rename it to adom_attr. Attribute used to retrieve adom
            attributes:
                type: str
                description: Attributes used for group searching.
            ca-cert:
                type: str
                description: Deprecated, please rename it to ca_cert. CA certificate name.
            cnid:
                type: str
                description: Common Name Identifier
            connect-timeout:
                type: int
                description: Deprecated, please rename it to connect_timeout. LDAP connection timeout
            dn:
                type: str
                description: Distinguished Name.
            filter:
                type: str
                description: Filter used for group searching.
            group:
                type: str
                description: Full base DN used for group searching.
            memberof-attr:
                type: str
                description: Deprecated, please rename it to memberof_attr. Attribute used to retrieve memeberof.
            name:
                type: str
                description: LDAP server entry name.
                required: true
            password:
                type: raw
                description: (list) Password for initial binding.
            port:
                type: int
                description: Port number of LDAP server
            profile-attr:
                type: str
                description: Deprecated, please rename it to profile_attr. Attribute used to retrieve admin profile.
            secondary-server:
                type: str
                description: Deprecated, please rename it to secondary_server. No description
            secure:
                type: str
                description:
                    - SSL connection.
                    - disable - No SSL.
                    - starttls - Use StartTLS.
                    - ldaps - Use LDAPS.
                choices:
                    - 'disable'
                    - 'starttls'
                    - 'ldaps'
            server:
                type: str
                description: No description
            tertiary-server:
                type: str
                description: Deprecated, please rename it to tertiary_server. No description
            type:
                type: str
                description:
                    - Type of LDAP binding.
                    - simple - Simple password authentication without search.
                    - anonymous - Bind using anonymous user search.
                    - regular - Bind using username/password and then search.
                choices:
                    - 'simple'
                    - 'anonymous'
                    - 'regular'
            username:
                type: str
                description: Username
            adom-access:
                type: str
                description:
                    - Deprecated, please rename it to adom_access.
                    - set all or specify adom access type.
                    - all - All ADOMs access.
                    - specify - Specify ADOMs access.
                choices:
                    - 'all'
                    - 'specify'
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
    - name: LDAP server entry configuration.
      fortinet.fortimanager.fmgr_system_admin_ldap:
        bypass_validation: false
        state: present
        system_admin_ldap:
          adom:
            - adom-name: ansible
          name: ansible-test-ldap
          password: Fortinet
          port: 390
          server: ansible
          type: regular # <value in [simple, anonymous, regular]>
          username: ansible-username

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the LDAP servers
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_admin_ldap"
          params:
            ldap: "your_value"
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
        '/cli/global/system/admin/ldap'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/admin/ldap/{ldap}'
    ]

    url_params = []
    module_primary_key = 'name'
    module_arg_spec = {
        'system_admin_ldap': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'adom': {'type': 'list', 'options': {'adom-name': {'type': 'str'}}, 'elements': 'dict'},
                'adom-attr': {'type': 'str'},
                'attributes': {'type': 'str'},
                'ca-cert': {'type': 'str'},
                'cnid': {'type': 'str'},
                'connect-timeout': {'type': 'int'},
                'dn': {'type': 'str'},
                'filter': {'type': 'str'},
                'group': {'type': 'str'},
                'memberof-attr': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'password': {'no_log': True, 'type': 'raw'},
                'port': {'type': 'int'},
                'profile-attr': {'type': 'str'},
                'secondary-server': {'type': 'str'},
                'secure': {'choices': ['disable', 'starttls', 'ldaps'], 'type': 'str'},
                'server': {'type': 'str'},
                'tertiary-server': {'type': 'str'},
                'type': {'choices': ['simple', 'anonymous', 'regular'], 'type': 'str'},
                'username': {'type': 'str'},
                'adom-access': {'v_range': [['7.0.3', '']], 'choices': ['all', 'specify'], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_admin_ldap'),
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
