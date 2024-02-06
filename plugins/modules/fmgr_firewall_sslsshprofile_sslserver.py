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
module: fmgr_firewall_sslsshprofile_sslserver
short_description: SSL servers.
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
    ssl-ssh-profile:
        description: Deprecated, please use "ssl_ssh_profile"
        type: str
    ssl_ssh_profile:
        description: The parameter (ssl-ssh-profile) in requested url.
        type: str
    firewall_sslsshprofile_sslserver:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            ftps-client-cert-request:
                type: str
                description: Deprecated, please rename it to ftps_client_cert_request. Action based on client certificate request during the FTPS hands...
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            https-client-cert-request:
                type: str
                description: Deprecated, please rename it to https_client_cert_request. Action based on client certificate request during the HTTPS han...
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            id:
                type: int
                description: SSL server ID.
                required: true
            imaps-client-cert-request:
                type: str
                description: Deprecated, please rename it to imaps_client_cert_request. Action based on client certificate request during the IMAPS han...
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            ip:
                type: str
                description: IPv4 address of the SSL server.
            pop3s-client-cert-request:
                type: str
                description: Deprecated, please rename it to pop3s_client_cert_request. Action based on client certificate request during the POP3S han...
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            smtps-client-cert-request:
                type: str
                description: Deprecated, please rename it to smtps_client_cert_request. Action based on client certificate request during the SMTPS han...
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            ssl-other-client-cert-request:
                type: str
                description: Deprecated, please rename it to ssl_other_client_cert_request. Action based on client certificate request during an SSL pr...
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            ftps-client-certificate:
                type: str
                description: Deprecated, please rename it to ftps_client_certificate. Action based on received client certificate during the FTPS hands...
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            https-client-certificate:
                type: str
                description: Deprecated, please rename it to https_client_certificate. Action based on received client certificate during the HTTPS han...
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            imaps-client-certificate:
                type: str
                description: Deprecated, please rename it to imaps_client_certificate. Action based on received client certificate during the IMAPS han...
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            pop3s-client-certificate:
                type: str
                description: Deprecated, please rename it to pop3s_client_certificate. Action based on received client certificate during the POP3S han...
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            smtps-client-certificate:
                type: str
                description: Deprecated, please rename it to smtps_client_certificate. Action based on received client certificate during the SMTPS han...
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            ssl-other-client-certificate:
                type: str
                description: Deprecated, please rename it to ssl_other_client_certificate. Action based on received client certificate during an SSL pr...
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
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
    - name: SSL servers.
      fortinet.fortimanager.fmgr_firewall_sslsshprofile_sslserver:
        bypass_validation: false
        adom: ansible
        ssl-ssh-profile: "ansible-test" # name
        state: present
        firewall_sslsshprofile_sslserver:
          ftps-client-cert-request: block # <value in [bypass, inspect, block]>
          https-client-cert-request: bypass # <value in [bypass, inspect, block]>
          id: 1
          imaps-client-cert-request: bypass # <value in [bypass, inspect, block]>

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the SSL servers SSL/SSH protocol option
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_sslsshprofile_sslserver"
          params:
            adom: "ansible"
            ssl-ssh-profile: "ansible-test" # name
            ssl-server: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-server',
        '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-server'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-server/{ssl-server}',
        '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-server/{ssl-server}'
    ]

    url_params = ['adom', 'ssl-ssh-profile']
    module_primary_key = 'id'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'ssl-ssh-profile': {'type': 'str', 'api_name': 'ssl_ssh_profile'},
        'ssl_ssh_profile': {'type': 'str'},
        'firewall_sslsshprofile_sslserver': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'ftps-client-cert-request': {'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'https-client-cert-request': {'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'id': {'required': True, 'type': 'int'},
                'imaps-client-cert-request': {'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'ip': {'type': 'str'},
                'pop3s-client-cert-request': {'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'smtps-client-cert-request': {'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'ssl-other-client-cert-request': {'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'ftps-client-certificate': {'v_range': [['6.4.0', '']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'https-client-certificate': {'v_range': [['6.4.0', '']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'imaps-client-certificate': {'v_range': [['6.4.0', '']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'pop3s-client-certificate': {'v_range': [['6.4.0', '']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'smtps-client-certificate': {'v_range': [['6.4.0', '']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'ssl-other-client-certificate': {'v_range': [['6.4.0', '']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_sslsshprofile_sslserver'),
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
