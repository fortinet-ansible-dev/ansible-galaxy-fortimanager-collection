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
module: fmgr_system_mail
short_description: Alert emails.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    system_mail:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auth:
                type: str
                description:
                    - Enable authentication.
                    - disable - Disable authentication.
                    - enable - Enable authentication.
                choices: ['disable', 'enable']
            id:
                type: str
                description: Mail Service ID.
                required: true
            passwd:
                type: raw
                description: (list) SMTP account password.
            port:
                type: int
                description: SMTP server port.
            secure_option:
                aliases: ['secure-option']
                type: str
                description:
                    - Communication secure option.
                    - default - Try STARTTLS, proceed as plain text communication otherwise.
                    - none - Communication will be in plain text format.
                    - smtps - Communication will be protected by SMTPS.
                    - starttls - Communication will be protected by STARTTLS.
                choices: ['default', 'none', 'smtps', 'starttls']
            server:
                type: str
                description: SMTP server.
            user:
                type: str
                description: SMTP account username.
            auth_type:
                aliases: ['auth-type']
                type: str
                description:
                    - SMTP authentication type.
                    - psk - Use username and password to authenticate.
                    - certificate - Use local certificate to authenticate.
                choices: ['psk', 'certificate']
            local_cert:
                aliases: ['local-cert']
                type: str
                description: SMTP local certificate.
            from:
                type: str
                description: Username for MAIL FROM.
            ssl_protocol:
                aliases: ['ssl-protocol']
                type: str
                description:
                    - set the lowest SSL protocol version for connection to mail server.
                    - follow-global-ssl-protocol - Follow system.
                    - sslv3 - set SSLv3 as the lowest version.
                    - tlsv1.
                    - tlsv1.
                    - tlsv1.
                    - tlsv1.
                choices: ['follow-global-ssl-protocol', 'sslv3', 'tlsv1.0', 'tlsv1.1', 'tlsv1.2',
                          'tlsv1.3']
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Alert emails.
      fortinet.fortimanager.fmgr_system_mail:
        bypass_validation: false
        state: present
        system_mail:
          auth: enable
          id: 1
          passwd: fortinet
          port: 1
          secure_option: none # <value in [default, none, smtps, ...]>
          server: ALL
          user: ansible

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the alert emails
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_mail"
          params:
            mail: "your_value"
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
        '/cli/global/system/mail'
    ]
    module_arg_spec = {
        'system_mail': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'auth': {'choices': ['disable', 'enable'], 'type': 'str'},
                'id': {'required': True, 'type': 'str'},
                'passwd': {'no_log': True, 'type': 'raw'},
                'port': {'type': 'int'},
                'secure-option': {'choices': ['default', 'none', 'smtps', 'starttls'], 'type': 'str'},
                'server': {'type': 'str'},
                'user': {'type': 'str'},
                'auth-type': {'v_range': [['6.4.6', '']], 'choices': ['psk', 'certificate'], 'type': 'str'},
                'local-cert': {'v_range': [['6.4.6', '']], 'type': 'str'},
                'from': {'v_range': [['7.0.7', '7.0.16'], ['7.2.2', '']], 'type': 'str'},
                'ssl-protocol': {
                    'v_range': [['7.4.4', '7.4.10'], ['7.6.2', '']],
                    'choices': ['follow-global-ssl-protocol', 'sslv3', 'tlsv1.0', 'tlsv1.1', 'tlsv1.2', 'tlsv1.3'],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_mail'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'id', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
