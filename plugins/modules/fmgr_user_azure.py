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
module: fmgr_user_azure
short_description: User azure
version_added: "2.15.0"
extends_documentation_fragment:
  - fortinet.fortimanager.general
  - fortinet.fortimanager.general.full_crud
options:
  revision_note:
    description: The change note that can be specified when an object is created or updated.
    type: str
  adom:
    description: The parameter (adom) in requested url.
    type: str
    required: true
  user_azure:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      SPN:
        type: str
        description: SPN.
      alias:
        type: str
        description: Alias.
      kbconfig:
        type: str
        description: Kbconfig.
      name:
        type: str
        description: Name.
        required: true
      page_size:
        type: int
        description: Page size.
      password:
        type: list
        elements: str
        description: Password.
      proxy_enable:
        type: str
        description: Proxy enable.
        choices: ['disable', 'enable']
      proxy_host:
        type: str
        description: Proxy host.
      proxy_passwd:
        type: list
        elements: str
        description: Proxy passwd.
      proxy_scheme:
        type: str
        description: Proxy scheme.
        choices: ['http', 'https']
      proxy_user:
        type: str
        description: Proxy user.
      realm:
        type: str
        description: Realm.
      region:
        type: str
        description: Region.
        choices: ['global', 'china', 'germany', 'usgov', 'local']
      rule:
        type: list
        elements: dict
        description: Rule.
        suboptions:
          name:
            type: str
            description: Name.
          rule:
            type: str
            description: Rule.
      select_proxy:
        type: str
        description: Select proxy.
        choices: ['basic', 'kerberos']
      status:
        type: str
        description: Status.
        choices: ['disable', 'enable']
      tenantid:
        type: str
        description: Tenantid.
      upd_interval:
        type: int
        description: Upd interval.
      user:
        type: str
        description: User.
      verifycert:
        type: str
        description: Verifycert.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Test Azure users
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Create an Azure user connector
      fortinet.fortimanager.fmgr_user_azure:
        enable_log: true
        adom: root
        state: present
        user_azure:
          name: test_azure

- name: Test Azure user rules
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Create the parent Azure user connector
      fortinet.fortimanager.fmgr_user_azure:
        enable_log: true
        adom: root
        state: present
        user_azure:
          name: test_azure

    - name: Create an Azure user rule
      fortinet.fortimanager.fmgr_user_azure_rule:
        enable_log: true
        adom: root
        azure: test_azure
        state: present
        user_azure_rule:
          name: test_rule
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
        '/pm/config/adom/{adom}/obj/user/azure',
        '/pm/config/global/obj/user/azure'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'user_azure': {
            'type': 'dict', 'v_range': [['8.0.0', '']],
            'options': {
                'SPN': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'alias': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'kbconfig': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'name': {'v_range': [['8.0.0', '']], 'required': True, 'type': 'str'},
                'page_size': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'password': {'v_range': [['8.0.0', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'proxy_enable': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'proxy_host': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'proxy_passwd': {'v_range': [['8.0.0', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'proxy_scheme': {'v_range': [['8.0.0', '']], 'choices': ['http', 'https'], 'type': 'str'},
                'proxy_user': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'realm': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'region': {'v_range': [['8.0.0', '']], 'choices': ['global', 'china', 'germany', 'usgov', 'local'], 'type': 'str'},
                'rule': {
                    'v_range': [['8.0.0', '']],
                    'type': 'list',
                    'options': {'name': {'v_range': [['8.0.0', '']], 'type': 'str'}, 'rule': {'v_range': [['8.0.0', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'select_proxy': {'v_range': [['8.0.0', '']], 'choices': ['basic', 'kerberos'], 'type': 'str'},
                'status': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tenantid': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'upd_interval': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'user': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'verifycert': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_azure'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'name', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
