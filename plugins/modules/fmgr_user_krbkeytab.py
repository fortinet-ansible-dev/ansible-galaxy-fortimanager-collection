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
module: fmgr_user_krbkeytab
short_description: Configure Kerberos keytab entries.
version_added: "2.1.0"
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
    user_krbkeytab:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            keytab:
                type: str
                description: Base64 coded keytab file containing a pre-shared key.
            ldap_server:
                aliases: ['ldap-server']
                type: raw
                description: (list or str) LDAP server name.
            name:
                type: str
                description: Kerberos keytab entry name.
                required: true
            pac_data:
                aliases: ['pac-data']
                type: str
                description: Enable/disable parsing PAC data in the ticket.
                choices: ['disable', 'enable']
            principal:
                type: str
                description: Kerberos service principal, e.
            password:
                type: raw
                description: (list) Password for keytab.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure Kerberos keytab entries.
      fortinet.fortimanager.fmgr_user_krbkeytab:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        user_krbkeytab:
          name: "your value" # Required variable, string
          # keytab: <string>
          # ldap_server: <list or string>
          # pac_data: <value in [disable, enable]>
          # principal: <string>
          # password: <list or string>
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
        '/pm/config/adom/{adom}/obj/user/krb-keytab',
        '/pm/config/global/obj/user/krb-keytab'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'user_krbkeytab': {
            'type': 'dict', 'v_range': [['6.2.1', '']], 'no_log': False,
            'options': {
                'keytab': {'v_range': [['6.2.1', '']], 'no_log': True, 'type': 'str'},
                'ldap-server': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'name': {'v_range': [['6.2.1', '']], 'required': True, 'type': 'str'},
                'pac-data': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'principal': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'password': {'v_range': [['6.2.2', '7.2.0'], ['7.2.5', '7.2.12'], ['7.4.2', '']], 'no_log': True, 'type': 'raw'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_krbkeytab'),
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
