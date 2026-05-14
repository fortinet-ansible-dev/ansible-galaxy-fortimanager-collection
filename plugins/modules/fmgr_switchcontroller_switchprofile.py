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
module: fmgr_switchcontroller_switchprofile
short_description: Configure FortiSwitch switch profile.
version_added: "2.12.0"
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
    switchcontroller_switchprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            login:
                type: str
                description: Enable/disable FortiSwitch serial console.
                choices: ['disable', 'enable']
            login_passwd:
                aliases: ['login-passwd']
                type: list
                elements: str
                description: Login password of managed FortiSwitch.
            login_passwd_override:
                aliases: ['login-passwd-override']
                type: str
                description: Enable/disable overriding the admin administrator password for a managed FortiSwitch with the FortiGate admin administrato...
                choices: ['disable', 'enable']
            name:
                type: str
                description: FortiSwitch Profile name.
                required: true
            revision_backup_on_logout:
                aliases: ['revision-backup-on-logout']
                type: str
                description: Enable/disable automatic revision backup upon logout from FortiSwitch.
                choices: ['disable', 'enable']
            revision_backup_on_upgrade:
                aliases: ['revision-backup-on-upgrade']
                type: str
                description: Enable/disable automatic revision backup upon FortiSwitch image upgrade.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure FortiSwitch switch profile.
      fortinet.fortimanager.fmgr_switchcontroller_switchprofile:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_switchprofile:
          name: "your value" # Required variable, string
          # login: <value in [disable, enable]>
          # login_passwd: <list or string>
          # login_passwd_override: <value in [disable, enable]>
          # revision_backup_on_logout: <value in [disable, enable]>
          # revision_backup_on_upgrade: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/switch-controller/switch-profile',
        '/pm/config/global/obj/switch-controller/switch-profile'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'switchcontroller_switchprofile': {
            'type': 'dict', 'v_range': [['7.6.4', '']],
            'options': {
                'login': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'login-passwd': {'v_range': [['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'login-passwd-override': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.6.4', '']], 'required': True, 'type': 'str'},
                'revision-backup-on-logout': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'revision-backup-on-upgrade': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_switchprofile'),
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
