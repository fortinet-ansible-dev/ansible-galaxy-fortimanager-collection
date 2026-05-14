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
module: fmgr_mpskprofile_mpskgroup
short_description: List of multiple PSK groups.
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
    mpsk-profile:
        description: Deprecated, please use "mpsk_profile"
        type: str
    mpsk_profile:
        description: The parameter (mpsk-profile) in requested url.
        type: str
    mpskprofile_mpskgroup:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            mpsk_key:
                aliases: ['mpsk-key']
                type: list
                elements: dict
                description: Mpsk key.
                suboptions:
                    comment:
                        type: str
                        description: Comment.
                    concurrent_client_limit_type:
                        aliases: ['concurrent-client-limit-type']
                        type: str
                        description: MPSK client limit type options.
                        choices: ['default', 'unlimited', 'specified']
                    concurrent_clients:
                        aliases: ['concurrent-clients']
                        type: int
                        description: Number of clients that can connect using this pre-shared key
                    mac:
                        type: str
                        description: MAC address.
                    mpsk_schedules:
                        aliases: ['mpsk-schedules']
                        type: raw
                        description: (list or str) Firewall schedule for MPSK passphrase.
                    name:
                        type: str
                        description: Pre-shared key name.
                    passphrase:
                        type: raw
                        description: (list) WPA Pre-shared key.
                    pmk:
                        type: raw
                        description: (list) WPA PMK.
                    key_type:
                        aliases: ['key-type']
                        type: str
                        description: Select the type of the key.
                        choices: ['wpa2-personal', 'wpa3-sae']
                    sae_password:
                        aliases: ['sae-password']
                        type: raw
                        description: (list) WPA3 SAE password.
                    sae_pk:
                        aliases: ['sae-pk']
                        type: str
                        description: Enable/disable WPA3 SAE-PK
                        choices: ['disable', 'enable']
                    sae_private_key:
                        aliases: ['sae-private-key']
                        type: str
                        description: Private key used for WPA3 SAE-PK authentication.
            name:
                type: str
                description: MPSK group name.
                required: true
            vlan_id:
                aliases: ['vlan-id']
                type: int
                description: Optional VLAN ID.
            vlan_type:
                aliases: ['vlan-type']
                type: str
                description: MPSK group VLAN options.
                choices: ['no-vlan', 'fixed-vlan']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: List of multiple PSK groups.
      fortinet.fortimanager.fmgr_mpskprofile_mpskgroup:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        mpsk_profile: <your own value>
        state: present # <value in [present, absent]>
        mpskprofile_mpskgroup:
          name: "your value" # Required variable, string
          # mpsk_key:
          #   - comment: <string>
          #     concurrent_client_limit_type: <value in [default, unlimited, specified]>
          #     concurrent_clients: <integer>
          #     mac: <string>
          #     mpsk_schedules: <list or string>
          #     name: <string>
          #     passphrase: <list or string>
          #     pmk: <list or string>
          #     key_type: <value in [wpa2-personal, wpa3-sae]>
          #     sae_password: <list or string>
          #     sae_pk: <value in [disable, enable]>
          #     sae_private_key: <string>
          # vlan_id: <integer>
          # vlan_type: <value in [no-vlan, fixed-vlan]>
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
        '/pm/config/adom/{adom}/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group',
        '/pm/config/global/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'mpsk-profile': {'type': 'str', 'api_name': 'mpsk_profile'},
        'mpsk_profile': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'mpskprofile_mpskgroup': {
            'type': 'dict', 'v_range': [['6.4.2', '']],
            'options': {
                'mpsk-key': {
                    'v_range': [['6.4.2', '']],
                    'no_log': True,
                    'type': 'list',
                    'options': {
                        'comment': {'v_range': [['6.4.2', '']], 'type': 'str'},
                        'concurrent-client-limit-type': {'v_range': [['6.4.2', '']], 'choices': ['default', 'unlimited', 'specified'], 'type': 'str'},
                        'concurrent-clients': {'v_range': [['6.4.2', '']], 'type': 'int'},
                        'mac': {'v_range': [['6.4.2', '']], 'type': 'str'},
                        'mpsk-schedules': {'v_range': [['6.4.2', '']], 'type': 'raw'},
                        'name': {'v_range': [['6.4.2', '']], 'type': 'str'},
                        'passphrase': {'v_range': [['6.4.2', '']], 'no_log': True, 'type': 'raw'},
                        'pmk': {'v_range': [['6.4.2', '']], 'type': 'raw'},
                        'key-type': {'v_range': [['7.4.3', '']], 'choices': ['wpa2-personal', 'wpa3-sae'], 'type': 'str'},
                        'sae-password': {'v_range': [['7.4.3', '']], 'no_log': True, 'type': 'raw'},
                        'sae-pk': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sae-private-key': {'v_range': [['7.4.3', '']], 'no_log': True, 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'name': {'v_range': [['6.4.2', '']], 'required': True, 'type': 'str'},
                'vlan-id': {'v_range': [['6.4.2', '']], 'type': 'int'},
                'vlan-type': {'v_range': [['6.4.2', '']], 'choices': ['no-vlan', 'fixed-vlan'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'mpskprofile_mpskgroup'),
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
