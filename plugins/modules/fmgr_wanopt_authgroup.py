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
module: fmgr_wanopt_authgroup
short_description: Configure WAN optimization authentication groups.
version_added: "2.0.0"
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
    wanopt_authgroup:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auth_method:
                aliases: ['auth-method']
                type: str
                description: Select certificate or pre-shared key authentication for this authentication group.
                choices: ['cert', 'psk']
            cert:
                type: str
                description: Name of certificate to identify this peer.
            name:
                type: str
                description: Auth-group name.
                required: true
            peer:
                type: str
                description: If peer-accept is set to one, select the name of one peer to add to this authentication group.
            peer_accept:
                aliases: ['peer-accept']
                type: str
                description: Determine if this auth group accepts, any peer, a list of defined peers, or just one peer.
                choices: ['any', 'defined', 'one']
            psk:
                type: raw
                description: (list) Pre-shared key used by the peers in this authentication group.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure WAN optimization authentication groups.
      fortinet.fortimanager.fmgr_wanopt_authgroup:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        wanopt_authgroup:
          name: "your value" # Required variable, string
          # auth_method: <value in [cert, psk]>
          # cert: <string>
          # peer: <string>
          # peer_accept: <value in [any, defined, one]>
          # psk: <list or string>
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
        '/pm/config/adom/{adom}/obj/wanopt/auth-group',
        '/pm/config/global/obj/wanopt/auth-group'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'wanopt_authgroup': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'auth-method': {'choices': ['cert', 'psk'], 'type': 'str'},
                'cert': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'peer': {'type': 'str'},
                'peer-accept': {'choices': ['any', 'defined', 'one'], 'type': 'str'},
                'psk': {'type': 'raw'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wanopt_authgroup'),
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
