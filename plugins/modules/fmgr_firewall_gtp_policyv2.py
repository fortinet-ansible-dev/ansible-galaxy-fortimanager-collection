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
module: fmgr_firewall_gtp_policyv2
short_description: Apply allow or deny action to each GTPv2-c packet.
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
    gtp:
        description: The parameter (gtp) in requested url.
        type: str
        required: true
    firewall_gtp_policyv2:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Action.
                choices: ['deny', 'allow']
            apn_sel_mode:
                aliases: ['apn-sel-mode']
                type: list
                elements: str
                description: APN selection mode.
                choices: ['ms', 'net', 'vrf']
            apnmember:
                type: raw
                description: (list or str) APN member.
            id:
                type: int
                description: ID.
                required: true
            imsi_prefix:
                aliases: ['imsi-prefix']
                type: str
                description: IMSI prefix.
            max_apn_restriction:
                aliases: ['max-apn-restriction']
                type: str
                description: Maximum APN restriction value.
                choices: ['all', 'public-1', 'public-2', 'private-1', 'private-2']
            mei:
                type: str
                description: MEI pattern.
            messages:
                type: list
                elements: str
                description: GTP messages.
                choices: ['create-ses-req', 'create-ses-res', 'modify-bearer-req',
                          'modify-bearer-res']
            msisdn_prefix:
                aliases: ['msisdn-prefix']
                type: str
                description: MSISDN prefix.
            rat_type:
                aliases: ['rat-type']
                type: list
                elements: str
                description: RAT Type.
                choices: ['any', 'utran', 'geran', 'wlan', 'gan', 'hspa', 'eutran', 'virtual',
                          'nbiot', 'ltem', 'nr']
            uli:
                type: raw
                description: (list) GTPv2 ULI patterns
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Apply allow or deny action to each GTPv2-c packet.
      fortinet.fortimanager.fmgr_firewall_gtp_policyv2:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        gtp: <your own value>
        state: present # <value in [present, absent]>
        firewall_gtp_policyv2:
          id: 0 # Required variable, integer
          # action: <value in [deny, allow]>
          # apn_sel_mode: ["ms", "net", "vrf"]
          # apnmember: <list or string>
          # imsi_prefix: <string>
          # max_apn_restriction: <value in [all, public-1, public-2, ...]>
          # mei: <string>
          # messages: ["create-ses-req", "create-ses-res", "modify-bearer-req",
          #            "modify-bearer-res"]
          # msisdn_prefix: <string>
          # rat_type: ["any", "utran", "geran", "wlan", "gan", "hspa", "eutran", "virtual",
          #            "nbiot", "ltem", "nr"]
          # uli: <list or string>
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
        '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/policy-v2',
        '/pm/config/global/obj/firewall/gtp/{gtp}/policy-v2'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'gtp': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_gtp_policyv2': {
            'type': 'dict', 'v_range': [['6.2.1', '']],
            'options': {
                'action': {'v_range': [['6.2.1', '']], 'choices': ['deny', 'allow'], 'type': 'str'},
                'apn-sel-mode': {'v_range': [['6.2.1', '']], 'type': 'list', 'choices': ['ms', 'net', 'vrf'], 'elements': 'str'},
                'apnmember': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'id': {'v_range': [['6.2.1', '']], 'required': True, 'type': 'int'},
                'imsi-prefix': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'max-apn-restriction': {'v_range': [['6.2.1', '']], 'choices': ['all', 'public-1', 'public-2', 'private-1', 'private-2'], 'type': 'str'},
                'mei': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'messages': {
                    'v_range': [['6.2.1', '']],
                    'type': 'list',
                    'choices': ['create-ses-req', 'create-ses-res', 'modify-bearer-req', 'modify-bearer-res'],
                    'elements': 'str'
                },
                'msisdn-prefix': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'rat-type': {
                    'v_range': [['6.2.1', '']],
                    'type': 'list',
                    'choices': ['any', 'utran', 'geran', 'wlan', 'gan', 'hspa', 'eutran', 'virtual', 'nbiot', 'ltem', 'nr'],
                    'elements': 'str'
                },
                'uli': {'v_range': [['6.2.1', '']], 'type': 'raw'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_gtp_policyv2'),
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
