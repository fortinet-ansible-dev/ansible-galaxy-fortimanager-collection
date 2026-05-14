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
module: fmgr_hotspot20_h2qpadviceofcharge_aoclist_planinfo
short_description: Plan info.
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
    h2qp-advice-of-charge:
        description: Deprecated, please use "h2qp_advice_of_charge"
        type: str
    h2qp_advice_of_charge:
        description: The parameter (h2qp-advice-of-charge) in requested url.
        type: str
    aoc-list:
        description: Deprecated, please use "aoc_list"
        type: str
    aoc_list:
        description: The parameter (aoc-list) in requested url.
        type: str
    hotspot20_h2qpadviceofcharge_aoclist_planinfo:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            currency:
                type: str
                description: Currency code.
            info_file:
                aliases: ['info-file']
                type: str
                description: Info file.
            lang:
                type: str
                description: Language code.
            name:
                type: str
                description: Plan name.
                required: true
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Plan info.
      fortinet.fortimanager.fmgr_hotspot20_h2qpadviceofcharge_aoclist_planinfo:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        h2qp_advice_of_charge: <your own value>
        aoc_list: <your own value>
        state: present # <value in [present, absent]>
        hotspot20_h2qpadviceofcharge_aoclist_planinfo:
          name: "your value" # Required variable, string
          # currency: <string>
          # info_file: <string>
          # lang: <string>
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
        '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}/plan-info',
        '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}/plan-info'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'h2qp-advice-of-charge': {'type': 'str', 'api_name': 'h2qp_advice_of_charge'},
        'h2qp_advice_of_charge': {'type': 'str'},
        'aoc-list': {'type': 'str', 'api_name': 'aoc_list'},
        'aoc_list': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'hotspot20_h2qpadviceofcharge_aoclist_planinfo': {
            'type': 'dict', 'v_range': [['7.0.3', '']],
            'options': {
                'currency': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'info-file': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'lang': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'name': {'v_range': [['7.0.3', '']], 'required': True, 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'hotspot20_h2qpadviceofcharge_aoclist_planinfo'),
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
