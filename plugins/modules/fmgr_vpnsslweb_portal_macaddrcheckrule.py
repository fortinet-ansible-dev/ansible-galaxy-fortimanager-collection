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
module: fmgr_vpnsslweb_portal_macaddrcheckrule
short_description: Client MAC address check rule.
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
    portal:
        description: The parameter (portal) in requested url.
        type: str
        required: true
    vpnsslweb_portal_macaddrcheckrule:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            mac_addr_list:
                aliases: ['mac-addr-list']
                type: raw
                description: (list) Client MAC address list.
            mac_addr_mask:
                aliases: ['mac-addr-mask']
                type: int
                description: Client MAC address mask.
            name:
                type: str
                description: Client MAC address check rule name.
                required: true
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Client MAC address check rule.
      fortinet.fortimanager.fmgr_vpnsslweb_portal_macaddrcheckrule:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        portal: <your own value>
        state: present # <value in [present, absent]>
        vpnsslweb_portal_macaddrcheckrule:
          name: "your value" # Required variable, string
          # mac_addr_list: <list or string>
          # mac_addr_mask: <integer>
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
        '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/mac-addr-check-rule',
        '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/mac-addr-check-rule'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'portal': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'vpnsslweb_portal_macaddrcheckrule': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {'mac-addr-list': {'type': 'raw'}, 'mac-addr-mask': {'type': 'int'}, 'name': {'required': True, 'type': 'str'}}
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpnsslweb_portal_macaddrcheckrule'),
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
