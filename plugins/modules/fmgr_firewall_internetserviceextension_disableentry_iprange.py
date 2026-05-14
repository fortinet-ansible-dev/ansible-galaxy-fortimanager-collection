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
module: fmgr_firewall_internetserviceextension_disableentry_iprange
short_description: IPv4 ranges in the disable entry.
version_added: "2.10.0"
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
    internet-service-extension:
        description: Deprecated, please use "internet_service_extension"
        type: str
    internet_service_extension:
        description: The parameter (internet-service-extension) in requested url.
        type: str
    disable-entry:
        description: Deprecated, please use "disable_entry"
        type: str
    disable_entry:
        description: The parameter (disable-entry) in requested url.
        type: str
    firewall_internetserviceextension_disableentry_iprange:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            end_ip:
                aliases: ['end-ip']
                type: str
                description: End IPv4 address.
            id:
                type: int
                description: Disable entry range ID.
                required: true
            start_ip:
                aliases: ['start-ip']
                type: str
                description: Start IPv4 address.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: IPv4 ranges in the disable entry.
      fortinet.fortimanager.fmgr_firewall_internetserviceextension_disableentry_iprange:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        internet_service_extension: <your own value>
        disable_entry: <your own value>
        state: present # <value in [present, absent]>
        firewall_internetserviceextension_disableentry_iprange:
          id: 0 # Required variable, integer
          # end_ip: <string>
          # start_ip: <string>
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
        '/pm/config/adom/{adom}/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/ip-range',
        '/pm/config/global/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/ip-range'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'internet-service-extension': {'type': 'str', 'api_name': 'internet_service_extension'},
        'internet_service_extension': {'type': 'str'},
        'disable-entry': {'type': 'str', 'api_name': 'disable_entry'},
        'disable_entry': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_internetserviceextension_disableentry_iprange': {
            'type': 'dict', 'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']],
            'options': {
                'end-ip': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'id': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'start-ip': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_internetserviceextension_disableentry_iprange'),
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
