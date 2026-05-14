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
module: fmgr_firewall_shapingprofile_shapingentries
short_description: Define shaping entries of this shaping profile.
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
    shaping-profile:
        description: Deprecated, please use "shaping_profile"
        type: str
    shaping_profile:
        description: The parameter (shaping-profile) in requested url.
        type: str
    firewall_shapingprofile_shapingentries:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            class_id:
                aliases: ['class-id']
                type: raw
                description: (int or str) Class ID.
            guaranteed_bandwidth_percentage:
                aliases: ['guaranteed-bandwidth-percentage']
                type: int
                description: Guaranteed bandwith in percentage.
            id:
                type: int
                description: ID number.
                required: true
            maximum_bandwidth_percentage:
                aliases: ['maximum-bandwidth-percentage']
                type: int
                description: Maximum bandwith in percentage.
            priority:
                type: str
                description: Priority.
                choices: ['low', 'medium', 'high', 'critical', 'top']
            burst_in_msec:
                aliases: ['burst-in-msec']
                type: int
                description: Number of bytes that can be burst at maximum-bandwidth speed.
            cburst_in_msec:
                aliases: ['cburst-in-msec']
                type: int
                description: Number of bytes that can be burst as fast as the interface can transmit.
            limit:
                type: int
                description: Hard limit on the real queue size in packets.
            max:
                type: int
                description: Average queue size in packets at which RED drop probability is maximal.
            min:
                type: int
                description: Average queue size in packets at which RED drop becomes a possibility.
            red_probability:
                aliases: ['red-probability']
                type: int
                description: Maximum probability
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
    - name: Define shaping entries of this shaping profile.
      fortinet.fortimanager.fmgr_firewall_shapingprofile_shapingentries:
        bypass_validation: false
        adom: ansible
        shaping_profile: "ansible-test" # profile-name
        state: present
        firewall_shapingprofile_shapingentries:
          guaranteed_bandwidth_percentage: 50
          id: 1
          maximum_bandwidth_percentage: 70
          priority: medium # <value in [low, medium, high]>

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the shaping entries of this shaping profile
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_shapingprofile_shapingentries"
          params:
            adom: "ansible"
            shaping_profile: "ansible-test" # profile-name
            shaping_entries: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/shaping-profile/{shaping-profile}/shaping-entries',
        '/pm/config/global/obj/firewall/shaping-profile/{shaping-profile}/shaping-entries'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'shaping-profile': {'type': 'str', 'api_name': 'shaping_profile'},
        'shaping_profile': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_shapingprofile_shapingentries': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'class-id': {'type': 'raw'},
                'guaranteed-bandwidth-percentage': {'type': 'int'},
                'id': {'required': True, 'type': 'int'},
                'maximum-bandwidth-percentage': {'type': 'int'},
                'priority': {'choices': ['low', 'medium', 'high', 'critical', 'top'], 'type': 'str'},
                'burst-in-msec': {'v_range': [['6.2.1', '']], 'type': 'int'},
                'cburst-in-msec': {'v_range': [['6.2.1', '']], 'type': 'int'},
                'limit': {'v_range': [['6.2.1', '']], 'type': 'int'},
                'max': {'v_range': [['6.2.1', '']], 'type': 'int'},
                'min': {'v_range': [['6.2.1', '']], 'type': 'int'},
                'red-probability': {'v_range': [['6.2.1', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_shapingprofile_shapingentries'),
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
