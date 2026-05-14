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
module: fmgr_hotspot20_h2qposuprovider_servicedescription
short_description: OSU service name.
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
    h2qp-osu-provider:
        description: Deprecated, please use "h2qp_osu_provider"
        type: str
    h2qp_osu_provider:
        description: The parameter (h2qp-osu-provider) in requested url.
        type: str
    hotspot20_h2qposuprovider_servicedescription:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            lang:
                type: str
                description: Language code.
            service_description:
                aliases: ['service-description']
                type: str
                description: Service description.
            service_id:
                aliases: ['service-id']
                type: int
                description: OSU service ID.
                required: true
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: OSU service name.
      fortinet.fortimanager.fmgr_hotspot20_h2qposuprovider_servicedescription:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        h2qp_osu_provider: <your own value>
        state: present # <value in [present, absent]>
        hotspot20_h2qposuprovider_servicedescription:
          service_id: 0 # Required variable, integer
          # lang: <string>
          # service_description: <string>
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
        '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/service-description',
        '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/service-description'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'h2qp-osu-provider': {'type': 'str', 'api_name': 'h2qp_osu_provider'},
        'h2qp_osu_provider': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'hotspot20_h2qposuprovider_servicedescription': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {'lang': {'type': 'str'}, 'service-description': {'type': 'str'}, 'service-id': {'required': True, 'type': 'int'}}
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'hotspot20_h2qposuprovider_servicedescription'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'service-id', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
