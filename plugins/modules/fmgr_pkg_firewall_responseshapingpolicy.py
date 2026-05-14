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
module: fmgr_pkg_firewall_responseshapingpolicy
short_description: Policy package firewall response shaping policy
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
    pkg:
        description: The parameter (pkg) in requested url.
        type: str
        required: true
    pkg_firewall_responseshapingpolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            class_id:
                aliases: ['class-id']
                type: int
                description: Class id.
            class_id_reverse:
                aliases: ['class-id-reverse']
                type: int
                description: Class id reverse.
            comment:
                type: str
                description: Comment.
            dstaddr:
                type: list
                elements: str
                description: Dstaddr.
            dstaddr6:
                type: list
                elements: str
                description: Dstaddr6.
            id:
                type: int
                description: Id.
                required: true
            ip_version:
                aliases: ['ip-version']
                type: str
                description: Ip version.
                choices: ['6', '4']
            name:
                type: str
                description: Name.
            per_ip_shaper:
                aliases: ['per-ip-shaper']
                type: list
                elements: str
                description: Per ip shaper.
            schedule:
                type: list
                elements: str
                description: Schedule.
            srcaddr:
                type: list
                elements: str
                description: Srcaddr.
            status:
                type: str
                description: Status.
                choices: ['disable', 'enable']
            traffic_shaper:
                aliases: ['traffic-shaper']
                type: list
                elements: str
                description: Traffic shaper.
            traffic_shaper_reverse:
                aliases: ['traffic-shaper-reverse']
                type: list
                elements: str
                description: Traffic shaper reverse.
            uuid:
                type: str
                description: Uuid.
            diffserv_forward:
                aliases: ['diffserv-forward']
                type: str
                description: Diffserv forward.
                choices: ['disable', 'enable']
            diffserv_reverse:
                aliases: ['diffserv-reverse']
                type: str
                description: Diffserv reverse.
                choices: ['disable', 'enable']
            diffservcode_forward:
                aliases: ['diffservcode-forward']
                type: str
                description: Diffservcode forward.
            diffservcode_rev:
                aliases: ['diffservcode-rev']
                type: str
                description: Diffservcode rev.
            matched_shaping_policies:
                aliases: ['matched-shaping-policies']
                type: list
                elements: str
                description: Matched shaping policies.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Policy package firewall response shaping policy
      fortinet.fortimanager.fmgr_pkg_firewall_responseshapingpolicy:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        pkg: <your own value>
        state: present # <value in [present, absent]>
        pkg_firewall_responseshapingpolicy:
          id: 0 # Required variable, integer
          # class_id: <integer>
          # class_id_reverse: <integer>
          # comment: <string>
          # dstaddr: <list or string>
          # dstaddr6: <list or string>
          # ip_version: <value in [6, 4]>
          # name: <string>
          # per_ip_shaper: <list or string>
          # schedule: <list or string>
          # srcaddr: <list or string>
          # status: <value in [disable, enable]>
          # traffic_shaper: <list or string>
          # traffic_shaper_reverse: <list or string>
          # uuid: <string>
          # diffserv_forward: <value in [disable, enable]>
          # diffserv_reverse: <value in [disable, enable]>
          # diffservcode_forward: <string>
          # diffservcode_rev: <string>
          # matched_shaping_policies: <list or string>
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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/response-shaping-policy'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'pkg_firewall_responseshapingpolicy': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                'class-id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'class-id-reverse': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'comment': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'dstaddr': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dstaddr6': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'ip-version': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['6', '4'], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'per-ip-shaper': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'schedule': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'srcaddr': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'traffic-shaper': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'traffic-shaper-reverse': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'uuid': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'diffserv-forward': {'v_range': [['7.4.9', '7.4.10'], ['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'diffserv-reverse': {'v_range': [['7.4.9', '7.4.10'], ['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'diffservcode-forward': {'v_range': [['7.4.9', '7.4.10'], ['7.6.5', '']], 'type': 'str'},
                'diffservcode-rev': {'v_range': [['7.4.9', '7.4.10'], ['7.6.5', '']], 'type': 'str'},
                'matched-shaping-policies': {'v_range': [['7.4.9', '7.4.10'], ['7.6.5', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_responseshapingpolicy'),
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
