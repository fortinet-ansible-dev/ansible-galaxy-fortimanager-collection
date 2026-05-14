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
module: fmgr_fmg_device_blueprint
short_description: Fmg device blueprint
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
    fmg_device_blueprint:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            cliprofs:
                type: raw
                description: (list) Cliprofs.
            description:
                type: str
                description: Description.
            dev_group:
                aliases: ['dev-group']
                type: raw
                description: (list) Dev group.
            folder:
                type: str
                description: Folder.
            name:
                type: str
                description: Name.
                required: true
            pkg:
                type: str
                description: Pkg.
            platform:
                type: str
                description: Platform.
            prefer_img_ver:
                aliases: ['prefer-img-ver']
                type: str
                description: Prefer img ver.
            prerun_cliprof:
                aliases: ['prerun-cliprof']
                type: raw
                description: (list) Prerun cliprof.
            prov_type:
                aliases: ['prov-type']
                type: str
                description: Prov type.
                choices: ['none', 'templates', 'template-group']
            template_group:
                aliases: ['template-group']
                type: str
                description: Template group.
            templates:
                type: raw
                description: (list) Templates.
            enforce_device_config:
                aliases: ['enforce-device-config']
                type: str
                description: Enforce device config.
                choices: ['disable', 'enable']
            auth_template:
                aliases: ['auth-template']
                type: raw
                description: (list) Auth template.
            ha_config:
                aliases: ['ha-config']
                type: str
                description: Ha config.
                choices: ['disable', 'enable']
            ha_hbdev:
                aliases: ['ha-hbdev']
                type: raw
                description: Ha hbdev.
            ha_monitor:
                aliases: ['ha-monitor']
                type: raw
                description: (list) Ha monitor.
            ha_password:
                aliases: ['ha-password']
                type: raw
                description: (list) Ha password.
            linked_to_model:
                aliases: ['linked-to-model']
                type: str
                description: Linked to model.
                choices: ['disable', 'enable']
            port_provisioning:
                aliases: ['port-provisioning']
                type: int
                description: Port provisioning.
            sdwan_management:
                aliases: ['sdwan-management']
                type: str
                description: Sdwan management.
                choices: ['disable', 'enable']
            split_switch_port:
                aliases: ['split-switch-port']
                type: str
                description: Split switch port.
                choices: ['disable', 'enable']
            vm_log_disk:
                aliases: ['vm-log-disk']
                type: str
                description: Vm log disk.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Fmg device blueprint
      fortinet.fortimanager.fmgr_fmg_device_blueprint:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        fmg_device_blueprint:
          name: "your value" # Required variable, string
          # cliprofs: <list or string>
          # description: <string>
          # dev_group: <list or string>
          # folder: <string>
          # pkg: <string>
          # platform: <string>
          # prefer_img_ver: <string>
          # prerun_cliprof: <list or string>
          # prov_type: <value in [none, templates, template-group]>
          # template_group: <string>
          # templates: <list or string>
          # enforce_device_config: <value in [disable, enable]>
          # auth_template: <list or string>
          # ha_config: <value in [disable, enable]>
          # ha_hbdev: <any type>
          # ha_monitor: <list or string>
          # ha_password: <list or string>
          # linked_to_model: <value in [disable, enable]>
          # port_provisioning: <integer>
          # sdwan_management: <value in [disable, enable]>
          # split_switch_port: <value in [disable, enable]>
          # vm_log_disk: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/fmg/device/blueprint',
        '/pm/config/global/obj/fmg/device/blueprint'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'fmg_device_blueprint': {
            'type': 'dict', 'v_range': [['7.2.0', '']],
            'options': {
                'cliprofs': {'v_range': [['7.2.0', '']], 'type': 'raw'},
                'description': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'dev-group': {'v_range': [['7.2.0', '']], 'type': 'raw'},
                'folder': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'name': {'v_range': [['7.2.0', '']], 'required': True, 'type': 'str'},
                'pkg': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'platform': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'prefer-img-ver': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'prerun-cliprof': {'v_range': [['7.2.0', '']], 'type': 'raw'},
                'prov-type': {'v_range': [['7.2.0', '']], 'choices': ['none', 'templates', 'template-group'], 'type': 'str'},
                'template-group': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'templates': {'v_range': [['7.2.0', '']], 'type': 'raw'},
                'enforce-device-config': {'v_range': [['7.2.5', '7.2.12'], ['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-template': {'v_range': [['7.4.1', '']], 'type': 'raw'},
                'ha-config': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ha-hbdev': {'v_range': [['7.4.1', '']], 'type': 'raw'},
                'ha-monitor': {'v_range': [['7.4.1', '']], 'type': 'raw'},
                'ha-password': {'v_range': [['7.4.1', '']], 'no_log': True, 'type': 'raw'},
                'linked-to-model': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'port-provisioning': {'v_range': [['7.4.4', '']], 'type': 'int'},
                'sdwan-management': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'split-switch-port': {'v_range': [['7.4.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vm-log-disk': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fmg_device_blueprint'),
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
