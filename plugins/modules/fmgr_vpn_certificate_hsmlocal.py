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
module: fmgr_vpn_certificate_hsmlocal
short_description: Local certificates whose keys are stored on HSM.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.
version_added: "2.12.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Starting in version 2.4.0, all input arguments are named using the underscore naming convention (snake_case).
      Please change the arguments such as "var-name" to "var_name".
      Old argument names are still available yet you will receive deprecation warnings.
      You can ignore this warning by setting deprecation_warnings=False in ansible.cfg.
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    vpn_certificate_hsmlocal:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            api_version:
                aliases: ['api-version']
                type: str
                description: API version for communicating with HSM.
                choices:
                    - 'unknown'
                    - 'gch-default'
            certificate:
                type: str
                description: PEM format certificate.
            comments:
                type: str
                description: Comment.
            gch_cloud_service_name:
                aliases: ['gch-cloud-service-name']
                type: list
                elements: str
                description: Cloud service config name to generate access token.
            gch_cryptokey:
                aliases: ['gch-cryptokey']
                type: str
                description: Google Cloud HSM cryptokey.
            gch_cryptokey_algorithm:
                aliases: ['gch-cryptokey-algorithm']
                type: str
                description: Google Cloud HSM cryptokey algorithm.
                choices:
                    - 'rsa-sign-pkcs1-2048-sha256'
                    - 'rsa-sign-pkcs1-3072-sha256'
                    - 'rsa-sign-pkcs1-4096-sha256'
                    - 'rsa-sign-pkcs1-4096-sha512'
                    - 'rsa-sign-pss-2048-sha256'
                    - 'rsa-sign-pss-3072-sha256'
                    - 'rsa-sign-pss-4096-sha256'
                    - 'rsa-sign-pss-4096-sha512'
                    - 'ec-sign-p256-sha256'
                    - 'ec-sign-p384-sha384'
                    - 'ec-sign-secp256k1-sha256'
                    - '2048-RSA-PKCS1v1.5-SHA256'
                    - '3072-RSA-PKCS1v1.5-SHA256'
                    - '4096-RSA-PKCS1v1.5-SHA256'
                    - '4096-RSA-PKCS1v1.5-SHA512'
                    - 'EC_P256_SHA256'
                    - 'EC_P384_SHA384'
                    - 'EC_secp256k1_SHA256'
            gch_cryptokey_version:
                aliases: ['gch-cryptokey-version']
                type: str
                description: Google Cloud HSM cryptokey version.
            gch_keyring:
                aliases: ['gch-keyring']
                type: str
                description: Google Cloud HSM keyring.
            gch_location:
                aliases: ['gch-location']
                type: str
                description: Google Cloud HSM location.
            gch_project:
                aliases: ['gch-project']
                type: str
                description: Google Cloud HSM project ID.
            gch_url:
                aliases: ['gch-url']
                type: str
                description: Gch url.
            name:
                type: str
                description: Name.
                required: true
            range:
                type: str
                description: Either a global or VDOM IP address range for the certificate.
                choices:
                    - 'global'
                    - 'vdom'
            source:
                type: str
                description: Certificate source type.
                choices:
                    - 'factory'
                    - 'user'
                    - 'bundle'
            tmp_cert_file:
                aliases: ['tmp-cert-file']
                type: str
                description: Temporary certificate file.
            vendor:
                type: str
                description: HSM vendor.
                choices:
                    - 'unknown'
                    - 'gch'
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Local certificates whose keys are stored on HSM.
      fortinet.fortimanager.fmgr_vpn_certificate_hsmlocal:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        vpn_certificate_hsmlocal:
          name: "your value" # Required variable, string
          # api_version: <value in [unknown, gch-default]>
          # certificate: <string>
          # comments: <string>
          # gch_cloud_service_name: <list or string>
          # gch_cryptokey: <string>
          # gch_cryptokey_algorithm: <value in [rsa-sign-pkcs1-2048-sha256, rsa-sign-pkcs1-3072-sha256, rsa-sign-pkcs1-4096-sha256, ...]>
          # gch_cryptokey_version: <string>
          # gch_keyring: <string>
          # gch_location: <string>
          # gch_project: <string>
          # gch_url: <string>
          # range: <value in [global, vdom]>
          # source: <value in [factory, user, bundle]>
          # tmp_cert_file: <string>
          # vendor: <value in [unknown, gch]>
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
        '/pm/config/adom/{adom}/obj/vpn/certificate/hsm-local',
        '/pm/config/global/obj/vpn/certificate/hsm-local'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'vpn_certificate_hsmlocal': {
            'type': 'dict',
            'v_range': [['7.6.4', '']],
            'options': {
                'api-version': {'v_range': [['7.6.4', '']], 'choices': ['unknown', 'gch-default'], 'type': 'str'},
                'certificate': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'comments': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'gch-cloud-service-name': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'gch-cryptokey': {'v_range': [['7.6.4', '']], 'no_log': True, 'type': 'str'},
                'gch-cryptokey-algorithm': {
                    'v_range': [['7.6.4', '']],
                    'choices': [
                        'rsa-sign-pkcs1-2048-sha256', 'rsa-sign-pkcs1-3072-sha256', 'rsa-sign-pkcs1-4096-sha256', 'rsa-sign-pkcs1-4096-sha512',
                        'rsa-sign-pss-2048-sha256', 'rsa-sign-pss-3072-sha256', 'rsa-sign-pss-4096-sha256', 'rsa-sign-pss-4096-sha512',
                        'ec-sign-p256-sha256', 'ec-sign-p384-sha384', 'ec-sign-secp256k1-sha256', '2048-RSA-PKCS1v1.5-SHA256',
                        '3072-RSA-PKCS1v1.5-SHA256', '4096-RSA-PKCS1v1.5-SHA256', '4096-RSA-PKCS1v1.5-SHA512', 'EC_P256_SHA256', 'EC_P384_SHA384',
                        'EC_secp256k1_SHA256'
                    ],
                    'type': 'str'
                },
                'gch-cryptokey-version': {'v_range': [['7.6.4', '']], 'no_log': True, 'type': 'str'},
                'gch-keyring': {'v_range': [['7.6.4', '']], 'no_log': True, 'type': 'str'},
                'gch-location': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'gch-project': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'gch-url': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'name': {'v_range': [['7.6.4', '']], 'required': True, 'type': 'str'},
                'range': {'v_range': [['7.6.4', '']], 'choices': ['global', 'vdom'], 'type': 'str'},
                'source': {'v_range': [['7.6.4', '']], 'choices': ['factory', 'user', 'bundle'], 'type': 'str'},
                'tmp-cert-file': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'vendor': {'v_range': [['7.6.4', '']], 'choices': ['unknown', 'gch'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpn_certificate_hsmlocal'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
