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
module: fmgr_firewall_sslsshprofile_ssl
short_description: Configure SSL options.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    ssl-ssh-profile:
        description: Deprecated, please use "ssl_ssh_profile"
        type: str
    ssl_ssh_profile:
        description: The parameter (ssl-ssh-profile) in requested url.
        type: str
    firewall_sslsshprofile_ssl:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            allow_invalid_server_cert:
                aliases: ['allow-invalid-server-cert']
                type: str
                description: When enabled, allows SSL sessions whose server certificate validation failed.
                choices: ['disable', 'enable']
            client_cert_request:
                aliases: ['client-cert-request']
                type: str
                description: Action based on client certificate request.
                choices: ['bypass', 'inspect', 'block']
            inspect_all:
                aliases: ['inspect-all']
                type: str
                description: Level of SSL inspection.
                choices: ['disable', 'certificate-inspection', 'deep-inspection']
            unsupported_ssl:
                aliases: ['unsupported-ssl']
                type: str
                description: Action based on the SSL encryption used being unsupported.
                choices: ['bypass', 'inspect', 'block']
            untrusted_cert:
                aliases: ['untrusted-cert']
                type: str
                description: Allow, ignore, or block the untrusted SSL session server certificate.
                choices: ['allow', 'block', 'ignore']
            invalid_server_cert:
                aliases: ['invalid-server-cert']
                type: str
                description: Allow or block the invalid SSL session server certificate.
                choices: ['allow', 'block']
            sni_server_cert_check:
                aliases: ['sni-server-cert-check']
                type: str
                description: Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                choices: ['disable', 'enable', 'strict']
            untrusted_server_cert:
                aliases: ['untrusted-server-cert']
                type: str
                description: Allow, ignore, or block the untrusted SSL session server certificate.
                choices: ['allow', 'block', 'ignore']
            cert_validation_failure:
                aliases: ['cert-validation-failure']
                type: str
                description: Action based on certificate validation failure.
                choices: ['allow', 'block', 'ignore']
            cert_validation_timeout:
                aliases: ['cert-validation-timeout']
                type: str
                description: Action based on certificate validation timeout.
                choices: ['allow', 'block', 'ignore']
            client_certificate:
                aliases: ['client-certificate']
                type: str
                description: Action based on received client certificate.
                choices: ['bypass', 'inspect', 'block', 'bypass-on-cert-req']
            expired_server_cert:
                aliases: ['expired-server-cert']
                type: str
                description: Action based on server certificate is expired.
                choices: ['allow', 'block', 'ignore']
            revoked_server_cert:
                aliases: ['revoked-server-cert']
                type: str
                description: Action based on server certificate is revoked.
                choices: ['allow', 'block', 'ignore']
            unsupported_ssl_cipher:
                aliases: ['unsupported-ssl-cipher']
                type: str
                description: Action based on the SSL cipher used being unsupported.
                choices: ['allow', 'block']
            unsupported_ssl_negotiation:
                aliases: ['unsupported-ssl-negotiation']
                type: str
                description: Action based on the SSL negotiation used being unsupported.
                choices: ['allow', 'block']
            cert_probe_failure:
                aliases: ['cert-probe-failure']
                type: str
                description: Action based on certificate probe failure.
                choices: ['block', 'allow']
            min_allowed_ssl_version:
                aliases: ['min-allowed-ssl-version']
                type: str
                description: Minimum SSL version to be allowed.
                choices: ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3']
            unsupported_ssl_version:
                aliases: ['unsupported-ssl-version']
                type: str
                description: Action based on the SSL version used being unsupported.
                choices: ['block', 'allow', 'inspect']
            encrypted_client_hello:
                aliases: ['encrypted-client-hello']
                type: str
                description: Block/allow session based on existence of encrypted-client-hello.
                choices: ['block', 'allow']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure SSL options.
      fortinet.fortimanager.fmgr_firewall_sslsshprofile_ssl:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        ssl_ssh_profile: <your own value>
        firewall_sslsshprofile_ssl:
          # allow_invalid_server_cert: <value in [disable, enable]>
          # client_cert_request: <value in [bypass, inspect, block]>
          # inspect_all: <value in [disable, certificate-inspection, deep-inspection]>
          # unsupported_ssl: <value in [bypass, inspect, block]>
          # untrusted_cert: <value in [allow, block, ignore]>
          # invalid_server_cert: <value in [allow, block]>
          # sni_server_cert_check: <value in [disable, enable, strict]>
          # untrusted_server_cert: <value in [allow, block, ignore]>
          # cert_validation_failure: <value in [allow, block, ignore]>
          # cert_validation_timeout: <value in [allow, block, ignore]>
          # client_certificate: <value in [bypass, inspect, block, ...]>
          # expired_server_cert: <value in [allow, block, ignore]>
          # revoked_server_cert: <value in [allow, block, ignore]>
          # unsupported_ssl_cipher: <value in [allow, block]>
          # unsupported_ssl_negotiation: <value in [allow, block]>
          # cert_probe_failure: <value in [block, allow]>
          # min_allowed_ssl_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          # unsupported_ssl_version: <value in [block, allow, inspect]>
          # encrypted_client_hello: <value in [block, allow]>
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
        '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl',
        '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'ssl-ssh-profile': {'type': 'str', 'api_name': 'ssl_ssh_profile'},
        'ssl_ssh_profile': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_sslsshprofile_ssl': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'allow-invalid-server-cert': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'client-cert-request': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'inspect-all': {'choices': ['disable', 'certificate-inspection', 'deep-inspection'], 'type': 'str'},
                'unsupported-ssl': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'untrusted-cert': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                'invalid-server-cert': {'v_range': [['6.2.0', '7.6.2']], 'choices': ['allow', 'block'], 'type': 'str'},
                'sni-server-cert-check': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable', 'strict'], 'type': 'str'},
                'untrusted-server-cert': {'v_range': [['6.2.0', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                'cert-validation-failure': {'v_range': [['6.4.0', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                'cert-validation-timeout': {'v_range': [['6.4.0', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                'client-certificate': {'v_range': [['6.4.0', '']], 'choices': ['bypass', 'inspect', 'block', 'bypass-on-cert-req'], 'type': 'str'},
                'expired-server-cert': {'v_range': [['6.4.0', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                'revoked-server-cert': {'v_range': [['6.4.0', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                'unsupported-ssl-cipher': {'v_range': [['6.4.0', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                'unsupported-ssl-negotiation': {'v_range': [['6.4.0', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                'cert-probe-failure': {'v_range': [['7.0.1', '']], 'choices': ['block', 'allow'], 'type': 'str'},
                'min-allowed-ssl-version': {'v_range': [['7.0.3', '']], 'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                'unsupported-ssl-version': {'v_range': [['7.0.1', '']], 'choices': ['block', 'allow', 'inspect'], 'type': 'str'},
                'encrypted-client-hello': {'v_range': [['7.4.3', '']], 'choices': ['block', 'allow'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_sslsshprofile_ssl'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('partial crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgr.process_partial_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
