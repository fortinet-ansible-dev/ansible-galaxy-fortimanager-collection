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
module: fmgr_authentication_scheme
short_description: Configure Authentication Schemes.
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
    authentication_scheme:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            domain_controller:
                aliases: ['domain-controller']
                type: str
                description: Domain controller setting.
            fsso_agent_for_ntlm:
                aliases: ['fsso-agent-for-ntlm']
                type: str
                description: FSSO agent to use for NTLM authentication.
            fsso_guest:
                aliases: ['fsso-guest']
                type: str
                description: Enable/disable user fsso-guest authentication
                choices: ['disable', 'enable']
            kerberos_keytab:
                aliases: ['kerberos-keytab']
                type: str
                description: Kerberos keytab setting.
            method:
                type: list
                elements: str
                description: Authentication methods
                choices: ['ntlm', 'basic', 'digest', 'form', 'negotiate', 'fsso', 'rsso',
                          'ssh-publickey', 'saml', 'cert', 'x-auth-user', 'saml-sp', 'entra-sso',
                          'ztna-relay', 'oidc']
            name:
                type: str
                description: Authentication scheme name.
                required: true
            negotiate_ntlm:
                aliases: ['negotiate-ntlm']
                type: str
                description: Enable/disable negotiate authentication for NTLM
                choices: ['disable', 'enable']
            require_tfa:
                aliases: ['require-tfa']
                type: str
                description: Enable/disable two-factor authentication
                choices: ['disable', 'enable']
            ssh_ca:
                aliases: ['ssh-ca']
                type: str
                description: SSH CA name.
            user_database:
                aliases: ['user-database']
                type: raw
                description: (list or str) Authentication server to contain user information; local
            ems_device_owner:
                aliases: ['ems-device-owner']
                type: str
                description: Enable/disable SSH public-key authentication with device owner
                choices: ['disable', 'enable']
            saml_server:
                aliases: ['saml-server']
                type: str
                description: SAML configuration.
            saml_timeout:
                aliases: ['saml-timeout']
                type: int
                description: SAML authentication timeout in seconds.
            user_cert:
                aliases: ['user-cert']
                type: str
                description: Enable/disable authentication with user certificate
                choices: ['disable', 'enable']
            external_idp:
                aliases: ['external-idp']
                type: raw
                description: (list) External identity provider configuration.
            digest_algo:
                aliases: ['digest-algo']
                type: list
                elements: str
                description: Digest Authentication Algorithms.
                choices: ['md5', 'sha-256']
            group_attr_type:
                aliases: ['group-attr-type']
                type: str
                description: Group attribute type used to match SCIM groups
                choices: ['display-name', 'external-id']
            search_all_ldap_databases:
                aliases: ['search-all-ldap-databases']
                type: str
                description: Search all ldap databases.
                choices: ['disable', 'enable']
            saml_idp_portal:
                aliases: ['saml-idp-portal']
                type: str
                description: External SAML-IDP authentication Portal URL.
            oidc_server:
                aliases: ['oidc-server']
                type: raw
                description: (list) Oidc server.
            oidc_timeout:
                aliases: ['oidc-timeout']
                type: int
                description: Oidc timeout.
            digest_rfc2069:
                aliases: ['digest-rfc2069']
                type: str
                description: Enable/disable support for the deprecated RFC2069 Digest Client
                choices: ['disable', 'enable']
            auth_user_header:
                aliases: ['auth-user-header']
                type: str
                description: Auth user header.
            captcha:
                type: str
                description: Captcha.
                choices: ['disable', 'enable']
            captcha_secret_key:
                aliases: ['captcha-secret-key']
                type: str
                description: Captcha secret key.
            captcha_site_key:
                aliases: ['captcha-site-key']
                type: str
                description: Captcha site key.
            captcha_vendor:
                aliases: ['captcha-vendor']
                type: str
                description: Captcha vendor.
                choices: ['google-recaptcha-v2-checkbox', 'google-recaptcha-v2-invisible',
                          'google-recaptcha-v3', 'cloudflare-turnstile']
            cert_http_header:
                aliases: ['cert-http-header']
                type: str
                description: Enable/disable authentication with user certificate in Client-Cert HTTP header
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure Authentication Schemes.
      fortinet.fortimanager.fmgr_authentication_scheme:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        authentication_scheme:
          name: "your value" # Required variable, string
          # domain_controller: <string>
          # fsso_agent_for_ntlm: <string>
          # fsso_guest: <value in [disable, enable]>
          # kerberos_keytab: <string>
          # method: ["ntlm", "basic", "digest", "form", "negotiate", "fsso", "rsso",
          #          "ssh-publickey", "saml", "cert", "x-auth-user", "saml-sp", "entra-sso",
          #          "ztna-relay", "oidc"]
          # negotiate_ntlm: <value in [disable, enable]>
          # require_tfa: <value in [disable, enable]>
          # ssh_ca: <string>
          # user_database: <list or string>
          # ems_device_owner: <value in [disable, enable]>
          # saml_server: <string>
          # saml_timeout: <integer>
          # user_cert: <value in [disable, enable]>
          # external_idp: <list or string>
          # digest_algo: ["md5", "sha-256"]
          # group_attr_type: <value in [display-name, external-id]>
          # search_all_ldap_databases: <value in [disable, enable]>
          # saml_idp_portal: <string>
          # oidc_server: <list or string>
          # oidc_timeout: <integer>
          # digest_rfc2069: <value in [disable, enable]>
          # auth_user_header: <string>
          # captcha: <value in [disable, enable]>
          # captcha_secret_key: <string>
          # captcha_site_key: <string>
          # captcha_vendor: <value in [google-recaptcha-v2-checkbox, google-recaptcha-v2-invisible, google-recaptcha-v3, ...]>
          # cert_http_header: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/authentication/scheme',
        '/pm/config/global/obj/authentication/scheme'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'authentication_scheme': {
            'type': 'dict', 'v_range': [['6.2.1', '']],
            'options': {
                'domain-controller': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'fsso-agent-for-ntlm': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'fsso-guest': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'kerberos-keytab': {'v_range': [['6.2.1', '']], 'no_log': True, 'type': 'str'},
                'method': {
                    'v_range': [['6.2.1', '']],
                    'type': 'list',
                    'choices': [
                        'ntlm', 'basic', 'digest', 'form', 'negotiate', 'fsso', 'rsso', 'ssh-publickey', 'saml', 'cert', 'x-auth-user', 'saml-sp',
                        'entra-sso', 'ztna-relay', 'oidc'
                    ],
                    'elements': 'str'
                },
                'name': {'v_range': [['6.2.1', '']], 'required': True, 'type': 'str'},
                'negotiate-ntlm': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'require-tfa': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssh-ca': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'user-database': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'ems-device-owner': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'saml-server': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'saml-timeout': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'user-cert': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'external-idp': {'v_range': [['7.6.2', '']], 'type': 'raw'},
                'digest-algo': {'v_range': [['7.6.3', '']], 'type': 'list', 'choices': ['md5', 'sha-256'], 'elements': 'str'},
                'group-attr-type': {'v_range': [['7.6.3', '']], 'choices': ['display-name', 'external-id'], 'type': 'str'},
                'search-all-ldap-databases': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'saml-idp-portal': {'v_range': [['7.4.8', '7.4.10']], 'type': 'str'},
                'oidc-server': {'v_range': [['7.6.4', '']], 'type': 'raw'},
                'oidc-timeout': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'digest-rfc2069': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-user-header': {'v_range': [['7.4.9', '7.4.10'], ['7.6.5', '']], 'type': 'str'},
                'captcha': {'v_range': [['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'captcha-secret-key': {'v_range': [['7.6.5', '']], 'no_log': True, 'type': 'str'},
                'captcha-site-key': {'v_range': [['7.6.5', '']], 'no_log': True, 'type': 'str'},
                'captcha-vendor': {
                    'v_range': [['7.6.5', '']],
                    'choices': ['google-recaptcha-v2-checkbox', 'google-recaptcha-v2-invisible', 'google-recaptcha-v3', 'cloudflare-turnstile'],
                    'type': 'str'
                },
                'cert-http-header': {'v_range': [['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'authentication_scheme'),
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
