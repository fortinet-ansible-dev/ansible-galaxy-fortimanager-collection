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
module: fmgr_spamfilter_profile
short_description: Configure AntiSpam profiles.
version_added: "1.0.0"
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
    spamfilter_profile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Comment.
            external:
                type: str
                description: Enable/disable external Email inspection.
                choices: ['disable', 'enable']
            flow_based:
                aliases: ['flow-based']
                type: str
                description: Enable/disable flow-based spam filtering.
                choices: ['disable', 'enable']
            name:
                type: str
                description: Profile name.
                required: true
            options:
                type: list
                elements: str
                description: Options.
                choices: ['bannedword', 'spamemailbwl', 'spamfsip', 'spamfssubmit',
                          'spamfschksum', 'spamfsurl', 'spamhelodns', 'spamipbwl', 'spamraddrdns',
                          'spamrbl', 'spamhdrcheck', 'spamfsphish', 'spambwl']
            replacemsg_group:
                aliases: ['replacemsg-group']
                type: str
                description: Replacement message group.
            spam_bwl_table:
                aliases: ['spam-bwl-table']
                type: str
                description: Anti-spam black/white list table ID.
            spam_bword_table:
                aliases: ['spam-bword-table']
                type: str
                description: Anti-spam banned word table ID.
            spam_bword_threshold:
                aliases: ['spam-bword-threshold']
                type: int
                description: Spam banned word threshold.
            spam_filtering:
                aliases: ['spam-filtering']
                type: str
                description: Enable/disable spam filtering.
                choices: ['disable', 'enable']
            spam_iptrust_table:
                aliases: ['spam-iptrust-table']
                type: str
                description: Anti-spam IP trust table ID.
            spam_log:
                aliases: ['spam-log']
                type: str
                description: Enable/disable spam logging for email filtering.
                choices: ['disable', 'enable']
            spam_log_fortiguard_response:
                aliases: ['spam-log-fortiguard-response']
                type: str
                description: Enable/disable logging FortiGuard spam response.
                choices: ['disable', 'enable']
            spam_mheader_table:
                aliases: ['spam-mheader-table']
                type: str
                description: Anti-spam MIME header table ID.
            spam_rbl_table:
                aliases: ['spam-rbl-table']
                type: str
                description: Anti-spam DNSBL table ID.
            gmail:
                type: dict
                description: Gmail.
                suboptions:
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices: ['disable', 'enable']
            imap:
                type: dict
                description: Imap.
                suboptions:
                    action:
                        type: str
                        description: Action for spam email.
                        choices: ['pass', 'tag']
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices: ['disable', 'enable']
                    tag_msg:
                        aliases: ['tag-msg']
                        type: str
                        description: Subject text or header added to spam email.
                    tag_type:
                        aliases: ['tag-type']
                        type: list
                        elements: str
                        description: Tag subject or header for spam email.
                        choices: ['subject', 'header', 'spaminfo']
            mapi:
                type: dict
                description: Mapi.
                suboptions:
                    action:
                        type: str
                        description: Action for spam email.
                        choices: ['pass', 'discard']
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices: ['disable', 'enable']
            msn_hotmail:
                aliases: ['msn-hotmail']
                type: dict
                description: Msn hotmail.
                suboptions:
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices: ['disable', 'enable']
            pop3:
                type: dict
                description: Pop3.
                suboptions:
                    action:
                        type: str
                        description: Action for spam email.
                        choices: ['pass', 'tag']
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices: ['disable', 'enable']
                    tag_msg:
                        aliases: ['tag-msg']
                        type: str
                        description: Subject text or header added to spam email.
                    tag_type:
                        aliases: ['tag-type']
                        type: list
                        elements: str
                        description: Tag subject or header for spam email.
                        choices: ['subject', 'header', 'spaminfo']
            smtp:
                type: dict
                description: Smtp.
                suboptions:
                    action:
                        type: str
                        description: Action for spam email.
                        choices: ['pass', 'tag', 'discard']
                    hdrip:
                        type: str
                        description: Enable/disable SMTP email header IP checks for spamfsip, spamrbl and spambwl filters.
                        choices: ['disable', 'enable']
                    local_override:
                        aliases: ['local-override']
                        type: str
                        description: Enable/disable local filter to override SMTP remote check result.
                        choices: ['disable', 'enable']
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices: ['disable', 'enable']
                    tag_msg:
                        aliases: ['tag-msg']
                        type: str
                        description: Subject text or header added to spam email.
                    tag_type:
                        aliases: ['tag-type']
                        type: list
                        elements: str
                        description: Tag subject or header for spam email.
                        choices: ['subject', 'header', 'spaminfo']
            yahoo_mail:
                aliases: ['yahoo-mail']
                type: dict
                description: Yahoo mail.
                suboptions:
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure AntiSpam profiles.
      fortinet.fortimanager.fmgr_spamfilter_profile:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        spamfilter_profile:
          name: "your value" # Required variable, string
          # comment: <string>
          # external: <value in [disable, enable]>
          # flow_based: <value in [disable, enable]>
          # options: ["bannedword", "spamemailbwl", "spamfsip", "spamfssubmit", "spamfschksum",
          #           "spamfsurl", "spamhelodns", "spamipbwl", "spamraddrdns", "spamrbl",
          #           "spamhdrcheck", "spamfsphish", "spambwl"]
          # replacemsg_group: <string>
          # spam_bwl_table: <string>
          # spam_bword_table: <string>
          # spam_bword_threshold: <integer>
          # spam_filtering: <value in [disable, enable]>
          # spam_iptrust_table: <string>
          # spam_log: <value in [disable, enable]>
          # spam_log_fortiguard_response: <value in [disable, enable]>
          # spam_mheader_table: <string>
          # spam_rbl_table: <string>
          # gmail:
          #   log: <value in [disable, enable]>
          # imap:
          #   action: <value in [pass, tag]>
          #   log: <value in [disable, enable]>
          #   tag_msg: <string>
          #   tag_type: ["subject", "header", "spaminfo"]
          # mapi:
          #   action: <value in [pass, discard]>
          #   log: <value in [disable, enable]>
          # msn_hotmail:
          #   log: <value in [disable, enable]>
          # pop3:
          #   action: <value in [pass, tag]>
          #   log: <value in [disable, enable]>
          #   tag_msg: <string>
          #   tag_type: ["subject", "header", "spaminfo"]
          # smtp:
          #   action: <value in [pass, tag, discard]>
          #   hdrip: <value in [disable, enable]>
          #   local_override: <value in [disable, enable]>
          #   log: <value in [disable, enable]>
          #   tag_msg: <string>
          #   tag_type: ["subject", "header", "spaminfo"]
          # yahoo_mail:
          #   log: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/spamfilter/profile',
        '/pm/config/global/obj/spamfilter/profile'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'spamfilter_profile': {
            'type': 'dict', 'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']],
            'options': {
                'comment': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'str'},
                'external': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'flow-based': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'required': True, 'type': 'str'},
                'options': {
                    'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']],
                    'type': 'list',
                    'choices': [
                        'bannedword', 'spamemailbwl', 'spamfsip', 'spamfssubmit', 'spamfschksum', 'spamfsurl', 'spamhelodns', 'spamipbwl',
                        'spamraddrdns', 'spamrbl', 'spamhdrcheck', 'spamfsphish', 'spambwl'
                    ],
                    'elements': 'str'
                },
                'replacemsg-group': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'str'},
                'spam-bwl-table': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'str'},
                'spam-bword-table': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'str'},
                'spam-bword-threshold': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'int'},
                'spam-filtering': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'spam-iptrust-table': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'str'},
                'spam-log': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'spam-log-fortiguard-response': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'spam-mheader-table': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'str'},
                'spam-rbl-table': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'str'},
                'gmail': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1'], ['7.4.8', '7.4.10']],
                    'type': 'dict',
                    'options': {
                        'log': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1'], ['7.4.8', '7.4.10']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        }
                    }
                },
                'imap': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1'], ['7.4.8', '7.4.10']],
                    'type': 'dict',
                    'options': {
                        'action': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1'], ['7.4.8', '7.4.10']], 'choices': ['pass', 'tag'], 'type': 'str'},
                        'log': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1'], ['7.4.8', '7.4.10']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'tag-msg': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'str'},
                        'tag-type': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1'], ['7.4.8', '7.4.10']],
                            'type': 'list',
                            'choices': ['subject', 'header', 'spaminfo'],
                            'elements': 'str'
                        }
                    }
                },
                'mapi': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1'], ['7.4.8', '7.4.10']],
                    'type': 'dict',
                    'options': {
                        'action': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1'], ['7.4.8', '7.4.10']],
                            'choices': ['pass', 'discard'],
                            'type': 'str'
                        },
                        'log': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1'], ['7.4.8', '7.4.10']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        }
                    }
                },
                'msn-hotmail': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1'], ['7.4.8', '7.4.10']],
                    'type': 'dict',
                    'options': {
                        'log': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1'], ['7.4.8', '7.4.10']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        }
                    }
                },
                'pop3': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1'], ['7.4.8', '7.4.10']],
                    'type': 'dict',
                    'options': {
                        'action': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1'], ['7.4.8', '7.4.10']], 'choices': ['pass', 'tag'], 'type': 'str'},
                        'log': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1'], ['7.4.8', '7.4.10']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'tag-msg': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'str'},
                        'tag-type': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1'], ['7.4.8', '7.4.10']],
                            'type': 'list',
                            'choices': ['subject', 'header', 'spaminfo'],
                            'elements': 'str'
                        }
                    }
                },
                'smtp': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1'], ['7.4.8', '7.4.10']],
                    'type': 'dict',
                    'options': {
                        'action': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1'], ['7.4.8', '7.4.10']],
                            'choices': ['pass', 'tag', 'discard'],
                            'type': 'str'
                        },
                        'hdrip': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1'], ['7.4.8', '7.4.10']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'local-override': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1'], ['7.4.8', '7.4.10']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'log': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1'], ['7.4.8', '7.4.10']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'tag-msg': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'str'},
                        'tag-type': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1'], ['7.4.8', '7.4.10']],
                            'type': 'list',
                            'choices': ['subject', 'header', 'spaminfo'],
                            'elements': 'str'
                        }
                    }
                },
                'yahoo-mail': {
                    'v_range': [['6.2.8', '6.2.13']],
                    'type': 'dict',
                    'options': {'log': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'}}
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'spamfilter_profile'),
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
