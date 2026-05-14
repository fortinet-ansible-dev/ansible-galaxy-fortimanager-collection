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
module: fmgr_firewall_gtp_messageratelimit
short_description: Message rate limiting.
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
    gtp:
        description: The parameter (gtp) in requested url.
        type: str
        required: true
    firewall_gtp_messageratelimit:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            create_aa_pdp_request:
                aliases: ['create-aa-pdp-request']
                type: int
                description: Rate limit for create AA PDP context request
            create_aa_pdp_response:
                aliases: ['create-aa-pdp-response']
                type: int
                description: Rate limit for create AA PDP context response
            create_mbms_request:
                aliases: ['create-mbms-request']
                type: int
                description: Rate limit for create MBMS context request
            create_mbms_response:
                aliases: ['create-mbms-response']
                type: int
                description: Rate limit for create MBMS context response
            create_pdp_request:
                aliases: ['create-pdp-request']
                type: int
                description: Rate limit for create PDP context request
            create_pdp_response:
                aliases: ['create-pdp-response']
                type: int
                description: Rate limit for create PDP context response
            delete_aa_pdp_request:
                aliases: ['delete-aa-pdp-request']
                type: int
                description: Rate limit for delete AA PDP context request
            delete_aa_pdp_response:
                aliases: ['delete-aa-pdp-response']
                type: int
                description: Rate limit for delete AA PDP context response
            delete_mbms_request:
                aliases: ['delete-mbms-request']
                type: int
                description: Rate limit for delete MBMS context request
            delete_mbms_response:
                aliases: ['delete-mbms-response']
                type: int
                description: Rate limit for delete MBMS context response
            delete_pdp_request:
                aliases: ['delete-pdp-request']
                type: int
                description: Rate limit for delete PDP context request
            delete_pdp_response:
                aliases: ['delete-pdp-response']
                type: int
                description: Rate limit for delete PDP context response
            echo_reponse:
                aliases: ['echo-reponse']
                type: int
                description: Rate limit for echo response
            echo_request:
                aliases: ['echo-request']
                type: int
                description: Rate limit for echo requests
            error_indication:
                aliases: ['error-indication']
                type: int
                description: Rate limit for error indication
            failure_report_request:
                aliases: ['failure-report-request']
                type: int
                description: Rate limit for failure report request
            failure_report_response:
                aliases: ['failure-report-response']
                type: int
                description: Rate limit for failure report response
            fwd_reloc_complete_ack:
                aliases: ['fwd-reloc-complete-ack']
                type: int
                description: Rate limit for forward relocation complete acknowledge
            fwd_relocation_complete:
                aliases: ['fwd-relocation-complete']
                type: int
                description: Rate limit for forward relocation complete
            fwd_relocation_request:
                aliases: ['fwd-relocation-request']
                type: int
                description: Rate limit for forward relocation request
            fwd_relocation_response:
                aliases: ['fwd-relocation-response']
                type: int
                description: Rate limit for forward relocation response
            fwd_srns_context:
                aliases: ['fwd-srns-context']
                type: int
                description: Rate limit for forward SRNS context
            fwd_srns_context_ack:
                aliases: ['fwd-srns-context-ack']
                type: int
                description: Rate limit for forward SRNS context acknowledge
            g_pdu:
                aliases: ['g-pdu']
                type: int
                description: Rate limit for G-PDU
            identification_request:
                aliases: ['identification-request']
                type: int
                description: Rate limit for identification request
            identification_response:
                aliases: ['identification-response']
                type: int
                description: Rate limit for identification response
            mbms_de_reg_request:
                aliases: ['mbms-de-reg-request']
                type: int
                description: Rate limit for MBMS de-registration request
            mbms_de_reg_response:
                aliases: ['mbms-de-reg-response']
                type: int
                description: Rate limit for MBMS de-registration response
            mbms_notify_rej_request:
                aliases: ['mbms-notify-rej-request']
                type: int
                description: Rate limit for MBMS notification reject request
            mbms_notify_rej_response:
                aliases: ['mbms-notify-rej-response']
                type: int
                description: Rate limit for MBMS notification reject response
            mbms_notify_request:
                aliases: ['mbms-notify-request']
                type: int
                description: Rate limit for MBMS notification request
            mbms_notify_response:
                aliases: ['mbms-notify-response']
                type: int
                description: Rate limit for MBMS notification response
            mbms_reg_request:
                aliases: ['mbms-reg-request']
                type: int
                description: Rate limit for MBMS registration request
            mbms_reg_response:
                aliases: ['mbms-reg-response']
                type: int
                description: Rate limit for MBMS registration response
            mbms_ses_start_request:
                aliases: ['mbms-ses-start-request']
                type: int
                description: Rate limit for MBMS session start request
            mbms_ses_start_response:
                aliases: ['mbms-ses-start-response']
                type: int
                description: Rate limit for MBMS session start response
            mbms_ses_stop_request:
                aliases: ['mbms-ses-stop-request']
                type: int
                description: Rate limit for MBMS session stop request
            mbms_ses_stop_response:
                aliases: ['mbms-ses-stop-response']
                type: int
                description: Rate limit for MBMS session stop response
            note_ms_request:
                aliases: ['note-ms-request']
                type: int
                description: Rate limit for note MS GPRS present request
            note_ms_response:
                aliases: ['note-ms-response']
                type: int
                description: Rate limit for note MS GPRS present response
            pdu_notify_rej_request:
                aliases: ['pdu-notify-rej-request']
                type: int
                description: Rate limit for PDU notify reject request
            pdu_notify_rej_response:
                aliases: ['pdu-notify-rej-response']
                type: int
                description: Rate limit for PDU notify reject response
            pdu_notify_request:
                aliases: ['pdu-notify-request']
                type: int
                description: Rate limit for PDU notify request
            pdu_notify_response:
                aliases: ['pdu-notify-response']
                type: int
                description: Rate limit for PDU notify response
            ran_info:
                aliases: ['ran-info']
                type: int
                description: Rate limit for RAN information relay
            relocation_cancel_request:
                aliases: ['relocation-cancel-request']
                type: int
                description: Rate limit for relocation cancel request
            relocation_cancel_response:
                aliases: ['relocation-cancel-response']
                type: int
                description: Rate limit for relocation cancel response
            send_route_request:
                aliases: ['send-route-request']
                type: int
                description: Rate limit for send routing information for GPRS request
            send_route_response:
                aliases: ['send-route-response']
                type: int
                description: Rate limit for send routing information for GPRS response
            sgsn_context_ack:
                aliases: ['sgsn-context-ack']
                type: int
                description: Rate limit for SGSN context acknowledgement
            sgsn_context_request:
                aliases: ['sgsn-context-request']
                type: int
                description: Rate limit for SGSN context request
            sgsn_context_response:
                aliases: ['sgsn-context-response']
                type: int
                description: Rate limit for SGSN context response
            support_ext_hdr_notify:
                aliases: ['support-ext-hdr-notify']
                type: int
                description: Rate limit for support extension headers notification
            update_mbms_request:
                aliases: ['update-mbms-request']
                type: int
                description: Rate limit for update MBMS context request
            update_mbms_response:
                aliases: ['update-mbms-response']
                type: int
                description: Rate limit for update MBMS context response
            update_pdp_request:
                aliases: ['update-pdp-request']
                type: int
                description: Rate limit for update PDP context request
            update_pdp_response:
                aliases: ['update-pdp-response']
                type: int
                description: Rate limit for update PDP context response
            version_not_support:
                aliases: ['version-not-support']
                type: int
                description: Rate limit for version not supported
            echo_response:
                aliases: ['echo-response']
                type: int
                description: Rate limit for echo response
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Message rate limiting.
      fortinet.fortimanager.fmgr_firewall_gtp_messageratelimit:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        gtp: <your own value>
        firewall_gtp_messageratelimit:
          # create_aa_pdp_request: <integer>
          # create_aa_pdp_response: <integer>
          # create_mbms_request: <integer>
          # create_mbms_response: <integer>
          # create_pdp_request: <integer>
          # create_pdp_response: <integer>
          # delete_aa_pdp_request: <integer>
          # delete_aa_pdp_response: <integer>
          # delete_mbms_request: <integer>
          # delete_mbms_response: <integer>
          # delete_pdp_request: <integer>
          # delete_pdp_response: <integer>
          # echo_reponse: <integer>
          # echo_request: <integer>
          # error_indication: <integer>
          # failure_report_request: <integer>
          # failure_report_response: <integer>
          # fwd_reloc_complete_ack: <integer>
          # fwd_relocation_complete: <integer>
          # fwd_relocation_request: <integer>
          # fwd_relocation_response: <integer>
          # fwd_srns_context: <integer>
          # fwd_srns_context_ack: <integer>
          # g_pdu: <integer>
          # identification_request: <integer>
          # identification_response: <integer>
          # mbms_de_reg_request: <integer>
          # mbms_de_reg_response: <integer>
          # mbms_notify_rej_request: <integer>
          # mbms_notify_rej_response: <integer>
          # mbms_notify_request: <integer>
          # mbms_notify_response: <integer>
          # mbms_reg_request: <integer>
          # mbms_reg_response: <integer>
          # mbms_ses_start_request: <integer>
          # mbms_ses_start_response: <integer>
          # mbms_ses_stop_request: <integer>
          # mbms_ses_stop_response: <integer>
          # note_ms_request: <integer>
          # note_ms_response: <integer>
          # pdu_notify_rej_request: <integer>
          # pdu_notify_rej_response: <integer>
          # pdu_notify_request: <integer>
          # pdu_notify_response: <integer>
          # ran_info: <integer>
          # relocation_cancel_request: <integer>
          # relocation_cancel_response: <integer>
          # send_route_request: <integer>
          # send_route_response: <integer>
          # sgsn_context_ack: <integer>
          # sgsn_context_request: <integer>
          # sgsn_context_response: <integer>
          # support_ext_hdr_notify: <integer>
          # update_mbms_request: <integer>
          # update_mbms_response: <integer>
          # update_pdp_request: <integer>
          # update_pdp_response: <integer>
          # version_not_support: <integer>
          # echo_response: <integer>
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
        '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/message-rate-limit',
        '/pm/config/global/obj/firewall/gtp/{gtp}/message-rate-limit'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'gtp': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_gtp_messageratelimit': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'create-aa-pdp-request': {'type': 'int'},
                'create-aa-pdp-response': {'type': 'int'},
                'create-mbms-request': {'type': 'int'},
                'create-mbms-response': {'type': 'int'},
                'create-pdp-request': {'type': 'int'},
                'create-pdp-response': {'type': 'int'},
                'delete-aa-pdp-request': {'type': 'int'},
                'delete-aa-pdp-response': {'type': 'int'},
                'delete-mbms-request': {'type': 'int'},
                'delete-mbms-response': {'type': 'int'},
                'delete-pdp-request': {'type': 'int'},
                'delete-pdp-response': {'type': 'int'},
                'echo-reponse': {'type': 'int'},
                'echo-request': {'type': 'int'},
                'error-indication': {'type': 'int'},
                'failure-report-request': {'type': 'int'},
                'failure-report-response': {'type': 'int'},
                'fwd-reloc-complete-ack': {'type': 'int'},
                'fwd-relocation-complete': {'type': 'int'},
                'fwd-relocation-request': {'type': 'int'},
                'fwd-relocation-response': {'type': 'int'},
                'fwd-srns-context': {'type': 'int'},
                'fwd-srns-context-ack': {'type': 'int'},
                'g-pdu': {'type': 'int'},
                'identification-request': {'type': 'int'},
                'identification-response': {'type': 'int'},
                'mbms-de-reg-request': {'type': 'int'},
                'mbms-de-reg-response': {'type': 'int'},
                'mbms-notify-rej-request': {'type': 'int'},
                'mbms-notify-rej-response': {'type': 'int'},
                'mbms-notify-request': {'type': 'int'},
                'mbms-notify-response': {'type': 'int'},
                'mbms-reg-request': {'type': 'int'},
                'mbms-reg-response': {'type': 'int'},
                'mbms-ses-start-request': {'type': 'int'},
                'mbms-ses-start-response': {'type': 'int'},
                'mbms-ses-stop-request': {'type': 'int'},
                'mbms-ses-stop-response': {'type': 'int'},
                'note-ms-request': {'type': 'int'},
                'note-ms-response': {'type': 'int'},
                'pdu-notify-rej-request': {'type': 'int'},
                'pdu-notify-rej-response': {'type': 'int'},
                'pdu-notify-request': {'type': 'int'},
                'pdu-notify-response': {'type': 'int'},
                'ran-info': {'type': 'int'},
                'relocation-cancel-request': {'type': 'int'},
                'relocation-cancel-response': {'type': 'int'},
                'send-route-request': {'type': 'int'},
                'send-route-response': {'type': 'int'},
                'sgsn-context-ack': {'type': 'int'},
                'sgsn-context-request': {'type': 'int'},
                'sgsn-context-response': {'type': 'int'},
                'support-ext-hdr-notify': {'type': 'int'},
                'update-mbms-request': {'type': 'int'},
                'update-mbms-response': {'type': 'int'},
                'update-pdp-request': {'type': 'int'},
                'update-pdp-response': {'type': 'int'},
                'version-not-support': {'type': 'int'},
                'echo-response': {'v_range': [['7.4.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_gtp_messageratelimit'),
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
