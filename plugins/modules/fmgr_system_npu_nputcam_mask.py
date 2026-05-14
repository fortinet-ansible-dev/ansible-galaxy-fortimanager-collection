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
module: fmgr_system_npu_nputcam_mask
short_description: Mask fields of TCAM.
version_added: "2.4.0"
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
    npu-tcam:
        description: Deprecated, please use "npu_tcam"
        type: str
    npu_tcam:
        description: The parameter (npu-tcam) in requested url.
        type: str
    system_npu_nputcam_mask:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            df:
                type: str
                description: Tcam mask ip flag df.
                choices: ['disable', 'enable']
            dstip:
                type: str
                description: Tcam mask dst ipv4 address.
            dstipv6:
                type: str
                description: Tcam mask dst ipv6 address.
            dstmac:
                type: str
                description: Tcam mask dst macaddr.
            dstport:
                type: int
                description: Tcam mask L4 dst port.
            ethertype:
                type: str
                description: Tcam mask ethertype.
            ext_tag:
                aliases: ['ext-tag']
                type: str
                description: Tcam mask extension tag.
                choices: ['disable', 'enable']
            frag_off:
                aliases: ['frag-off']
                type: int
                description: Tcam data ip flag fragment offset.
            gen_buf_cnt:
                aliases: ['gen-buf-cnt']
                type: int
                description: Tcam mask gen info buffer count.
            gen_iv:
                aliases: ['gen-iv']
                type: str
                description: Tcam mask gen info iv.
                choices: ['invalid', 'valid']
            gen_l3_flags:
                aliases: ['gen-l3-flags']
                type: int
                description: Tcam mask gen info L3 flags.
            gen_l4_flags:
                aliases: ['gen-l4-flags']
                type: int
                description: Tcam mask gen info L4 flags.
            gen_pkt_ctrl:
                aliases: ['gen-pkt-ctrl']
                type: int
                description: Tcam mask gen info packet control.
            gen_pri:
                aliases: ['gen-pri']
                type: int
                description: Tcam mask gen info priority.
            gen_pri_v:
                aliases: ['gen-pri-v']
                type: str
                description: Tcam mask gen info priority valid.
                choices: ['invalid', 'valid']
            gen_tv:
                aliases: ['gen-tv']
                type: str
                description: Tcam mask gen info tv.
                choices: ['invalid', 'valid']
            ihl:
                type: int
                description: Tcam mask ipv4 IHL.
            ip4_id:
                aliases: ['ip4-id']
                type: int
                description: Tcam mask ipv4 id.
            ip6_fl:
                aliases: ['ip6-fl']
                type: int
                description: Tcam mask ipv6 flow label.
            ipver:
                type: int
                description: Tcam mask ip header version.
            l4_wd10:
                aliases: ['l4-wd10']
                type: int
                description: Tcam mask L4 word10.
            l4_wd11:
                aliases: ['l4-wd11']
                type: int
                description: Tcam mask L4 word11.
            l4_wd8:
                aliases: ['l4-wd8']
                type: int
                description: Tcam mask L4 word8.
            l4_wd9:
                aliases: ['l4-wd9']
                type: int
                description: Tcam mask L4 word9.
            mf:
                type: str
                description: Tcam mask ip flag mf.
                choices: ['disable', 'enable']
            protocol:
                type: int
                description: Tcam mask ip protocol.
            slink:
                type: int
                description: Tcam mask sublink.
            smac_change:
                aliases: ['smac-change']
                type: str
                description: Tcam mask source MAC change.
                choices: ['disable', 'enable']
            sp:
                type: int
                description: Tcam mask source port.
            src_cfi:
                aliases: ['src-cfi']
                type: str
                description: Tcam mask source cfi.
                choices: ['disable', 'enable']
            src_prio:
                aliases: ['src-prio']
                type: int
                description: Tcam mask source priority.
            src_updt:
                aliases: ['src-updt']
                type: str
                description: Tcam mask source update.
                choices: ['disable', 'enable']
            srcip:
                type: str
                description: Tcam mask src ipv4 address.
            srcipv6:
                type: str
                description: Tcam mask src ipv6 address.
            srcmac:
                type: str
                description: Tcam mask src macaddr.
            srcport:
                type: int
                description: Tcam mask L4 src port.
            svid:
                type: int
                description: Tcam mask source vid.
            tcp_ack:
                aliases: ['tcp-ack']
                type: str
                description: Tcam mask tcp flag ack.
                choices: ['disable', 'enable']
            tcp_cwr:
                aliases: ['tcp-cwr']
                type: str
                description: Tcam mask tcp flag cwr.
                choices: ['disable', 'enable']
            tcp_ece:
                aliases: ['tcp-ece']
                type: str
                description: Tcam mask tcp flag ece.
                choices: ['disable', 'enable']
            tcp_fin:
                aliases: ['tcp-fin']
                type: str
                description: Tcam mask tcp flag fin.
                choices: ['disable', 'enable']
            tcp_push:
                aliases: ['tcp-push']
                type: str
                description: Tcam mask tcp flag push.
                choices: ['disable', 'enable']
            tcp_rst:
                aliases: ['tcp-rst']
                type: str
                description: Tcam mask tcp flag rst.
                choices: ['disable', 'enable']
            tcp_syn:
                aliases: ['tcp-syn']
                type: str
                description: Tcam mask tcp flag syn.
                choices: ['disable', 'enable']
            tcp_urg:
                aliases: ['tcp-urg']
                type: str
                description: Tcam mask tcp flag urg.
                choices: ['disable', 'enable']
            tgt_cfi:
                aliases: ['tgt-cfi']
                type: str
                description: Tcam mask target cfi.
                choices: ['disable', 'enable']
            tgt_prio:
                aliases: ['tgt-prio']
                type: int
                description: Tcam mask target priority.
            tgt_updt:
                aliases: ['tgt-updt']
                type: str
                description: Tcam mask target port update.
                choices: ['disable', 'enable']
            tgt_v:
                aliases: ['tgt-v']
                type: str
                description: Tcam mask target valid.
                choices: ['invalid', 'valid']
            tos:
                type: int
                description: Tcam mask ip tos.
            tp:
                type: int
                description: Tcam mask target port.
            ttl:
                type: int
                description: Tcam mask ip ttl.
            tvid:
                type: int
                description: Tcam mask target vid.
            vdid:
                type: int
                description: Tcam mask vdom id.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Mask fields of TCAM.
      fortinet.fortimanager.fmgr_system_npu_nputcam_mask:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        npu_tcam: <your own value>
        system_npu_nputcam_mask:
          # df: <value in [disable, enable]>
          # dstip: <string>
          # dstipv6: <string>
          # dstmac: <string>
          # dstport: <integer>
          # ethertype: <string>
          # ext_tag: <value in [disable, enable]>
          # frag_off: <integer>
          # gen_buf_cnt: <integer>
          # gen_iv: <value in [invalid, valid]>
          # gen_l3_flags: <integer>
          # gen_l4_flags: <integer>
          # gen_pkt_ctrl: <integer>
          # gen_pri: <integer>
          # gen_pri_v: <value in [invalid, valid]>
          # gen_tv: <value in [invalid, valid]>
          # ihl: <integer>
          # ip4_id: <integer>
          # ip6_fl: <integer>
          # ipver: <integer>
          # l4_wd10: <integer>
          # l4_wd11: <integer>
          # l4_wd8: <integer>
          # l4_wd9: <integer>
          # mf: <value in [disable, enable]>
          # protocol: <integer>
          # slink: <integer>
          # smac_change: <value in [disable, enable]>
          # sp: <integer>
          # src_cfi: <value in [disable, enable]>
          # src_prio: <integer>
          # src_updt: <value in [disable, enable]>
          # srcip: <string>
          # srcipv6: <string>
          # srcmac: <string>
          # srcport: <integer>
          # svid: <integer>
          # tcp_ack: <value in [disable, enable]>
          # tcp_cwr: <value in [disable, enable]>
          # tcp_ece: <value in [disable, enable]>
          # tcp_fin: <value in [disable, enable]>
          # tcp_push: <value in [disable, enable]>
          # tcp_rst: <value in [disable, enable]>
          # tcp_syn: <value in [disable, enable]>
          # tcp_urg: <value in [disable, enable]>
          # tgt_cfi: <value in [disable, enable]>
          # tgt_prio: <integer>
          # tgt_updt: <value in [disable, enable]>
          # tgt_v: <value in [invalid, valid]>
          # tos: <integer>
          # tp: <integer>
          # ttl: <integer>
          # tvid: <integer>
          # vdid: <integer>
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
        '/pm/config/adom/{adom}/obj/system/npu/npu-tcam/{npu-tcam}/mask',
        '/pm/config/global/obj/system/npu/npu-tcam/{npu-tcam}/mask'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'npu-tcam': {'type': 'str', 'api_name': 'npu_tcam'},
        'npu_tcam': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_npu_nputcam_mask': {
            'type': 'dict', 'v_range': [['7.4.2', '']],
            'options': {
                'df': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dstip': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'dstipv6': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'dstmac': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'dstport': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'ethertype': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'ext-tag': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'frag-off': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'gen-buf-cnt': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'gen-iv': {'v_range': [['7.4.2', '']], 'choices': ['invalid', 'valid'], 'type': 'str'},
                'gen-l3-flags': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'gen-l4-flags': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'gen-pkt-ctrl': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'gen-pri': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'gen-pri-v': {'v_range': [['7.4.2', '']], 'choices': ['invalid', 'valid'], 'type': 'str'},
                'gen-tv': {'v_range': [['7.4.2', '']], 'choices': ['invalid', 'valid'], 'type': 'str'},
                'ihl': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'ip4-id': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'ip6-fl': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'ipver': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'l4-wd10': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'l4-wd11': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'l4-wd8': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'l4-wd9': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'mf': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'protocol': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'slink': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'smac-change': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sp': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'src-cfi': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'src-prio': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'src-updt': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'srcip': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'srcipv6': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'srcmac': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'srcport': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'svid': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'tcp-ack': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tcp-cwr': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tcp-ece': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tcp-fin': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tcp-push': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tcp-rst': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tcp-syn': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tcp-urg': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tgt-cfi': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tgt-prio': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'tgt-updt': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tgt-v': {'v_range': [['7.4.2', '']], 'choices': ['invalid', 'valid'], 'type': 'str'},
                'tos': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'tp': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'ttl': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'tvid': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'vdid': {'v_range': [['7.4.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_npu_nputcam_mask'),
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
