
import argparse
import ConfigParser
import json
from libutils import get_logical_switch, get_vdsportgroupid, connect_to_vc, check_for_parameters
from libutils import get_datacentermoid, get_edgeresourcepoolmoid, get_edge, get_datastoremoid, get_networkid
from tabulate import tabulate
from nsxramlclient.client import NsxClient
from argparse import RawTextHelpFormatter
from pkg_resources import resource_filename
# PEZ Changes
import xml.etree.ElementTree as ET

#PEZ Changes
def add_nat_rule(client_session, esg_name, nat_type, nat_vnic, original_ip, translated_ip, original_port, translated_port, protocol, description):
#def add_nat_rule(client_session, esg_name, nat_type, original_ip, translated_ip):
    """
    This function adds an NAT to an ESG

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for Load Balancing
    :type original_ip: str
    :param original_ip: Original IP Address
    :type translated_ip: str
    :param translated_ip: Translated IP Address
    :return: Returns the Object Id of the newly created NAT Rule and None if the ESG was
             not found in NSX
    :rtype: str
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    # PEZ Changes
    nat_dict = client_session.extract_resource_body_example('edgeNatRules', 'create')
    #{'natRules': {'natRule': {'vnic': None, 'protocol': None, 'description': None,
    #'loggingEnabled': None, 'translatedAddress': None, 'enabled': None, 'originalAddress': None,
    #'translatedPort': None, 'action': None, 'originalPort': None}}}

    nat_dict['natRules']['natRule']['vnic'] = nat_vnic
    nat_dict['natRules']['natRule']['protocol'] = protocol
    nat_dict['natRules']['natRule']['description'] = description
    nat_dict['natRules']['natRule']['loggingEnabled'] = 'true'
    # nat_dict['natRules']['natRule']['vnic'] = '0'
    # nat_dict['natRules']['natRule']['protocol'] = 'any'
    # nat_dict['natRules']['natRule']['description'] = ''
    # nat_dict['natRules']['natRule']['loggingEnabled'] = 'false'
    nat_dict['natRules']['natRule']['translatedAddress'] = translated_ip
    nat_dict['natRules']['natRule']['enabled'] = 'true'
    nat_dict['natRules']['natRule']['originalAddress'] = original_ip
    nat_dict['natRules']['natRule']['action'] = nat_type
    nat_dict['natRules']['natRule']['translatedPort'] = translated_port
    nat_dict['natRules']['natRule']['originalPort'] = original_port

    result = client_session.create('edgeNatRules', uri_parameters={'edgeId': esg_id},
                                   request_body_dict=nat_dict)
    if result['status'] != 201:
        return None
    else:
        return result['objectId']

def _add_nat_rule(client_session, **kwargs):
    # PEZ Changes
    needed_params = ['esg_name', 'nat_type', 'nat_vnic', 'original_ip', 'translated_ip', 'original_port', 'translated_port', 'protocol', 'description' ]
    if not check_for_parameters(needed_params, kwargs):
        return None

    # PEZ Changes
    result = add_nat_rule(client_session, kwargs['esg_name'], kwargs['nat_type'], kwargs['nat_vnic'], kwargs['original_ip'], kwargs['translated_ip'], kwargs['original_port'],kwargs['translated_port'], kwargs['protocol'], kwargs['description'])

    if result and kwargs['verbose']:
        print result
    elif result:
        print '{} Rule created on edge {} for {} -> {}'.format(kwargs['nat_type'].upper(), kwargs['esg_name'], kwargs['original_ip'], kwargs['translated_ip'])
    else:
        print '{} Rule creation failed on edge {} for {} -> {}'.format(kwargs['nat_type'].upper(), kwargs['esg_name'], kwargs['original_ip'], kwargs['translated_ip'])

# PEZ Changes
# New function to search NAT rules by IP
def get_nat_rules_with_ip(client_session, esg_name, original_ip, translated_ip):
    """
    This function returns all NAT rules on an esg with the specified original and translated IPs
    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for Load Balancing
    :type original_ip: str
    :param esg_name: The original IP in the NAT rule
    :type translated_ip: str
    :param esg_name: The translated IP in the NAT rule
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    result = client_session.read('edgeNat', uri_parameters={'edgeId': esg_id})

    if result['status'] != 200:
        return None
    else:
        rules = []
        nats = result['body']['nat']['natRules']['natRule']

        for i in nats:
            if original_ip in i['originalAddress'] and translated_ip in i['translatedAddress'] and i['ruleType'] == 'user':
                rules.append(i['ruleId'])

        # returns a list of ruleIDs
        return rules

def _get_nat_rules_with_ip(client_session, **kwargs):
    needed_params = ['esg_name', 'original_ip','translated_ip']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = get_nat_rules_with_ip(client_session, kwargs['esg_name'], kwargs['original_ip'], kwargs['translated_ip'])

    if result and kwargs['verbose']:
        print result
    elif result:
        for i in result:
            print i
    else:
        print 'Failed to get NAT rules for {} on {}'.format(kwargs['translated_ip'], kwargs['esg_name'])

# PEZ Changes
# new function to delete a NAT
def delete_nat_rule(client_session, esg_name, rule_id):
    """
    This function deletes the NAT rule with ID rule_id

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway
    :param rule_id: The ID of the NAT rules
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    result = client_session.delete('edgeNatRule', uri_parameters={'edgeId': esg_id, 'ruleID':rule_id})
    if result['status'] != 204:
        return None
    else:
        return result

def _delete_nat_rule(client_session, **kwargs):
    needed_params = ['esg_name', 'rule_id']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = delete_nat_rule(client_session, kwargs['esg_name'], kwargs['rule_id'])

    if result and kwargs['verbose']:
        print result
    elif result:
        print 'NAT rule {} on edge {} deleted'.format(kwargs['rule_id'], kwargs['esg_name'])
    else:
        print 'Failed to delete NAT rule {} on {}'.format(kwargs['rule_id'], kwargs['esg_name'])



def contruct_parser(subparsers):
    parser = subparsers.add_parser('nat', description="Functions for NAT",
                                   help="Functions for NAT",
                                   formatter_class=RawTextHelpFormatter)

    parser.add_argument("command", help="""
    add_nat: create a new NAT Rule
    # PEZ Changes
    # new functions
    delete_nat: delete a NAT using the rule ID
    get_nat_rules_tip: get all NAT rules with translated IP
    """)

    parser.add_argument("-n",
                        "--esg_name",
                        help="Edge Name")
    parser.add_argument("-t",
                        "--nat_type",
                        help="Type of NAT Rule (SNAT or DNAT)")
    parser.add_argument("-o",
                        "--original_ip",
                        help="Original IP Address")
    parser.add_argument("-tip",
                        "--translated_ip",
                        help="Translated IP Address")
    # PEZ Changes
    # New arguments
    parser.add_argument("-op",
                        "--original_port",
                        help="Original port")
    parser.add_argument("-tp",
                        "--translated_port",
                        help="Translated port")
    parser.add_argument("-i",
                        "--nat_vnic",
                        help="Interface on which the translating is applied")
    parser.add_argument("-p",
                        "--protocol",
                        help="protocol")
    parser.add_argument("-r",
                        "--rule_id",
                        help="rule ID of a NAT")
    parser.add_argument("-d",
                        "--description",
                        help="description")

    parser.set_defaults(func=_nat_main)


def _nat_main(args):
    if args.debug:
        debug = True
    else:
        debug = False

    config = ConfigParser.ConfigParser()
    assert config.read(args.ini), 'could not read config file {}'.format(args.ini)

    try:
        nsxramlfile = config.get('nsxraml', 'nsxraml_file')
    except (ConfigParser.NoSectionError):
        nsxramlfile_dir = resource_filename(__name__, 'api_spec')
        nsxramlfile = '{}/nsxvapi.raml'.format(nsxramlfile_dir)

    client_session = NsxClient(nsxramlfile, config.get('nsxv', 'nsx_manager'),
                               config.get('nsxv', 'nsx_username'), config.get('nsxv', 'nsx_password'), debug=debug)

    try:
        command_selector = {
            'add_nat': _add_nat_rule,
            # PEZ changes
            # New functions
            'get_nat_rules_tip': _get_nat_rules_with_ip,
            'delete_nat': _delete_nat_rule,
            }
 
        # PEZ Changes
        # New arguments
        command_selector[args.command](client_session, esg_name=args.esg_name,
                                        original_ip=args.original_ip,
                                        translated_ip=args.translated_ip,
                                        verbose=args.verbose,
                                        nat_type=args.nat_type,
                                        original_port=args.original_port,
                                        translated_port=args.translated_port,
                                        nat_vnic=args.nat_vnic,
                                        protocol=args.protocol,
                                        description=args.description,
                                        rule_id=args.rule_id,
                                       )
    except KeyError:
        print('Unknown command')

def main():
    main_parser = argparse.ArgumentParser()
    subparsers = main_parser.add_subparsers()
    contruct_parser(subparsers)
    args = main_parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
