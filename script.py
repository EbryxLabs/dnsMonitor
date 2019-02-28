import json
import logging
import argparse

import boto3


SESSION = boto3.session.Session(profile_name='ebryx-soc-l5')

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter('%(asctime)s: %(message)s'))
logger.addHandler(handler)


def get_cloudfront_domains():

    logger.info('Fetching cloudfront domains...')
    domains = list()
    cloudfront = SESSION.client('cloudfront')
    res = cloudfront.list_distributions()
    if not res.get('DistributionList'):
        return domains

    for item in res['DistributionList'].get('Items', list()):
        domains.append(item.get('DomainName'))

    logger.info('[%02d] cloudfront domains fetched.', len(domains))
    logger.debug(domains)
    return domains


def get_elastic_ips():

    logger.info('Fetching elastic IP addresses...')
    addresses = list()
    regions = SESSION.get_available_regions('dynamodb')
    for region_name in regions:
        ec2 = SESSION.client('ec2', region_name=region_name)
        res = ec2.describe_addresses()

        for item in res.get('Addresses'):
            addresses.append(item['PublicIp'])

    logger.info('[%02d] elastic IPs fetched.', len(addresses))
    logger.debug(addresses)
    return addresses


def get_dns_records():

    logger.info('Fetching route53 hosted zones with records...')
    route53 = SESSION.client('route53')
    res = route53.list_hosted_zones()

    hosted_zones = list()
    for zone in res.get('HostedZones', list()):
        if not zone.get('Id'):
            continue

        record_sets = list()
        record_id = str()
        while True:
            if not record_id:
                res = route53.list_resource_record_sets(
                    HostedZoneId=zone['Id'])
            else:
                res = route53.list_resource_record_sets(
                    HostedZoneId=zone['Id'], StartRecordIdentifier=record_id)

            record_sets.extend(res.get('ResourceRecordSets'))
            if not(res.get('IsTruncated') or res.get('NextRecordIdentifier')):
                break

        hosted_zones.append({
            'name': zone['Name'], 'Id': zone['Id'],
            'records': record_sets})

    logger.info('[%02d] route53 hosted zones fetched.', len(hosted_zones))
    logger.debug(hosted_zones)
    return hosted_zones


def parse_records(zones, eips, cfdomains):

    logger.info('Parsing zone records...')

    ignore_types = ['NS', 'SOA']
    logger.info('Excluded %s record types.', ignore_types)

    for zone in zones:
        records = zone['records']
        a_names = [
            x.get('Name') for x in records if x.get('Type') in ['A', 'AAAA']]

        for record in records.copy():
            if record.get('Type') in ignore_types:
                records.remove(record)

            if record.get('Type') == 'CNAME':
                subrecords = record.get('ResourceRecords')
                for subrecord in subrecords.copy():
                    if subrecord.get('Value') in a_names:
                        subrecords.remove(subrecord)

                if not subrecords:
                    records.remove(record)

            if record.get('Type') in ['A', 'AAAA']:

                # if record.get('AliasTarget') and \
                #         record['AliasTarget'].get('DNSName') and \
                #         record['AliasTarget']['DNSName'].strip('.') \
                #         in cfdomains:
                #     records.remove(record)
                #     continue
                subrecords = record.get('ResourceRecords', list())
                for subrecord in subrecords.copy():
                    if subrecord.get('Value') in eips:
                        subrecords.remove(subrecord)

                if not subrecords:
                    records.remove(record)

    logger.info('Parsed zone records successfully.')
    logger.debug(zones)


if __name__ == "__main__":

    cloudfront_domains = get_cloudfront_domains()
    elastic_ips = get_elastic_ips()
    hosted_zones = get_dns_records()
    parse_records(hosted_zones, elastic_ips, cloudfront_domains)