import os
import json
import time
import logging
import argparse

import boto3
import requests


SESSION = boto3.session.Session()

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter('%(asctime)s: %(message)s'))
logger.addHandler(handler)


def _exit(code, message):

    return {'statusCode': code, 'body': json.dumps({
        'error' if code >= 300 else 'success': message})}


def define_params():

    global SESSION, logger, handler
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', default='info', choices=['info', 'debug'],
                        help='level of logging for the script.')
    parser.add_argument('-profile', default='default', type=str,
                        help='profile name to use for aws configuration. '
                        'mentioned in files `~/.aws/credentials` and '
                        '`~/.aws/config`')

    args = parser.parse_args()

    SESSION = boto3.session.Session(profile_name=args.profile)
    logger.setLevel(logging.INFO if args.v == 'info' else logging.DEBUG)
    handler.setLevel(logging.INFO if args.v == 'info' else logging.DEBUG)


def read_config():

    path = os.environ.get('CONFIG_FILE')
    if not path:
        logger.info('No `CONFIG_FILE` environment variable found. '
                    'Skipping config read.')
        return dict()

    if not os.path.isfile(path):
        logger.info('Invalid path in `CONFIG_FILE` environment variable. '
                    'Skipping config read.')
        return dict()

    logger.info('Reading CONFIG_FILE...')
    try:
        config = json.load(open(path, 'r'))
    except json.JSONDecodeError:
        logger.info('Error in decoding config file. Skipping config read.')
        return dict()

    return config


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
    logger.debug(json.dumps(domains, indent=2))
    return domains


def get_instance_details():

    logger.info('Fetching instance details...')
    addresses = list()
    hosts = list()
    regions = SESSION.get_available_regions('dynamodb')

    logger.info(str())
    logger.info('  Fetching elastic IP addresses...')
    for region_name in regions:
        ec2 = SESSION.client('ec2', region_name=region_name)
        logger.info('    Fetching from region [%s]...' % (region_name))
        res = ec2.describe_addresses()

        for item in res.get('Addresses'):
            public = item.get('PublicIp')
            private = item.get('PrivateIpAddress')

            if public:
                addresses.append(public)
                hosts.append('ec2-' + '-'.join(public.split('.')) + '.' +
                             region_name + '.compute.amazonaws.com')
            if private:
                addresses.append(private)
                hosts.append('ip-' + '-'.join(private.split('.')) + '.' +
                             region_name + '.compute.internal')

    logger.info(str())
    logger.info('  Fetching instances\' IP addresses...')
    for region_name in regions:
        ec2 = SESSION.client('ec2', region_name=region_name)
        logger.info('    Fetching from region [%s]...' % (region_name))

        next_token = None
        while True:
            if not next_token:
                res = ec2.describe_instances(MaxResults=999)
            else:
                res = ec2.describe_instances(
                    MaxResults=999, NextToken=next_token)

            for _ in res.get('Reservations'):
                for instance in _.get('Instances'):
                    if instance.get('PublicIpAddress'):
                        addresses.append(instance['PublicIpAddress'])
                    if instance.get('PrivateIpAddress'):
                        addresses.append(instance['PrivateIpAddress'])
                    if instance.get('PublicDnsName'):
                        hosts.append(instance['PublicDnsName'])
                    if instance.get('PrivateDnsName'):
                        hosts.append(instance['PrivateDnsName'])

            if res.get('NextToken'):
                next_token = res['NextToken']
            else:
                break

    logger.info(str())
    logger.info('[%02d] IPs fetched.', len(addresses))
    logger.debug(addresses)
    logger.debug(hosts)
    return addresses, hosts


def get_s3_buckets():

    logger.info('Fetching S3 buckets...')
    s3_client = SESSION.client('s3')
    buckets = [x.get('Name') for x in s3_client
               .list_buckets().get('Buckets', [{}])]

    logger.info('[%02d] buckets fetched.', len(buckets))
    return buckets


def get_dns_records():

    logger.info('Fetching route53 hosted zones with records...')
    route53 = SESSION.client('route53')
    res = route53.list_hosted_zones()

    hosted_zones = list()
    for zone in res.get('HostedZones', list()):
        if not zone.get('Id'):
            continue

        record_sets = list()
        record_name = str()
        while True:
            if not record_name:
                res = route53.list_resource_record_sets(
                    HostedZoneId=zone['Id'])
            else:
                res = route53.list_resource_record_sets(
                    HostedZoneId=zone['Id'], StartRecordName=record_name)

            record_sets.extend(res.get('ResourceRecordSets'))
            if not res.get('IsTruncated'):
                break
            else:
                record_name = res.get('NextRecordName')

        hosted_zones.append({
            'name': zone['Name'], 'Id': zone['Id'],
            'records': record_sets})

    logger.info('[%02d] route53 hosted zones fetched.', len(hosted_zones))
    logger.debug(hosted_zones)
    return hosted_zones


def is_whitelisted(config, list_name, value):

    for item in config.get('whitelists', dict()).get(list_name, list()):
        if item.startswith('*') and item.endswith('*'):
            if item.replace('*', str()) in value:
                return True

        if item.startswith('*') and not item.endswith('*'):
            if value.endswith(item.replace('*', str())):
                return True

        if not item.startswith('*') and item.endswith('*'):
            if value.startswith(item.replace('*', str())):
                return True


def post_on_slack(config, text):

    if not text:
        logger.info('No text to push to slack.')
        return

    if not config.get('hooks'):
        message = 'No slack hooks provided in config file.'
        return _exit(404, message)

    logger.info('Pushing text to slack...')
    for url in config['hooks']:
        response, _count = (None, 0)
        while not response and _count < 5:
            try:
                response = requests.post(url, json={'text': text})
            except:
                logger.info('Could not send slack request. '
                            'Retrying after 10 secs...')
                time.sleep(10)
                _count += 1

        if not response:
            continue

        if response.status_code == 200:
            message = 'Pushed message to slack successfully.'

        else:
            message = 'Could not push message to slack: <(%s) %s>' % (
                response.status_code, response.content.decode('utf8'))
            return _exit(500, message)


def get_parsed_records(zones, ips, hosts, cfdomains, buckets, config):

    logger.info(str())
    logger.info('Parsing zone records...')

    record_names = list()
    for zone in zones:
        records = zone['records']
        record_names.extend(
            [x.get('Name') for x in records
             if x.get('Type') in ['A', 'AAAA', 'CNAME']])

    record_names.extend(hosts)
    ignore_types = config.get('ignore_records', list())
    logger.info('Excluded %s record types.', ignore_types)

    for zone in zones.copy():
        records = zone['records']

        for record in records.copy():
            if record.get('Type') in ignore_types:
                records.remove(record)

            if record.get('Type') == 'CNAME':
                subrecords = record.get('ResourceRecords', list())

                for subrecord in subrecords.copy():
                    value = subrecord.get('Value')

                    if value.strip('.') in record_names or \
                            value in record_names or value + '.' \
                            in record_names:
                        subrecords.remove(subrecord)
                        continue

                    if is_whitelisted(config, 'hosts', value):
                        subrecords.remove(subrecord)
                        continue

                    if 's3.amazonaws.com' in value and record.get(
                            'Name', str()).strip('.') in buckets:
                        subrecords.remove(subrecord)

                    if 'cloudfront.net' in value:
                        filtered_value = value.strip(zone.get('name', str()))
                        if filtered_value.strip('.') in cfdomains:
                            subrecords.remove(subrecord)

                if not subrecords:
                    records.remove(record)

            if record.get('Type') in ['A', 'AAAA']:

                subrecords = record.get('ResourceRecords', list())
                for subrecord in subrecords.copy():
                    value = subrecord.get('Value')

                    if value in ips:
                        subrecords.remove(subrecord)
                        continue

                    if is_whitelisted(config, 'ips', value):
                        subrecords.remove(subrecord)

                alias_dns = record.get(
                    'AliasTarget', dict()).get('DNSName', str())
                if alias_dns and alias_dns.startswith('s3-website') \
                        and record.get('Name', str()).strip('.') in buckets:
                    record.pop('AliasTarget')

                if not subrecords:
                    records.remove(record)

            if record.get('Type') in ['TXT']:
                subrecords = record.get('ResourceRecords', list())
                for subrecord in subrecords.copy():
                    value = subrecord.get('Value')

                    if is_whitelisted(config, 'txts', value):
                        subrecords.remove(subrecord)

                if not subrecords:
                    records.remove(record)

        if not records:
            zones.remove(zone)

    logger.info('Parsed zone records successfully.')
    print(json.dumps(zones, indent=2))
    return zones


def main(_, __):

    define_params()
    config = read_config()
    cf_domains = get_cloudfront_domains()
    ips, hosts = get_instance_details()
    buckets = get_s3_buckets()
    hosted_zones = get_dns_records()

    zones = get_parsed_records(
        hosted_zones, ips, hosts, cf_domains, buckets, config)

    text = str()
    for zone in zones:
        if not zone.get('records'):
            continue
        text += '\n*Hosted Zone:* `%s`\n' % (zone.get('name'))
        for record in zone.get('records'):
            text += '   *`[%s] %s`*  `VALUES => (%s)`\n' % (record.get(
                'Type'), record.get('Name'), ', '.join([
                    x.get('Value') for x in record.get(
                        'ResourceRecords', [{}])]) or
                        record.get('AliasTarget', dict()).get('DNSName'))

    heading = 'Followings DNS records are detected to be potentially stale.\n'
    text = heading + text if text else text
    response = post_on_slack(config, text)
    if response and response.get('statusCode'):
        return response

    return _exit(200, 'Execution returned normally.')


if __name__ == "__main__":
    main({}, {})


