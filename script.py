import os
import json
import time
import logging
import argparse

import boto3
import requests


SESSION = boto3.session.Session()
args = None

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

    global SESSION, logger, handler, args
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', default='info', choices=['info', 'debug'],
                        help='level of logging for the script.')
    parser.add_argument('-p', '--profile', default='default', type=str,
                        help='profile name to use for aws configuration. '
                        'mentioned in files `~/.aws/credentials` and '
                        '`~/.aws/config`')
    parser.add_argument('-c', '--config', default='config.json', type=str,
                        help='Config file to use. Default is config.json')

    args = parser.parse_args()

    SESSION = boto3.session.Session(profile_name=args.profile)
    logger.setLevel(logging.INFO if args.verbose == 'info' else logging.DEBUG)
    handler.setLevel(logging.INFO if args.verbose == 'info' else logging.DEBUG)


def read_config():

    # path = os.environ.get('CONFIG_FILE')
    
    # if not path:
    #     logger.info('No `CONFIG_FILE` environment variable found. '
    #                 'Skipping config read.')
    #     return dict()

    path = args.config
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
    regions = SESSION.get_available_regions('dynamodb')

    for region in regions:
        cloudfront = SESSION.client('cloudfront', region_name=region)

        nextMarker = None
        isTruncated = False
        while True:
            res = list()
            if not nextMarker: res = cloudfront.list_distributions(MaxItems='1000')
            else: res = cloudfront.list_distributions(MaxItems='1000', Marker=nextMarker)

            for item in res.get('DistributionList').get('Items', list()):
                domains.append(item.get('DomainName'))

            nextMarker = res.get('DistributionList').get('NextMarker')
            if nextMarker: continue
            else: break

    logger.info('[%02d] cloudfront domains fetched.', len(domains))
    logger.debug(json.dumps(domains, indent=2))
    return domains


def get_beanstalk_endpoints():

    logger.info('Fetching elasticbeanstalk environments...')
    regions = SESSION.get_available_regions('dynamodb')
    envs = list()
    for region in regions:
        ebclient = SESSION.client('elasticbeanstalk', region_name=region)
        logger.info('Fetching for region {}'.format(region))
        try:
            for item in (ebclient.describe_environments() or dict()) \
                    .get('Environments', list()):
                envs.append(item.get('CNAME'))
        except Exception as e:
            logger.warn('Exception {0} occurred in get_beanstalk_endpoints() for region {1}'.format(e, region))

    logger.info('[%d] elasticbeanstalk apps found.', len(envs))
    return envs


def get_elb_names():

    logger.info('Fetching elb details...')
    regions = SESSION.get_available_regions('dynamodb')

    names = list()

    for region in regions:
        client = SESSION.client('elb', region_name=region)
        logger.info('Fetching for region {}'.format(region))
        try:
            nextMarker = None
            while True:
                res = list()
                if not nextMarker: res = client.describe_load_balancers(PageSize=400)
                else: res = client.describe_load_balancers(PageSize=400, Marker=nextMarker)
                for item in res.get('LoadBalancerDescriptions'):
                    names.append(item.get('DNSName'))
                nextMarker = res.get('NextMarker')
                if nextMarker: continue
                else: break
        except Exception as e:
            logger.warn('Exception {0} occurred in get_elb_names() for region {1}'.format(e, region))

    for region in regions:
        client = SESSION.client('elbv2', region_name=region)
        logger.info('Fetching for region {}'.format(region))
        try:
            nextMarker = None
            while True:
                res = list()
                if not nextMarker: res = client.describe_load_balancers(PageSize=400)
                else: res = client.describe_load_balancers(PageSize=400, Marker=nextMarker)
                for item in res.get('LoadBalancers'):
                    names.append(item.get('DNSName'))
                nextMarker = res.get('NextMarker')
                if nextMarker: continue
                else: break
        except Exception as e:
            logger.warn('Exception {0} occurred in get_elbv2_names() for region {1}'.format(e, region))

    logger.info('[%d] elb 1&2s names fetched.', len(names))
    return names


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
        try:
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
        except Exception as e:
            logger.warn('Exception {0} occurred in get_instance_details() while describe_addresses() for region {1}'.format(e, region_name))

    logger.info(str())
    logger.info('  Fetching instances\' IP addresses...')
    for region_name in regions:
        ec2 = SESSION.client('ec2', region_name=region_name)
        logger.info('    Fetching from region [%s]...' % (region_name))
        try:
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
        except Exception as e:
            logger.warn('Exception {0} occurred in get_instance_details() while describe_instances() for region {1}'.format(e, region_name))

    logger.info(str())
    logger.info('[%02d] IPs fetched.', len(addresses))
    logger.debug(addresses)
    logger.debug(hosts)
    return addresses, hosts


def get_rds_endpoints():
    logger.info('Fetching RDS details...')
    regions = SESSION.get_available_regions('dynamodb')

    names = list()

    for region in regions:
        client = SESSION.client('rds', region_name=region)
        logger.info('Fetching for region {}'.format(region))
        try:
            nextMarker = None
            while True:
                res = list()
                if not nextMarker: res = client.describe_db_clusters(MaxRecords=100, IncludeShared=True)
                else: res = client.describe_db_clusters(MaxRecords=100, IncludeShared=True, Marker=nextMarker)
                for item in res.get('DBClusters'):
                    names.append(item.get('Endpoint'))
                    names.append(item.get('ReaderEndpoint'))
                    for ce in item.get('CustomEndpoints'):
                        names.append(ce)
                nextMarker = res.get('Marker')
                if nextMarker: continue
                else: break
            names = list(dict.fromkeys(names))

            nextMarker = None
            while True:
                res = list()
                if not nextMarker: res = client.describe_db_instances(MaxRecords=100)
                else: res = client.describe_db_instances(MaxRecords=100, Marker=nextMarker)
                for item in res.get('DBInstances'):
                    names.append(item.get('Endpoint').get('Address'))
                nextMarker = res.get('Marker')
                if nextMarker: continue
                else: break
            names = list(dict.fromkeys(names))

        except Exception as e:
            logger.warn('Exception {0} occurred in get_elbv2_names() for region {1}'.format(e, region))

    logger.info('[%d] RDS endpoints fetched.', len(names))
    return names


def get_s3_buckets():

    logger.info('Fetching S3 buckets...')
    regions = SESSION.get_available_regions('dynamodb')
    buckets = list()
    for region in regions:
        s3_client = SESSION.client('s3', region_name=region)
        try:
            buckets.extend([
                x.get('Name') for x in s3_client.list_buckets().get(
                    'Buckets', [{}])])
        except Exception as e:
            logger.warn('Exception {0} occurred in get_s3_buckets() for region {1}'.format(e, region))

    logger.info('[%02d] buckets fetched.', len(buckets))
    return buckets


def list_hosted_zones(route53):
    ret = list()
    nextMarker = None
    while True:
        res = list()
        if not nextMarker: res = route53.list_hosted_zones(MaxItems='100')
        else: res = route53.list_hosted_zones(MaxItems='100', Marker=nextMarker)
        ret.extend(res.get('HostedZones'))
        nextMarker = res.get('NextMarker')
        if nextMarker: continue
        else: break
    return ret


def get_dns_records():

    logger.info('Fetching route53 hosted zones with records...')
    route53 = SESSION.client('route53')
    res = list_hosted_zones(route53)

    hosted_zones = list()
    for zone in res:
        if not zone.get('Id'):
            continue

        record_sets = list()
        record_name = str()
        while True:
            if not record_name:
                res = route53.list_resource_record_sets(
                    HostedZoneId=zone['Id'], MaxItems='100')
            else:
                res = route53.list_resource_record_sets(
                    HostedZoneId=zone['Id'], StartRecordName=record_name, MaxItems='100')

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


def get_parsed_records(zones, ips, hosts, cfdomains,
                       buckets, eb_endpoints, elb_names, vpc_endpoints, rds_endpoints, config):

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
        # iterate through copy of each hosted zone
        records = zone['records']

        for record in records.copy():

            # iterate through copy of records of in a hosted zone
            if record.get('Type') in ignore_types:
                # remove DNS record types which are of little to no interest, from the original
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

                    # Remove subrecords for whitelisted hosts
                    if is_whitelisted(config, 'hosts', value):
                        subrecords.remove(subrecord)
                        continue

                    # Remove subrecords for known/existing S3 buckets
                    if 's3.amazonaws.com' in value and record.get(
                            'Name', str()).strip('.') in buckets:
                        subrecords.remove(subrecord)

                    # Remove subrecords for known/existing VPC endpoints
                    if 'vpce.amazonaws.com' in value and record.get(
                            'Name', str()).strip('.') in vpc_endpoints:
                        subrecords.remove(subrecord)

                    # Remove subrecords for known/existing RDS endpoints
                    if '.rds.amazonaws.com' in value and record.get(
                            'Name', str()).strip('.') in rds_endpoints:
                        subrecords.remove(subrecord)

                    # Remove subrecords for known/existing CloudFront domains
                    if 'cloudfront.net' in value:
                        filtered_value = value.strip(zone.get('name', str()))
                        if filtered_value.strip('.') in cfdomains:
                            subrecords.remove(subrecord)

                    if 'elasticbeanstalk.com' in value and \
                            value in eb_endpoints:
                        subrecords.remove(subrecord)

                    if 'elb.' in value and value in elb_names:
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


def get_vpc_endpoints():
    logger.info('Fetching VPC endpoints DNS records...')
    regions = SESSION.get_available_regions('dynamodb')
    vpc_endpoints = list()
    for region in regions:
        ec2 = boto3.client('ec2', region_name=region)
        
        try:
            nextToken = None
            while True:
                res = list()
                if not nextToken: res = ec2.describe_vpc_endpoints(MaxResults=1000)
                else: res = ec2.describe_vpc_endpoints(MaxResults=1000, NextToken=nextToken)

                for item in res.get('VpcEndpoints'):
                    for dnsEntry in item.get('DnsEntries'):
                        vpc_endpoints.extend(dnsEntry.get('DnsName'))

                nextToken = res.get('NextToken')
                if nextToken: continue
                else: break

            logger.info('Fetched VPC endpoint DNS names for region {}'.format(region))
        
        except Exception as e:
            logger.error('Exception {} occurred in get_vpc_endpoints() while fetching DNS entries for VPC endpoints in region {}'.format(e, region))

    logger.info('[{}] List of VPC endpoint DNS names fetched...'.format(len(vpc_endpoints)))
    return vpc_endpoints


def prepare_slack_msg(zone):
    text = str()
    text += '\n*Following DNS records have been detected to be potentially stale and vulnerable to subdomain takeover for hosted zone:* `%s`\n' % (zone.get('name'))
    for record in zone.get('records'):
        text += '   *`[%s] %s`*  `VALUES => (%s)`\n' % (record.get(
            'Type'), record.get('Name'), ', '.join([
                x.get('Value') for x in record.get(
                    'ResourceRecords', [{}])]) or
                    record.get('AliasTarget', dict()).get('DNSName'))
    return text


def main(_, __):

    define_params()
    config = read_config()
    elb_names = get_elb_names()
    eb_endpoints = get_beanstalk_endpoints()
    cf_domains = get_cloudfront_domains()
    ips, hosts = get_instance_details()
    buckets = get_s3_buckets()
    vpc_endpoints = get_vpc_endpoints()
    rds_endpoints = get_rds_endpoints()
    hosted_zones = get_dns_records()

    zones = get_parsed_records(
        hosted_zones, ips, hosts, cf_domains,
        buckets, eb_endpoints, elb_names, vpc_endpoints, rds_endpoints, config)

    text = str()
    for zone in zones:
        if not zone.get('records'):
            continue
        response = post_on_slack(config, prepare_slack_msg(zone))
        logger.info('Results for zone {} posted on Slack with response {}'.format(zone.get('name'), response))
        
    return _exit(200, 'Execution returned normally.')


if __name__ == "__main__":
    main({}, {})
