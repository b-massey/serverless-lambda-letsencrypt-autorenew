"""
Lambda function to auto renew Letsencrypt certificates.
"""

import os
import base64
import hashlib
import logging
import time
import json

from datetime import datetime
from time import sleep

from acme import challenges
from acme import client
from acme import crypto_util
from acme import errors
from acme import messages

from botocore.config import Config
from botocore.exceptions import ClientError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from OpenSSL import crypto

import yaml
import requests
import boto3
import josepy as jose

LOG = logging.getLogger("letsencrypt_autorenew")
LOG.setLevel(logging.DEBUG)
HANDLER = logging.StreamHandler()
HANDLER.setLevel(logging.DEBUG)
HANDLER.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
LOG.addHandler(HANDLER)


def get_route53_zone_id(zone_name):
    """
    Get Zone ID for Route53 Zone
    """
    route_53 = boto3.client('route53', config=Config(signature_version='v4',
                                                     region_name=os.getenv('S3_REGION')))
    if not zone_name.endswith('.'):
        zone_name += '.'

    try:
        paginator = route_53.get_paginator('list_hosted_zones')
        for page in paginator.paginate():
            for zone in page['HostedZones']:
                if zone['Name'] == zone_name:
                    return zone['Id']

        if page['IsTruncated'] is not True:
            return None

    except ClientError as client_error:
        LOG.error("Failed to retrieve Route53 zone Id for '%s' ", zone_name)
        LOG.error("Error: %s", client_error)
        return None

    return None

def load_from_s3(conf, s3_key):
    """
    Try to load a file from the s3 bucket and return it as a string
    Return None on error
    """
    LOG.debug("Loading file '%s' from bucket '%s'", s3_key, conf['s3_bucket'])
    try:
        s3_client = conf['s3_client']
        content = s3_client.get_object(Bucket=conf['s3_bucket'], Key=s3_key)["Body"].read()
    except ClientError as client_error:
        LOG.error("Failed to load '%s' in bucket '%s'", s3_key, conf['s3_bucket'])
        LOG.error("Error: %s", client_error)
        return None

    return content

def save_to_s3(conf, s3_key, content, encrypt=False):
    """
    Save the rsa key in PEM format to s3 .. for later use
    """
    kms_key = conf['kms_key']
    LOG.debug("Saving object '%s' to in 's3://%s'", s3_key, conf['s3_bucket'])
    s3_client = conf['s3_client']
    kwargs = {
        'Bucket': conf['s3_bucket'],
        'Key': s3_key,
        'Body': content,
        'ACL': 'private'
    }
    if encrypt:
        if  kms_key != 'AES256':
            kwargs['ServerSideEncryption'] = 'aws:kms'
            kwargs['SSEKMSKeyId'] = kms_key
        else:
            kwargs['ServerSideEncryption'] = 'AES256'

    try:
        s3_client.put_object(**kwargs)
    except ClientError as client_error:
        LOG.error("Failed to save '{0}' in bucket '{1}'".format(s3_key, conf['s3_bucket']))
        LOG.error("Error: {0}".format(client_error))
    return None

def check_certtificate_expiration(conf, cert_name):

    cert_file = load_from_s3(conf, cert_name)
    if not cert_file:
        LOG.debug("No Certificate '%s' found in S3", cert_file)
        return False

    pem_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file)
    cert_expires = datetime.strptime(pem_certificate.get_notAfter(),"%Y%m%d%H%M%SZ")
    days_remaining = (cert_expires - datetime.utcnow()).days
    LOG.debug("Certificate validity %s, remaining %s", str(cert_expires), str(days_remaining))

    if days_remaining < 30:
        return True

    return False

def load_letsencrypt_account_key(conf, account_uri):
    """
    ACME Account key
    """
    acc_key_str = None 

    if account_uri:
        LOG.debug("Loading account key from s3")
        acc_key_str = load_from_s3(conf, conf['account_key'])

    if acc_key_str is None:
        LOG.debug("Generating new Private key") 
        account_key = rsa.generate_private_key(
                        public_exponent=65537,
                        key_size=4096,
                        backend=default_backend())
        acc_key_str = account_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption())

        LOG.debug("Save account key to S3")
        save_to_s3(conf, conf['account_key'], acc_key_str, True)
    else:
        account_key = load_pem_private_key(acc_key_str, None, default_backend())

    return account_key

def get_acme_client(conf, domain_conf):
    """
    ACME Client
    """
    account_key = load_letsencrypt_account_key(conf, domain_conf['account_uri'])

    a_key = jose.JWKRSA(key=account_key)
    net = client.ClientNetwork(a_key)

    directory_acme = messages.Directory.from_json(net.get(domain_conf['directory']).json())
    client_acme = client.ClientV2(directory_acme, net)


    if domain_conf['account_uri']:
        LOG.debug("Registering with ACME server with the new account key")
        new_reg = messages.NewRegistration.from_data(
            email=(', '.join(domain_conf['contact'])),
            terms_of_service_agreed=True)
        registration_resource = client_acme.new_account(new_reg)
        domain_conf['account_uri'] = registration_resource.uri

        LOG.debug("Write Account URI '%s' into Config file ", domain_conf['account_uri'])
        new_domain_conf = yaml.dump(domain_conf, default_flow_style = False)
        save_to_s3(conf, conf['config_file'], new_domain_conf)
    else:
        registration = messages.Registration(
            key=a_key,
            contact=tuple(domain_conf['contact']))
        registration_resource = messages.RegistrationResource(
            body=registration,
            uri=domain_conf['account_uri'])
        LOG.debug("Update the regristration: {0}".format(registration_resource))

        registration_resource = client_acme.query_registration(registration_resource)

    net.account = registration_resource
    

    return client_acme

def generate_csr(conf, domain):
    """
    Generate Certificate SR
    """
    pkey_pem = None
    cert_key_bits = domain['key_bits'] if 'key_bits' in domain else 4096

    if domain['reuse_key']:
        LOG.debug("Load private key from S3 for domain %s", domain['name'])
        pkey_pem = load_from_s3(conf, domain['cert_name'] +".key")

    if pkey_pem is None:
        # Create private key.
        LOG.debug("Creating CSR for domain %s, with key bits '%s'", domain['name'], cert_key_bits)
        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, cert_key_bits)
        pkey_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)

        LOG.info("Saving certificate key to S3")
        save_to_s3(conf, domain['cert_name'] + ".key", pkey_pem)

    csr_pem = crypto_util.make_csr(pkey_pem, [domain['name']])

    return pkey_pem, csr_pem

def reset_route53_letsencrypt_record(zone_id, rr_fqdn):
    """
    Remove previous challenges from the hosted zone
    """
    r53 = boto3.client('route53', config=Config(signature_version='v4',
                                                region_name=os.getenv('S3_REGION')))
    if rr_fqdn.endswith('.') is not True:
        rr_fqdn += '.'

    r53_changes = {'Changes': []}

    route_53 = boto3.client('route53', config=Config(signature_version='v4',
                                                     region_name='eu-west-2'))
    
    paginator = route_53.get_paginator('list_resource_record_sets')
    for record_page in paginator.paginate(HostedZoneId = zone_id):
        for record_set in record_page['ResourceRecordSets']:
            if record_set['Name'] == rr_fqdn and record_set['Type'] == 'TXT':
                print("add Change record")
                r53_changes['Changes'].append({
                    'Action': 'DELETE',
                    'ResourceRecordSet': {
                        'Name': record_set['Name'],
                        'Type': record_set['Type'],
                        'TTL': record_set['TTL'],
                        'ResourceRecords': record_set['ResourceRecords']
                    }
                })

    print(r53_changes)
    if r53_changes['Changes']:
        try:
            res = route_53.change_resource_record_sets(HostedZoneId=zone_id, ChangeBatch=r53_changes)
            LOG.info("Removed record '%s' from hosted zone '%s'", rr_fqdn, zone_id)
            return True

        except ClientError as client_error:
            LOG.error("Failed to remove record '%s' from hosted zone '%s", rr_fqdn, zone_id)
            LOG.error("Error: %s", client_error)
            return None
    else:
        LOG.debug("No Resource Record to delete.")
        print("nothing to delete")
    return False

def create_route53_letsencrypt_record(zone_id, rr_fqdn, rr_value):
    """
    Create the required dns record for letsencrypt to verify
    """
    r53 = boto3.client('route53', config=Config(signature_version='v4',
                                                region_name=os.getenv('S3_REGION')))

    if rr_fqdn.endswith('.') is not True:
        rr_fqdn += '.'

    r53_changes = {'Changes': [{
        'Action': 'CREATE',
        'ResourceRecordSet': {
            'Name': rr_fqdn,
            'Type': 'TXT',
            'TTL': 60,
            'ResourceRecords': [{
                'Value': rr_value
            }]
        }
    }]}

    try:
        res = r53.change_resource_record_sets(HostedZoneId=zone_id, ChangeBatch=r53_changes)
        LOG.info("Create verification record %s in hosted zone '%s", rr_fqdn, zone_id)
        return res

    except ClientError as client_error:
        LOG.error("Failed to create record %s in hosted zone %s", rr_fqdn, zone_id)
        LOG.error("Error: %s", client_error)
        return None

def wait_letsencrypt_record_insync(r53_status):
    """
    Wait until the new record set has been created
    """
    r53 = boto3.client('route53', config=Config(signature_version='v4',
                                                region_name=os.getenv('S3_REGION')))

    LOG.info("Waiting for DNS to synchronize with new TXT value")
    timeout = 60

    status = r53_status['ChangeInfo']['Status']
    while status != 'INSYNC':
        sleep(1)
        timeout = timeout-1
        try:
            r53_status = r53.get_change(Id=r53_status['ChangeInfo']['Id'])
            status = r53_status['ChangeInfo']['Status']

            if timeout == -1:
                return False

        except ClientError as client_error:
            LOG.error("Failed to retrieve record creation status.")
            LOG.error("Error: %s", client_error)
            return None

    LOG.debug("Route53 synchronized in {0:d} seconds.".format(60-timeout))
    return True

def answer_dns_challenge(conf, client, domain, challenge):
    """
    Compute the required answer and set it in the DNS record
    for the domain.
    """
    zone_id = conf['r53_zone_id']
    account_key = client.net.key

    authorization = "{}.{}".format(
        base64.urlsafe_b64encode(challenge.get("token")).decode("ascii").replace("=", ""),
        base64.urlsafe_b64encode(account_key.thumbprint()).decode("ascii").replace("=", ""))

    dns_response = base64.urlsafe_b64encode(hashlib.sha256(
        authorization.encode()).digest()).decode("ascii").replace("=", "")


    LOG.info("authorization ='{0}' dns_response= '{1}' for Id".format(authorization, dns_response))

    #domain_name = '.'.join(domain['name'].split('.')[1:]) 
    domain_name = domain['name'].replace('*.','') if domain['name'].startswith('*.') else domain['name']
    acme_domain = "_acme-challenge.%s.%s" % (domain_name, conf['r53_zone'])


    res = reset_route53_letsencrypt_record(zone_id, acme_domain)

    if res is None:
        LOG.error("An error occured while trying to remove a "
                  "previous resource record. Skipping domain %s",
                  domain_name)
        return None

    add_status = create_route53_letsencrypt_record(zone_id, acme_domain, '"' + dns_response + '"')
    if add_status is None:
        LOG.error("An error occured while creating the dns record. "
                  "Skipping domain %s", domain_name)
        return None

    add_status = wait_letsencrypt_record_insync(add_status)
    if add_status is None:
        LOG.error("Cannot determine if the dns record has been correctly created. "
                  "Skipping domain {0}".format(domain_name))
        return None

    if add_status is False:
        LOG.error("We updated R53 but the servers didn't sync within 60 seconds. "
                  "Skipping domain {0}".format(domain_name))
        return None

    if add_status is not True:
        LOG.error("An unexpected result code has been returned. Please report this bug. "
                  "Skipping domain {0}".format(domain_name))
        LOG.error("add_status={0}".format(add_status))
        return None

    challenge_response = challenges.DNS01Response(key_authorization=authorization)
    challenge_resource = client.answer_challenge(challenge, challenge_response)

    if challenge_resource.body.error is not None:
        return False

    return True


def letsencrypt_handler(event, context):
    """
    Lambda Handler
    """
    conf = {}
    conf['s3_bucket'] = os.getenv('S3_BUCKET')
    conf['s3_region'] = os.getenv('S3_REGION')
    conf['s3_client'] = boto3.client('s3', config=Config(signature_version='s3v4',
                                                         region_name=os.getenv('S3_REGION')))
    conf['config_file'] = os.getenv('DOMAIN_CONFIG')

    conf['account_key'] = "letsencrypt_account_{0}.key".format(os.getenv('ENVIRONMENT'))
    conf['kms_key'] = 'AES256'

    # Load config from S3
    domain_conf = yaml.safe_load(load_from_s3(conf, conf['config_file']))

    # Get R53 Zone ID
    conf['r53_zone'] = os.getenv('R53_DOMAIN')
    conf['r53_zone_id'] = get_route53_zone_id(conf['r53_zone'])

    if conf['r53_zone_id'] is None:
        LOG.Error("Unable to find Route 53 Zone ID for Zone '%s' ", conf['r53_zone'])
        return

    LOG.debug("Domain '%s' has Id '%s'", conf['r53_zone'], conf['r53_zone_id'])


    # Load/Create account key
    acme_client = get_acme_client(conf, domain_conf)

    for domain in domain_conf['domains']:
        domain['cert_name'] = (domain['name'].replace('*', 'star')).replace('.', '_')

        if 'key_bits' not in domain.keys():
            domain['key_bits'] = 4096

        if 'reuse_key' not in domain.keys():
            domain['reuse_key'] = True

        cert_renew = check_certtificate_expiration(conf, domain['cert_name']+'.pem') 
        if not cert_renew:
            LOG.debug("Certificate for domain '%s' does not need renewal", domain['name'])
            continue

        LOG.debug("Generate CSR for domain '%s' ", domain['name'])
        (cert_key, pem_csr) = generate_csr(conf, domain)

        LOG.debug("Raise order for new certificate for '%s' ", domain['name'])
        order_resource = acme_client.new_order(pem_csr)
        # LOG.debug("Order resource: %s ".order_resource)

        LOG.debug("Order Authorizations '{0}'".format(order_resource.authorizations))
        dns_challenges = filter(lambda x:
                                isinstance(x.chall, challenges.DNS01),
                                order_resource.authorizations[0].body.challenges)

        LOG.debug("DNS Challenge '{0}'".format(dns_challenges))

        res = answer_dns_challenge(conf, acme_client, domain, dns_challenges[0])
        if res is not True:
            LOG.error("An error occurred while answering the DNS challenge. "
                      "Skipping domain '%s'.", domain['name'])
            continue

        # Finalise order and retrieve certificate
        order_resource = acme_client.poll_and_finalize(order_resource)
        pem_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, order_resource.fullchain_pem)

        if order_resource.fullchain_pem is not None:
            LOG.info("Saving certificate to S3")
            save_to_s3(conf, domain['cert_name'] + ".pem", order_resource.fullchain_pem)
