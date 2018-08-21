import base64
import boto3
import hashlib
import logging
import os
import requests
import six
import yaml

from acme import challenges
from acme import client
from acme import errors
from acme import messages
from josepy import jwk # --> To add to requirements.txt   josepy==1.1.0
from botocore.config import Config
from botocore.exceptions import ClientError
from Crypto import Random
from Crypto.PublicKey import RSA
from datetime import datetime
from OpenSSL import crypto
from time import sleep

LOG = logging.getLogger("letslambda")
LOG.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
# add formatter to ch
handler.setFormatter(formatter)
# add ch to logger
LOG.addHandler(handler)



def load_from_s3(conf, s3_key):
    """
    Try to load a file from the s3 bucket and return it as a string
    Return None on error
    """
    LOG.debug("Loading file '{0}' from bucket '{1}'".format(s3_key, conf['s3_bucket']))
    try:
        s3 = conf['s3_client']
        content = s3.get_object(Bucket=conf['s3_bucket'], Key=s3_key)["Body"].read()
    except ClientError as e:
        LOG.error("Failed to load '{0}' in bucket '{1}'".format(s3_key, conf['s3_bucket']))
        LOG.error("Error: {0}".format(e))
        return None

    return content

def save_to_s3(conf, s3_key, content, encrypt=False, kms_key='AES256'):
    """
    Save the rsa key in PEM format to s3 .. for later use
    """
    LOG.debug("Saving object '{0}' to in 's3://{1}'".format(s3_key, conf['s3_bucket']))
    s3 = conf['s3_client']
    kwargs = {
        'Bucket': conf['s3_bucket'],
        'Key': s3_key,
        'Body': content,
        'ACL': 'private'
    }
    if encrypt == True:
        if  kms_key != 'AES256':
            kwargs['ServerSideEncryption'] = 'aws:kms'
            kwargs['SSEKMSKeyId'] = kms_key
        else:
            kwargs['ServerSideEncryption'] = 'AES256'

    try:
        s3.put_object(**kwargs);
    except ClientError as e:
        LOG.error("Failed to save '{0}' in bucket '{1}'".format(s3_key, conf['s3_bucket']))
        LOG.error("Error: {0}".format(e))
        return None

def create_and_save_key(conf, s3_key, kms_key='AES256'):
    """
    Generate a RSA 4096 key for general purpose (account or CSR)
    """
    LOG.debug("Generating new RSA key")
    key = RSA.generate(4096).exportKey("PEM")
    save_to_s3(conf, s3_key, key, True, kms_key)
    return key

def load_letsencrypt_account_key(conf):
    """
    Try to load the RSA account key from S3. If it doesn't succeed, it will create 
    a new account key with your provided information.  The letsenrypt account key  
    is needed to avoid redoing the Proof of Possession challenge (PoP). It is also 
    used to revoke an existing certificate.
    """
    LOG.debug("Loading account key from s3")

    newAccountNeeded = False
    account_key = load_from_s3(conf, 'account.key.rsa')
    if account_key == None:
        account_key = create_and_save_key(conf, "account.key.rsa", conf['kms_key'])
        newAccountNeeded = True

    key = jwk.JWKRSA.load(account_key)

    return key 

def get_acme_client(conf, domain_conf):

    newAccountNeeded = True
    account_key = load_letsencrypt_account_key(conf)

    LOG.info("account_key = '{0}'".format(account_key))
    
    directory_v2 = messages.Directory(requests.get(domain_conf['directory']).json())
    client_v2 = client.ClientV2( directory_v2, client.ClientNetwork(account_key))

    """
    Attempt to create a new account on the ACME server with the key.
    No problem if it fails because this key is already used.    
    """
    if newAccountNeeded:        
        LOG.debug("Registering with ACME server with the new account key")
        newReg = messages.NewRegistration(contact=tuple(domain_conf['contact']), key=account_key.public_key(), agreement='True')
        LOG.info("newReg = '{0}',client_v2[directory]='{1}' ".format(newReg, client_v2.directory['newAccount']))
        registration_resource = client_v2.new_account(newReg)

    return client_v2

def load_private_key(conf, domain):
    key = None
    name = domain['name'].replace('*','star') + ".key.rsa"

    if 'reuse_key' in domain.keys() and domain['reuse_key'] == True:
        LOG.debug("Attempting to load private key from S3 for domain '{0}'".format(domain['name']))
        key = load_from_s3(conf, name)

    if key == None:
        key = create_and_save_key(conf, name, domain['kmsKeyArn'])

    return crypto.load_privatekey(crypto.FILETYPE_PEM, key)

def generate_certificate_signing_request(conf, domain):
    key = load_private_key(conf, domain)

    LOG.debug("Creating Certificate Signing Request for domain '{0}'".format(domain))
    csr = crypto.X509Req()
    csr.get_subject().countryName = domain['countryName']
    csr.get_subject().CN = domain['name']
    csr.set_pubkey(key)
    csr.sign(key, "sha1")

    pem_csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM,csr)
    return (pem_csr, key)

def get_dns_challenge(authorization_resource):
    """
    Ask the ACME server to give us a list of challenges.
    Later, we will pick only the DNS one.
    """
    # Now let's look for a DNS challenge
    LOG.debug("Order resource '{0}'".format(authorization_resource))

    dns_challenges = filter(lambda x: isinstance(x.chall, challenges.DNS01), authorization_resource.body.challenges)
    return list(dns_challenges)[0]


def reset_route53_letsencrypt_record(conf, zone_id, zone_name, rr_fqdn):
    """
    Remove previous challenges from the hosted zone
    """
    r53 = boto3.client('route53', config=Config(signature_version='v4', region_name=conf['region']))

    if rr_fqdn.endswith('.') is not True:
        rr_fqdn += '.'

    rr_list = []
    results = r53.list_resource_record_sets(
                HostedZoneId=zone_id,
                StartRecordType='TXT',
                StartRecordName=rr_fqdn,
                MaxItems='100')

    while True:
        rr_list = rr_list + results['ResourceRecordSets']
        if results['IsTruncated'] == False:
            break

        results = r53.list_resource_record_sets(
            HostedZoneId=zone_id,
            StartRecordType='TXT',
            StartRecordName=results['NextRecordName'])

    r53_changes = { 'Changes': []}
    for rr in rr_list:
        if rr['Name'] == rr_fqdn and rr['Type'] == 'TXT':
            r53_changes['Changes'].append({
                'Action': 'DELETE',
                'ResourceRecordSet': {
                    'Name': rr['Name'],
                    'Type': rr['Type'],
                    'TTL': rr['TTL'],
                    'ResourceRecords': rr['ResourceRecords']
                }
            })
            try:
                res = r53.change_resource_record_sets(HostedZoneId=zone_id, ChangeBatch=r53_changes)
                LOG.info("Removed resource record '{0}' from hosted zone '{1}'".format(rr_fqdn, zone_name))
                return True

            except ClientError as e:
                LOG.error("Failed to remove resource record '{0}' from hosted zone '{1}'".format(rr_fqdn, zone_name))
                LOG.error("Error: {0}".format(e))
                return None

            break

    LOG.debug("No Resource Record to delete.")
    return False

def answer_dns_challenge(conf, client, domain, challenge):
    """
    Compute the required answer and set it in the DNS record
    for the domain.
    """
    authorization = "{}.{}".format(
        base64.urlsafe_b64encode(challenge.get("token")).decode("ascii").replace("=", ""),
        base64.urlsafe_b64encode(client.key.thumbprint()).decode("ascii").replace("=", "")
        )

    dns_response = base64.urlsafe_b64encode(hashlib.sha256(authorization.encode()).digest()).decode("ascii").replace("=", "")

    # Let's update the DNS on our R53 account
    zone_id = get_route53_zone_id(conf, domain['r53_zone'])
    if zone_id == None:
        LOG.error("Cannot determine zone id for zone '{0}'".format(domain['r53_zone']))
        return None

    LOG.info("Domain '{0}' has '{1}' for Id".format(domain['r53_zone'], zone_id))

    zone_id = get_route53_zone_id(conf, domain['r53_zone'])
    if zone_id == None:
        LOG.error("Cannot find R53 zone {}, are you controling it ?".format(domain['r53_zone']))
        return None

    acme_domain = "_acme-challenge.{}".format(domain['name'])


    res = reset_route53_letsencrypt_record(conf, zone_id, domain['name'], acme_domain)
    if res == None:
        LOG.error("An error occured while trying to remove a previous resource record. Skipping domain {0}".format(domain['name']))
        return None

    add_status == None
    #add_status = create_route53_letsencrypt_record(conf, zone_id, domain['name'], acme_domain, 'TXT', '"' + dns_response + '"')
    if add_status == None:
        LOG.error("An error occured while creating the dns record. Skipping domain {0}".format(domain['name']))
        return None

    #add_status = wait_letsencrypt_record_insync(conf, add_status)
    if add_status == None:
        LOG.error("Cannot determine if the dns record has been correctly created. Skipping domain {0}".format(domain['name']))
        return None

    if add_status == False:
        LOG.error("We updated R53 but the servers didn't sync within 60 seconds. Skipping domain {0}".format(domain['name']))
        return None

    if add_status is not True:
        LOG.error("An unexpected result code has been returned. Please report this bug. Skipping domain {0}".format(domain['name']))
        LOG.error("add_status={0}".format(add_status))
        return None

    ## Now, let's tell the ACME server that we are ready
    challenge_response = challenges.DNS01Response(key_authorization=authorization)
    #challenge_resource = client.answer_challenge(challenge, challenge_response)

    if challenge_resource.body.error != None:
        return False

    return True


def lambda_handler(event, context):

    conf = {}

    conf['s3_bucket'] = os.getenv('S3_BUCKET')
    conf['s3_region'] = os.getenv('S3_REGION')
    conf['s3_client'] = boto3.client('s3', config=Config(signature_version='s3v4', region_name=os.getenv('S3_REGION')))
    conf['config_file'] = os.getenv('DOMAIN_CONFIG')

    conf['kms_key'] = 'AES256'

    domain_conf = yaml.load( load_from_s3(conf,conf['config_file']))
    acme_client = get_acme_client(conf, domain_conf)    

    for domain in domain_conf['domains']:
        (pem_csr, key) = generate_certificate_signing_request(conf, domain)

        LOG.debug("Raise order for new certificate for '{0}'".format(domain))
        order_resource = acme_client.new_order(pem_csr)

        dns_challenge = get_dns_challenge(order_resource.authorizations[0])

        LOG.debug("DNS Challenge '{0}'".format(dns_challenge))
        res = answer_dns_challenge(conf, acme_client, domain, dns_challenge)


"""

    # Help -> https://community.letsencrypt.org/t/acme-v2-production-environment-wildcards/55578

        LOG.debug("Get authorization for domain '{0}'".format(domain))
        authorization_resource = get_authorization(acme_client, domain)
        
        LOG.debug("Issue DNS Challenge for domain '{0}'".format(domain))
        challenge = get_dns_challenge(authorization_resource)

        res = answer_dns_challenge(conf, acme_client, domain, challenge)

        if res is not True:
            LOG.error("An error occurred while answering the DNS challenge. Skipping domain '{0}'.".format(domain['name']))
            continue

        (chain, certificate, key) = request_certificate(conf, domain, acme_client, authorization_resource)
        if key == False or certificate == False:
            LOG.error("An error occurred while requesting the signed certificate. Skipping domain '{0}'.".format(domain['name']))
            continue

        save_certificates_to_s3(conf, domain, chain, certificate)
        iam_cert = upload_to_iam(conf, domain, chain, certificate, key)
        if iam_cert is not False and iam_cert['ResponseMetadata']['HTTPStatusCode'] is 200 and 'elb' in domain.keys():
            update_elb_server_certificate(conf, domain, iam_cert['ServerCertificateMetadata']['Arn'])
        else:
            LOG.error("An error occurred while saving your server certificate in IAM. Skipping domain '{0}'.".format(domain['name']))
            continue
"""
    
