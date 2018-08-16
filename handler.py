import base64
import boto3
import hashlib
import logging
import os
import requests
import yaml
import six

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

def get_acme_client(conf, domain_conf):

    newAccountNeeded = True
    account_key = load_letsencrypt_account_key(conf)

    LOG.info("account_key = '{0}'".format(account_key))
    
    #client_v2 = client.ClientV2(domain_conf['directory'], account_key)
    client_v2 = client.ClientV2(messages.Directory(requests.get(domain_conf['directory']).json()), account_key)

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

def get_authorization(client, domain):
    authorization_resource = client.request_domain_challenges(domain['name'])
    return authorization_resource



def lambda_handler(event, context):

    conf = {}

    conf['s3_bucket'] = os.getenv('S3_BUCKET')
    conf['s3_region'] = os.getenv('S3_REGION')
    #conf['s3_client'] = boto3.client('s3')
    conf['s3_client'] = boto3.client('s3', config=Config(signature_version='s3v4', region_name=os.getenv('S3_REGION')))
    conf['config_file'] = os.getenv('DOMAIN_CONFIG')

    conf['kms_key'] = 'AES256'

    domain_conf = yaml.load( load_from_s3(conf,conf['config_file']))
    acme_client = get_acme_client(conf, domain_conf)

"""
    for domain in domain_conf['domains']:

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
    
