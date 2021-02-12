#
# Copyright 2019 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#
#------------------------------------------------------------------------
#         Python Code Sample for Alexa Web Information Service          -
#------------------------------------------------------------------------
#
# This sample will make a request to the Alexa Web Information Service in
# AWS Marketplace using the API user credentials and API plan key. This
# sample demonstrates how to make a SigV4 signed request and refresh
# crdentials from the Cognito pool.
#

import sys, os, base64, hashlib, hmac
import logging, getopt
import boto3
import getpass
import requests
from datetime import datetime
import time
from configparser import ConfigParser # pip install configparser
from future.standard_library import install_aliases
install_aliases()
from urllib.parse import parse_qs, quote_plus

# ************* REQUEST VALUES *************
host = 'awis.api.alexa.com'
endpoint = 'https://' + host
region = 'us-east-1'
method = 'GET'
service = 'execute-api'
log = logging.getLogger( "awis" )
content_type = 'application/xml'
local_tz = "America/Los_Angeles"

# ******** LOCAL CREDENTIALS FILE **********
credentials_file = '.awis.py.credentials'

# ******* COGNITO AUTHENTICATION  *********
cognito_user_pool_id = 'us-east-1_n8TiZp7tu'
cognito_client_id = '6clvd0v40jggbaa5qid2h6hkqf'
cognito_identity_pool_id = 'us-east-1:bff024bb-06d0-4b04-9e5d-eb34ed07f884'
cognito_region = 'us-east-1'

###############################################################################
# usage                                                                       #
###############################################################################
def usage( ):
    sys.stderr.write ( """
Usage: awis.py [options]

  Make a signed request to Alexa Web Information API service

  Options:
     --action                Service Action
     -u, --user              Username
     -k, --key               API Key
     -o, --options           Service Options
     -?, --help       Print this help message and exit.

  Examples:
     UrlInfo:		awis.py -k 98hu7.... -u User --action urlInfo --options "&ResponseGroup=Rank&Url=sfgate.com"
""" )

###############################################################################
# parse_options                                                               #
###############################################################################
def parse_options( argv ):
    """Parse command line options."""

    opts = {}

    urlargs = {}

    try:
        user_opts, user_args = getopt.getopt( \
            argv, \
            'k:u:o:a:t:?', \
            [ 'key=', 'user=', 'options=', 'action=', 'help=' ] )
    except Exception as e:
        print('Command parse error:', e)
        log.error( "Unable to parse command line" )
        return None

    if ( '-?', '' ) in user_opts or ( '--help', '' ) in user_opts:
        opts['help'] = True
        return opts
    #
    # Convert command line options to dictionary elements
    #
    for opt in user_opts:
        if  opt[0] == '-k' or opt[0] == '--key':
            opts['key'] = opt[1]
        elif opt[0] == '-u' or opt[0] == '--user':
            opts['user'] = opt[1]
        elif opt[0] == '-a' or opt[0] == '--action':
            opts['action'] = opt[1]
        elif opt[0] == '-o' or opt[0] == '--options':
            opts['options'] = opt[1]
        elif opt[0] == '--action':
            opts['action'] = opt[1]
        elif opt[0] == '-v' or opt[0] == '--verbose':
            log.verbose()

    if 'key' not in opts or \
       'user' not in opts or \
       'action' not in opts:
        log.error( "Missing required arguments" )
        return None

    #
    # Return a dictionary of settings
    #
    success = True
    return opts

###############################################################################
# refresh_credentials                                                         #
###############################################################################
def refresh_credentials(user):
    client_idp = boto3.client('cognito-idp', region_name=cognito_region, aws_access_key_id='', aws_secret_access_key='')
    client_identity = boto3.client('cognito-identity', region_name='us-east-1')

    password = getpass.getpass('Password: ')
    response = client_idp.initiate_auth(
        ClientId=cognito_client_id,
        AuthFlow='USER_PASSWORD_AUTH',
        AuthParameters={
            'USERNAME': user,
            'PASSWORD': password
        }
    )

    idtoken = response['AuthenticationResult']['IdToken']
    response = client_identity.get_id(
        IdentityPoolId=cognito_identity_pool_id,
        Logins={
            'cognito-idp.us-east-1.amazonaws.com/'+cognito_user_pool_id: idtoken
        }
    )
    identityid = response['IdentityId']
    response = client_identity.get_credentials_for_identity(
        IdentityId=identityid,
        Logins={
            'cognito-idp.us-east-1.amazonaws.com/'+cognito_user_pool_id: idtoken
        }
    )

    config = ConfigParser()
    config['DEFAULT'] = {'aws_access_key_id': response['Credentials']['AccessKeyId'],
                         'aws_secret_access_key': response['Credentials']['SecretKey'],
                         'aws_session_token': response['Credentials']['SessionToken'],
                         'expiration': time.mktime(response['Credentials']['Expiration'].timetuple())
                        }

    print('Writing new credentials to %s\n' % credentials_file)
    with open(credentials_file, 'w') as configfile:
        config.write(configfile)
    configfile.close()

###############################################################################
# Key derivation functions. See:
# http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
###############################################################################
def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

def getSignatureKey(key, dateStamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning

###############################################################################
# sortQueryString                                                             #
###############################################################################
def sortQueryString(queryString):
    queryTuples = parse_qs(queryString)
    sortedQueryString = ""
    sep=""
    for key in sorted(queryTuples.keys()):
        sortedQueryString = sortedQueryString + sep + key + "=" + quote_plus(queryTuples[key][0])
        sep="&"
    return sortedQueryString

###############################################################################
# main                                                                        #
###############################################################################
if __name__ == "__main__":

    opts = parse_options( sys.argv[1:] )

    if not opts:
        usage( )
        sys.exit( -1 )

    if 'help' in opts:
        usage( )
        sys.exit( 0 )

    user = opts['user']

    if not os.path.isfile(credentials_file):
        refresh_credentials(user)

    # Get credentials to access api from local file. Refresh credentials from Cognito pool if necessary
    while True:
        config = ConfigParser()
        config.read(credentials_file)

        access_key = config.get("DEFAULT", "aws_access_key_id")
        secret_key = config.get("DEFAULT", "aws_secret_access_key")
        session_token = config.get("DEFAULT", "aws_session_token")
        expiration = config.get("DEFAULT", "expiration")

        exp_time = float(expiration)
        cur_time = time.mktime(datetime.now().timetuple())

        if cur_time > exp_time:
            refresh_credentials(user)
        else:
            break

    # Create a date for headers and the credential string
    t = datetime.utcnow()
    amzdate = t.strftime('%Y%m%dT%H%M%SZ')
    datestamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope

    # ************* TASK 1: CREATE A CANONICAL REQUEST *************
    # http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

    # Step 1 is to define the verb (GET, POST, etc.)--already done.

    # Step 2: Create canonical URI--the part of the URI from domain to query
    # string (use '/' if no path)
    canonical_uri = '/api'

    # Step 3: Create the canonical query string. In this example (a GET request),
    # request parameters are in the query string. Query string values must
    # be URL-encoded (space=%20). The parameters must be sorted by name.
    canonical_querystring = 'Action=' + opts['action']
    if 'options' in opts:
        canonical_querystring += "&" +  opts[ 'options']
    canonical_querystring = sortQueryString(canonical_querystring)

    # Step 4: Create the canonical headers and signed headers. Header names
    # must be trimmed and lowercase, and sorted in code point order from
    # low to high. Note that there is a trailing \n.
    canonical_headers = 'host:' + host + '\n' + 'x-amz-date:' + amzdate + '\n'

    # Step 5: Create the list of signed headers. This lists the headers
    # in the canonical_headers list, delimited with ";" and in alpha order.
    # Note: The request can include any headers; canonical_headers and
    # signed_headers lists those that you want to be included in the
    # hash of the request. "Host" and "x-amz-date" are always required.
    signed_headers = 'host;x-amz-date'

    # Step 6: Create payload hash (hash of the request body content). For GET
    # requests, the payload is an empty string ("").
    payload_hash = hashlib.sha256(('').encode('utf-8')).hexdigest()

    # Step 7: Combine elements to create canonical request
    canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash

    # ************* TASK 2: CREATE THE STRING TO SIGN*************
    # Match the algorithm to the hashing algorithm you use, either SHA-1 or
    # SHA-256 (recommended)
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
    string_to_sign = algorithm + '\n' +  amzdate + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

    # ************* TASK 3: CALCULATE THE SIGNATURE *************
    # Create the signing key using the function defined above.
    signing_key = getSignatureKey(secret_key, datestamp, region, service)

    # Sign the string_to_sign using the signing_key
    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

    # ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
    # The signing information can be either in a query string value or in
    # a header named Authorization. This code shows how to use a header.
    # Create authorization header and add to request headers
    authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature

    # The request can include any headers, but MUST include "host", "x-amz-date",
    # and (for this scenario) "Authorization". "host" and "x-amz-date" must
    # be included in the canonical_headers and signed_headers, as noted
    # earlier. Order here is not significant.
    # Python note: The 'host' header is added automatically by the Python 'requests' library.
    #headers = {'x-amz-date':amzdate, 'Authorization':authorization_header}
    headers = {'Accept':'application/xml',
               'Content-Type': content_type,
               'X-Amz-Date':amzdate,
               'Authorization': authorization_header,
               'x-amz-security-token': session_token,
               'x-api-key': opts['key']
              }

    # ************* SEND THE REQUEST *************
    request_url = endpoint + canonical_uri + "?" + canonical_querystring

    print('\nBEGIN REQUEST++++++++++++++++++++++++++++++++++++')
    print('Request URL = ' + request_url)
    r = requests.get(request_url, headers=headers)

    print('\nRESPONSE++++++++++++++++++++++++++++++++++++')
    print('Response code: %d\n' % r.status_code)
    print(r.text)
