# Amazon Neptune version 4 signing example (version v2)

# The following script requires python 3.6+
#    (sudo yum install python36 python36-virtualenv python36-pip)
# => the reason is that we're using urllib.parse() to manually encode URL
#    parameters: the problem here is that SIGV4 encoding requires whitespaces
#    to be encoded as %20 rather than not or using '+', as done by previous/
#    default versions of the library.


# See: https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
# This version makes a GET request and passes the signature
# in the Authorization header.
import sys
import os

# pip install custom package to /tmp/ and add to path
#subprocess.call('pip install requests -t /tmp/ --no-cache-dir'.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
#sys.path.insert(1, '/tmp/')

# Configuration. http is required.

import requests  # pip3 install requests
import urllib, datetime, hashlib, hmac
import json
from argparse import RawTextHelpFormatter
from argparse import ArgumentParser
import logging 

protocol = 'https'

# The following lines enable debugging at httplib level (requests->urllib3->http.client)
# You will see the REQUEST, including HEADERS and DATA, and RESPONSE with HEADERS but without DATA.
#
# The only thing missing will be the response.body which is not logged.


#import logging
#http_client.HTTPConnection.debuglevel = 1
#logging.basicConfig()
#logging.getLogger().setLevel(logging.DEBUG)
#requests_log = logging.getLogger("requests.packages.urllib3")
#requests_log.setLevel(logging.DEBUG)
#requests_log.propagate = True


# Read AWS access key from env. variables. Best practice is NOT
# to embed credentials in code.
access_key = os.getenv('AWS_ACCESS_KEY_ID', '')
secret_key = os.getenv('AWS_SECRET_ACCESS_KEY', '')
region = os.getenv('SERVICE_REGION', '')

# AWS_SESSION_TOKEN is optional environment variable. Specify a session token only if you are using temporary
# security credentials.
session_token = os.getenv('AWS_SESSION_TOKEN', '')

### Note same script can be used for AWS Lambda (runtime = python3.6).
## Steps to use this python script for AWS Lambda
# 1. AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN and AWS_REGION variables are already part of Lambda's Execution environment
#    No need to set them up explicitly.
# 3. Create Lambda deployment package https://docs.aws.amazon.com/lambda/latest/dg/lambda-python-how-to-create-deployment-package.html
# 4. Create a Lambda function in the same VPC and assign an IAM role with neptune access

def lambda_handler(event, context):
    # sample_test_input = {
    #     "host": "END_POINT:8182",
    #     "method": "GET",
    #     "query_type": "gremlin",
    #     "query": "g.V().count()"
    # }

    # Lambda uses AWS_REGION instead of SERVICE_REGION
    global region
    region = os.getenv('AWS_REGION', '')
    print("request body: " + str(event))
    #print(event)
    host = "optimizer-instance-1.chhh6csdt1hq.us-east-2.neptune.amazonaws.com:8182"
    method = "POST"
    query_type = "sparql"
    
    amount = event['amount']
    settles_by = event['settles_by']
    client = event['client']
    
    query =  buildSparqlQuery(amount, settles_by, client)
    
    return make_signed_request(host, method, query_type, query)
    
def buildSparqlQuery(amount, settles_by, client):
    
    #TODO: build paramterized query
    query = "PREFIX : <http://poc/> \nSELECT DISTINCT ?rail ?rate WHERE { \n"
    clients_instructs = "?client :INSTRUCTS_OVER ?threshold . \n"
    thresh_restricrt = "?threshold :RESTRICTS_TO ?rail .\n"
    thresh_amt = "?threshold :amount ?amount .\n"
    fil_amt = "{\n SELECT (MAX (?amount) AS ?Max_amount)\n WHERE {\n?threshold :amount ?amount .\n FILTER(?amount <=" + amount +  ") . \n } \n } \n"
    set_max = "FILTER(?amount = ?Max_amount) . \n"
    rail_settles_by = "?rail :SETTLES_BY ?date .\n"
    rail_curr = "?rail :ccy ?ccy .\n"
    days = "?date :daysToSettle ?days .\n"
    client_rtplan = "?client :HAS ?rateplan}\n"
    rateplan_rates = "?rail :COSTS ?rateplan . \n"
    rtplanrates = "?rateplan :rate ?rate .\n"
    #filamt = "FILTER (?amount <=" + amount+ ")\n"
    filday = "FILTER(?days = "+settles_by+ ")\n"
    filcli = "FILTER(?cliname = \"" + client + "\")\n"
    cliname = "?client :label ?cliname .\n"
    order = "ORDER BY ASC(?rate)"
    return (query+ clients_instructs + cliname+ filcli + thresh_amt + fil_amt + set_max + thresh_restricrt
            + rail_settles_by + days + filday +rtplanrates+rateplan_rates+client_rtplan +order)


def normalize_query_string(query):
    kv = (list(map(str.strip, s.split("=")))
          for s in query.split('&')
          if len(s) > 0)

    normalized = '&'.join('%s=%s' % (p[0], p[1] if len(p) > 1 else '')
                          for p in sorted(kv))
    return normalized

# Key derivation functions. See:
# https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def getSignatureKey(key, dateStamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning

def validate_input(method, query_type):
    # Supporting GET and POST for now:
    if (method != 'GET' and method != 'POST'):
        print('First parameter must be "GET" or "POST", but is "' + method + '".')
        sys.exit()

    # SPARQL UPDATE requires POST
    if (method == 'GET' and query_type == 'sparqlupdate'):
        print('SPARQL UPDATE is not supported in GET mode. Please choose POST.')
        sys.exit()

    # Note: it looks like Gremlin POST requires the query to be encoded in a JSON
    # struct; we haven't implemented this in the python script, so let's for now
    # disable Gremlin POST requests.
    if (method == 'POST' and query_type == 'gremlin'):
        print('POST is currently not supported for Gremlin in this python script.')
        sys.exit()

def get_canonical_uri_and_payload(query_type, query):
    # Set the stack and payload depending on query_type.
    if (query_type == 'sparql'):
        canonical_uri = '/sparql/'
        payload = {'query': query}

    elif (query_type == 'sparqlupdate'):
        canonical_uri = '/sparql/'
        payload = {'update': query}

    elif (query_type == 'gremlin'):
        canonical_uri = '/gremlin/'
        payload = {'gremlin': query}

    elif (query_type == "loader"):
        canonical_uri = "/loader/"
        payload = json.loads(query)

    elif (query_type == "status"):
        canonical_uri = "/status/"
        payload = {}

    else:
        print(
            'Third parameter should be from ["gremlin", "sparql", "sparqlupdate", "loader", "status] but is "' + query_type + '".')
        sys.exit()
    ## return output as tuple
    return canonical_uri, payload

def make_signed_request(host, method, query_type, query):
    service = 'neptune-db'
    endpoint = protocol + '://' + host

    print()
    print('+++++ USER INPUT +++++')
    print('host = ' + host)
    print('method = ' + method)
    print('query_type = ' + query_type)
    print('query = ' + query)

    # validate input
    validate_input(method, query_type)

    # get canonical_uri and payload
    canonical_uri, payload = get_canonical_uri_and_payload(query_type, query)
    print(payload)

    # ************* REQUEST VALUES *************

    # do the encoding => quote_via=urllib.parse.quote is used to map " " => "%20"
    request_parameters = urllib.parse.urlencode(payload, quote_via=urllib.parse.quote)
    request_parameters = request_parameters.replace('%27','%22')
    print(request_parameters)

    # ************* TASK 1: CREATE A CANONICAL REQUEST *************
    # https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

    # Step 1 is to define the verb (GET, POST, etc.)--already done.

    # Create a date for headers and the credential string.
    t = datetime.datetime.utcnow()
    amzdate = t.strftime('%Y%m%dT%H%M%SZ')
    datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope

    # ************* TASK 1: CREATE A CANONICAL REQUEST *************
    # https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

    # Step 1 is to define the verb (GET, POST, etc.)--already done.
    # Step 2: is to define the canonical_uri--already done.

    # Step 3: Create the canonical query string. In this example (a GET request),
    # request parameters are in the query string. Query string values must
    # be URL-encoded (space=%20). The parameters must be sorted by name.
    # For this example, the query string is pre-formatted in the request_parameters variable.
    if (method == 'GET'):
        canonical_querystring = normalize_query_string(request_parameters)
    elif (method == 'POST'):
        canonical_querystring = ''
    else:
        print('Request method is neither "GET" nor "POST", something is wrong here.')
        sys.exit()

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
    if (method == 'GET'):
        post_payload = ''
    elif (method == 'POST'):
        post_payload = request_parameters
    else:
        print('Request method is neither "GET" nor "POST", something is wrong here.')
        sys.exit()

    payload_hash = hashlib.sha256(post_payload.encode('utf-8')).hexdigest()

    # Step 7: Combine elements to create canonical request.
    canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash

    # ************* TASK 2: CREATE THE STRING TO SIGN*************
    # Match the algorithm to the hashing algorithm you use, either SHA-1 or
    # SHA-256 (recommended)
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
    string_to_sign = algorithm + '\n' + amzdate + '\n' + credential_scope + '\n' + hashlib.sha256(
        canonical_request.encode('utf-8')).hexdigest()

    # ************* TASK 3: CALCULATE THE SIGNATURE *************
    # Create the signing key using the function defined above.
    signing_key = getSignatureKey(secret_key, datestamp, region, service)

    # Sign the string_to_sign using the signing_key
    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

    # ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
    # The signing information can be either in a query string value or in
    # a header named Authorization. This code shows how to use a header.
    # Create authorization header and add to request headers
    authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' + 'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature

    # The request can include any headers, but MUST include "host", "x-amz-date",
    # and (for this scenario) "Authorization". "host" and "x-amz-date" must
    # be included in the canonical_headers and signed_headers, as noted
    # earlier. Order here is not significant.
    # Python note: The 'host' header is added automatically by the Python 'requests' library.
    if (method == 'GET'):
        headers = {'x-amz-date': amzdate, 'Authorization': authorization_header}
    elif (method == 'POST'):
        headers = {'content-type': 'application/x-www-form-urlencoded', 'x-amz-date': amzdate,
                   'Authorization': authorization_header}
    else:
        print('Request method is neither "GET" nor "POST", something is wrong here.')
        sys.exit()

    # https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
    # The process for temporary security credentials is the same as using long-term credentials and
    # for temporary security credentials should be added as parameter name is X-Amz-Security-Token.
    if session_token:
        headers['x-amz-security-token'] = session_token

    # ************* SEND THE REQUEST *************
    request_url = endpoint + canonical_uri

    print(request_url)
    print()
    if (method == 'GET'):

        print('++++ BEGIN GET REQUEST +++++')
        print('Request URL = ' + request_url)
        r = requests.get(request_url, headers=headers, verify=False, params=request_parameters)

        print()
        print('+++++ RESPONSE +++++')
        print('Response code: %d\n' % r.status_code)
        print(r.text)

    elif (method == 'POST'):

        print('\n+++++ BEGIN POST REQUEST +++++')
        print('Request URL = ' + request_url)
        r = requests.post(request_url, headers=headers, verify=False, data=request_parameters)

        print()
        print('+++++ RESPONSE +++++')
        print('Response code: %d\n' % r.status_code)
        print(r.text)

    else:
        print('Request method is neither "GET" nor "POST", something is wrong here.')
    return r.text

help_msg = '''
    export AWS_ACCESS_KEY_ID=[MY_ACCESS_KEY_ID]
    export AWS_SECRET_ACCESS_KEY=[MY_SECRET_ACCESS_KEY]
    export AWS_SESSION_TOKEN=[MY_AWS_SESSION_TOKEN]
    export SERVICE_REGION=[us-east-1|us-east-2|us-west-2|eu-west-1]

    python version >=3.6 is required.

    Examples: For help
    python3 program_name.py -h

    Examples: Queries
    python3 program_name.py -ho your-neptune-endpoint -p 8182 -a GET -q status
    python3 program_name.py -ho your-neptune-endpoint -p 8182 -a GET -q sparql -d "SELECT ?s WHERE { ?s ?p ?o }"
    python3 program_name.py -ho your-neptune-endpoint -p 8182 -a POST -q sparql -d "SELECT ?s WHERE { ?s ?p ?o }"
    python3 program_name.py -ho your-neptune-endpoint -p 8182 -a POST -q sparqlupdate -d "INSERT DATA { <https://s> <https://p> <https://o> }"
    python3 program_name.py -ho your-neptune-endpoint -p 8182 -a GET -q gremlin -d "g.V().count()"
    python3 program_name.py -ho your-neptune-endpoint -p 8182 -a GET -q loader -d '{"loadId": "68b28dcc-8e15-02b1-133d-9bd0557607e6"}'
    python3 program_name.py -ho your-neptune-endpoint -p 8182 -a GET -q loader -d '{}'
    python3 program_name.py -ho your-neptune-endpoint -p 8182 -a POST -q loader -d '{"source": "source", "format" : "csv", "failOnError": "fail_on_error", "iamRoleArn": "iam_role_arn", "region": "region"}'

    Environment variables must be defined as AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and SERVICE_REGION.
    You should also set AWS_SESSION_TOKEN environment variable if you are using temporary credentials (ex. IAM Role or EC2 Instance profile).

    Current Limitations:
    - Query mode "sparqlupdate" requires POST (as per the SPARQL 1.1 protocol)
    - The python script currently does not support POST for Gremlin
            '''

def exit_and_print_help():
    print(help_msg)
    exit()

def parse_input_and_query_neptune():


    parser = ArgumentParser(description=help_msg, formatter_class=RawTextHelpFormatter)
    group_host = parser.add_mutually_exclusive_group()
    group_host.add_argument("-ho", "--host", type=str)
    group_port = parser.add_mutually_exclusive_group()
    group_port.add_argument("-p", "--port", type=int, help="port ex. 8182, default=8182", default=8182)
    group_action = parser.add_mutually_exclusive_group()
    group_action.add_argument("-a", "--action", type=str, help="http action, default = GET", default="GET")
    group_endpoint = parser.add_mutually_exclusive_group()
    group_endpoint.add_argument("-q", "--query_type", type=str, help="query_type, default = status ", default="status")
    group_data = parser.add_mutually_exclusive_group()
    group_data.add_argument("-d", "--data", type=str, help="data required for the http action", default="")

    args = parser.parse_args()
    print("parsed input: ")
    print(args)

    # Read command line parameters
    host = args.host
    port = args.port
    method = args.action
    query_type = args.query_type
    query = args.data

    if (access_key == ''):
        print('!!! ERROR: Your AWS_ACCESS_KEY_ID environment variable is undefined.')
        exit_and_print_help()

    if (secret_key == ''):
        print('!!! ERROR: Your AWS_SECRET_ACCESS_KEY environment variable is undefined.')
        exit_and_print_help()

    if (region == ''):
        print('!!! ERROR: Your SERVICE_REGION environment variable is undefined.')
        exit_and_print_help()

    if host is None:
        print('!!! ERROR: Neptune dns is missing')
        exit_and_print_help()

    host = host + ":" + str(port)
    make_signed_request(host, method, query_type, query)


if __name__ == "__main__":
    parse_input_and_query_neptune()