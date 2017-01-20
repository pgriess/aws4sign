'''
A no-dependencies AWS4 signing library / tool.
'''

import copy
import hashlib
import hmac
import re
import time
import urllib
import urlparse


def aws4_signature_parts(
        aws_key,
        aws_key_secret,
        method,
        url,
        data='',
        headers=None,
        now=None,
        region=None,
        service=None):
    '''
    Return a tuple of the parts of the AWS request signature: canonical
    request, string to sign, resulting Authorization header value, and the full
    resulting set of of output headers.

    Most applications should ignore all but the last and use these headers
    instead of the ones they provided. Not only will they have Authorization
    set, but they will have an X-Amz-Date that matches.
    '''

    # Compute a binary digest of an HMAC-256
    def hmac_sha256(key, msg):
        return hmac.new(key, msg, hashlib.sha256).digest()

    up = urlparse.urlparse(url)

    if headers is None:
        headers = {}
    else:
        headers = copy.copy(headers)

    if now is None:
        now = time.gmtime()

    if region is None:
        parts = up.hostname.split('.')
        assert parts[-1] == 'com'
        assert parts[-2] == 'amazonaws'
        assert len(parts) == 3 or len(parts) == 4
        region = 'us-east-1' if len(parts) == 3 else parts[-3]

    if service is None:
        parts = up.hostname.split('.')
        assert parts[-1] == 'com'
        assert parts[-2] == 'amazonaws'
        assert len(parts) == 3 or len(parts) == 4
        service = parts[0]

    # Canonicalize header names as lower-case
    headers = dict([(hn.lower(), hv) for hn, hv in headers.iteritems()])

    # Set the Host header
    assert headers.get('host', up.hostname) == up.hostname
    headers['host'] = up.hostname

    # Set the X-Amz-Date header
    assert headers.get(
        'x-amz-date',
        time.strftime('%Y%m%dT%H%M%SZ', now)) == time.strftime('%Y%m%dT%H%M%SZ', now)
    headers['x-amz-date'] = time.strftime('%Y%m%dT%H%M%SZ', now)

    # Make sure we're processing headers in lexicographic order
    signed_headers = sorted(headers)

    # Compute a hash of the canonical request
    canon_req = '\n'.join([
        # Method
        method.upper(),

        # URI
        urllib.quote(up.path),

        # Query string
        #
        # XXX: Need to sort query string parameters
        up.query,

        # Headers
        ''.join([
            '{}:{}\n'.format(
                hn.lower(),
                re.sub(r' +', ' ', headers[hn].strip()))
            for hn in signed_headers]),

        # Signed headers
        ';'.join(signed_headers),

        # Signature
        hashlib.sha256(data).hexdigest()])
    canon_req_hash = hashlib.sha256(canon_req).hexdigest()

    # Compute the string to sign
    sig_string = '\n'.join([
        'AWS4-HMAC-SHA256',
        headers['x-amz-date'],
        '{}/{}/{}/aws4_request'.format(
            time.strftime('%Y%m%d', now),
            region,
            service),
        canon_req_hash])

    # Compute the signing key
    sig_key = hmac_sha256(
            'AWS4' + aws_key_secret,
            time.strftime('%Y%m%d', now).encode('utf-8'))
    sig_key = hmac_sha256(sig_key, region.encode('utf-8'))
    sig_key = hmac_sha256(sig_key, service)
    sig_key = hmac_sha256(sig_key, 'aws4_request')

    # Compute the signature
    sig = hmac.new(sig_key, sig_string, hashlib.sha256).hexdigest()

    # Compute the Authentication header value
    authz_value = 'AWS4-HMAC-SHA256 Credential={}/{}/{}/{}/aws4_request, SignedHeaders={}, Signature={}'.format(
            aws_key,
            time.strftime('%Y%m%d', now),
            region,
            service,
            ';'.join(signed_headers),
            sig)
    headers['authorization'] = authz_value

    return canon_req, sig_string, headers


# TODO: Add '-H' option for setting additional headers
#
# TODO: Add '-T' option for entering unittest mode and validating against AWS4
#       .creq/etc directory tree
def main():
    import argparse
    import os
    import sys

    ap = argparse.ArgumentParser(description='''
Generate an 'Authorization' header for used in signing AWS requests.
''')
    ap.add_argument(
            '-d', dest='data', action='store_true', default=False,
            help='read req body from stdin; change from GET to POST')
    ap.add_argument(
            '-k', dest='aws_key', metavar='<key>',
            help='AWS access key; defaults to $AWS_ACCESS_KEY_ID')
    ap.add_argument(
            '-K', dest='aws_key_secret', metavar='<key_secret>',
            help='AWS secret access key; defaults to $AWS_SECRET_ACCESS_KEY')
    ap.add_argument(
            '-t', dest='time', type=int, metavar='<secs>',
            default=int(time.time()),
            help='current time in local epoch seconds; defaults to now')
    ap.add_argument(
            '-s', dest='service', metavar='<service>',
            help='AWS service name (e.g. route53); default guessed from URL')
    ap.add_argument(
            '-r', dest='region', metavar='<region>',
            help='AWS region name (e.g. us-east-1); default guessed from URL')
    ap.add_argument('url', metavar='<url>', help='URL to sign')
    args = ap.parse_args()

    if args.aws_key is None:
        if 'AWS_ACCESS_KEY_ID' not in os.environ:
            ap.error('no access key specified; must use -k option or '
                     'set $AWS_ACCESS_KEY_ID')

        args.aws_key = os.environ['AWS_ACCESS_KEY_ID']

    if args.aws_key_secret is None:
        if 'AWS_SECRET_ACCESS_KEY' not in os.environ:
            ap.error('no secret access key specified; must use -K option or '
                     'set $AWS_SECRET_ACCESS_KEY')

        args.aws_key_secret = os.environ['AWS_SECRET_ACCESS_KEY']

    data = data.stdin.read() if args.data else ''
    method = 'POST' if len(data) > 0 else 'GET'

    _, _, headers = aws4_signature_parts(
            args.aws_key,
            args.aws_key_secret,
            method,
            args.url,
            data=data,
            headers=None,
            now=time.gmtime(args.time),
            region=args.region,
            service=args.service)

    print headers['authorization']


if __name__ == '__main__':
    main()
