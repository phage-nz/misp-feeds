#!/usr/bin/python3

# Based on: https://github.com/microsoftgraph/security-api-solutions/tree/master/Samples/MISP

from config import *
from datetime import date, datetime, timedelta
from helpers import misp_user_connection

import coloredlogs
import json
import logging
import requests

LOGGER = logging.getLogger('graphmisp')
logging.basicConfig(filename='misp_feeds.log', format='%(asctime)s %(name)s %(levelname)s: %(message)s', level=logging.INFO)
coloredlogs.install(level='INFO')

PLUGIN_NAME = 'Graph API'
PLUGIN_TYPE = 'export'
PLUGIN_ENABLED = True
PLUGIN_TIMES = ['00']

DEFAULT_FULL = True
DEFAULT_TLP = 'white'

MISP_EVENT_FILTERS = {
    'tags': ['type:OSINT'],
    'last': '70m'
}

DAYS_TO_EXPIRE = 30

GRAPH_TENANT_ID = 'YOUR TENANT ID'
GRAPH_CLIENT_ID = 'YOUR CLIENT ID'
GRAPH_CLIENT_SECRET = 'YOUR CLIENT SECRET'

GRAPH_ACTION = 'alert'
GRAPH_PASSIVE_ONLY = False
GRAPH_TARGET_PRODUCT = 'Azure Sentinel'
GRAPH_BATCH_SIZE = 100
GRAPH_HISTORY_FILE = 'graph.history'

GRAPH_TI_INDICATORS_URL = 'https://graph.microsoft.com/beta/security/tiIndicators'
GRAPH_BULK_POST_URL = '{0}/submitTiIndicators'.format(GRAPH_TI_INDICATORS_URL)
GRAPH_BULK_DEL_URL = '{0}/deleteTiIndicators'.format(GRAPH_TI_INDICATORS_URL)

ATTRIBUTE_MAPPING = {
    'AS': 'networkSourceAsn',
    'domain': 'domainName',
    'email-dst': 'emailRecipient',
    'email-src-display-name': 'emailSenderName',
    'email-subject': 'emailSubject',
    'email-x-mailer': 'emailXMailer',
    'filename': 'fileName',
    'hostname': 'domainName',
    'malware-type': 'malwareFamilyNames',
    'mutex': 'fileMutexName',
    'port': 'networkPort',
    'published': 'isActive',
    'size-in-bytes': 'fileSize',
    'url': 'url',
    'user-agent': 'userAgent',
    'uuid': 'externalId'
}

MISP_HASH_TYPES = frozenset([
    "filename|authentihash",
    "filename|impfuzzy",
    "filename|imphash",
    "filename|md5",
    "filename|pehash",
    "filename|sha1",
    "filename|sha224",
    "filename|sha256",
    "filename|sha384",
    "filename|sha512",
    "filename|sha512/224",
    "filename|sha512/256",
    "filename|ssdeep",
    "filename|tlsh",
    "authentihash",
    "impfuzzy",
    "imphash",
    "md5",
    "pehash",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha512/224",
    "sha512/256",
    "ssdeep",
    "tlsh",
])

MISP_SPECIAL_CASE_TYPES = frozenset([
    *MISP_HASH_TYPES,
    'ip-dst',
    'ip-src',
    'domain|ip',
    'email-src',
    'ip-dst|port',
    'ip-src|port'
])

MISP_ACTIONABLE_TYPES = frozenset([
    *ATTRIBUTE_MAPPING.keys(),
    *MISP_SPECIAL_CASE_TYPES
])

EVENT_MAPPING = {
    'date': 'firstReportedDateTime',
    'timestamp': 'lastReportedDateTime',
    'info': 'description',
    'uuid': 'externalId'
}

REQUIRED_GRAPH_METADATA = frozenset([
    "threatType",
    "tlpLevel",
    "description",
    "expirationDateTime",
    "targetProduct",
])

OPTIONAL_GRAPH_METADATA = frozenset([
    "activityGroupNames",
    "additionalInformation",
    "confidence",
    "diamondModel",
    "externalId",
    "isActive",
    "killChain",
    "knownFalsePositives",
    "lastReportedDateTime",
    "malwareFamilyNames",
    "passiveOnly",
    "severity",
    "tags",
])

GRAPH_OBSERVABLES = frozenset([
    "emailEncoding",
    "emailLanguage",
    "emailRecipient",
    "emailSenderAddress",
    "emailSenderName",
    "emailSourceDomain",
    "emailSourceIPAddress",
    "emailSubject",
    "emailXMailer",
    "fileCompileDateTime",
    "fileCreationDateTime",
    "fileHashType",
    "fileHashValue",
    "fileMutexName",
    "fileName",
    "filePacker",
    "filePath",
    "fileSize",
    "fileType",
    "domainName",
    "networkIPv4",
    "networkIPv6",
    "networkPort",
    "networkDestinationAsn",
    "networkDestinationCidrBlock",
    "networkDestinationIPv4",
    "networkDestinationIPv6",
    "networkDestinationPort",
    "networkProtocol",
    "networkSourceAsn",
    "networkSourceCidrBlock",
    "networkSourceIPv4",
    "networkSourceIPv6",
    "networkSourcePort",
    "url",
    "userAgent",
])

def disable_ssl_warnings():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class GraphAttribute:
    def __init__(self, attribute):
        mapping = ATTRIBUTE_MAPPING.get(attribute['type'])

        if mapping is not None:
            setattr(self, mapping, attribute['value'])

        if attribute['type'] in MISP_SPECIAL_CASE_TYPES:
            self.parse_special_cases(attribute)

        self.tags = [x['name'] for x in attribute.get('Tag', [])]

    def parse_ip(self, attribute, attribute_type, v4_name, v6_name):
        if attribute['type'] == attribute_type:
            if '.' in attribute['value']:
                setattr(self, v4_name, attribute['value'])

            else:
                setattr(self, v6_name, attribute['value'])

    def aggregated_parse_ip(self, attribute):
        self.parse_ip(attribute, 'ip-dst', 'networkDestinationIPv4', 'networkDestinationIPv6')
        self.parse_ip(attribute, 'ip-src', 'networkSourceIPv4', 'networkSourceIPv6')

    def parse_file_hash(self, attribute):
        if attribute['type'] in MISP_HASH_TYPES:
            if 'filename|' in attribute['type']:
                self.fileHashType = attribute['type'].split('|')[1]
                self.fileName, self.fileHashValue = attribute['value'].split('|')

            else:
                self.fileHashType = attribute['type']
                self.fileHashValue = attribute['value']

            if self.fileHashType not in ['sha1', 'sha256', 'md5', 'authenticodeHash256', 'lsHash', 'ctph']:
                self.fileHashType = 'unknown'

    def parse_email_src(self, attribute):
        if attribute['type'] == 'email-src':
            self.emailSenderAddress = attribute['value']
            self.emailSourceDomain = attribute['value'].split('@')[1]

    def parse_ip_port(self, attribute):
        if attribute['type'] == 'ip-dst|port' or attribute['type'] == 'ip-src|port':
            ip = attribute['value'].split('|')[0]
            port = attribute['value'].split('|')[1]

            if attribute['type'] == 'ip-dst|port':
                self.networkDestinationPort = port

                if '.' in attribute['value']:
                    self.networkDestinationIPv4 = ip

                else:
                    self.networkDestinationIPv6 = ip

            elif attribute['type'] == 'ip-src|port':
                self.networkSourcePort = port

                if '.' in attribute['value']:
                    self.networkSourceIPv4 = ip

                else:
                    self.networkSourceIPv6 = ip

    def parse_domain_ip(self, attribute):
        if attribute['type'] == 'domain|ip':
            self.domainName, ip = attribute['value'].split('|')

            if '.' in ip:
                self.networkIPv4 = ip

            else:
                self.networkIPv6 = ip

    def parse_special_cases(self, attribute):
        self.aggregated_parse_ip(attribute)
        self.parse_domain_ip(attribute)
        self.parse_email_src(attribute)
        self.parse_ip_port(attribute)
        self.parse_file_hash(attribute)

class GraphApi:
    def __enter__(self):
        self.expiration_date = datetime.utcnow() + timedelta(days=DAYS_TO_EXPIRE)
        self.threshold_date = datetime.now() - timedelta(days=DAYS_TO_EXPIRE)

        try:
            self.history_file = open(GRAPH_HISTORY_FILE, 'r+')
            self.history_data = json.load(self.history_file)

        except (FileNotFoundError, json.decoder.JSONDecodeError):
            self.history_file = open(GRAPH_HISTORY_FILE, 'w')
            self.history_data = {}

        access_token = self.get_access_token(GRAPH_TENANT_ID, GRAPH_CLIENT_ID, GRAPH_CLIENT_SECRET)
        self.headers = {'Authorization': 'Bearer {0}'.format(access_token), 'User-Agent': 'MISP/1.0'}
        self.headers_expiration_time = self.get_timestamp() + 3500
        self.send_list = []

        return self

    def get_timestamp(self):
        return datetime.now().timestamp()

    def get_access_token(self, tenant, client_id, client_secret):
        data = {
            'client_id': client_id,
            'scope': 'https://graph.microsoft.com/.default',
            'client_secret': client_secret,
            'grant_type': 'client_credentials'
        }

        try:
            access_token = requests.post('https://login.microsoftonline.com/{0}/oauth2/v2.0/token'.format(tenant), data=data).json()['access_token']

            return access_token

        except Exception as ex:
            LOGGER.error('Error authenticating aginst Graph API: {0}'.format(str(ex)))
            sys.exit(1)

    def update_headers_if_expired(self):
        if self.get_timestamp() > self.headers_expiration_time:
            access_token = self.get_access_token(GRAPH_TENANT_ID, GRAPH_CLIENT_ID, GRAPH_CLIENT_SECRET)
            self.headers = {'Authorization': 'Bearer {0}'.format(access_token), 'User-Agent': 'MISP/1.0'}

    def update_history_data(self, response_json):
        if 'error' in response_json:
            LOGGER.error('Error received from Graph API: {0}'.format(response_json['error']))

        if len(response_json['value']) == 0:
            return

        response_value = response_json['value']

        for value in response_value:
            if 'error' in value:
                LOGGER.error('Error received from Graph API: {0}'.format(value['error']))

            else:
                if not value['id'] in self.history_data:
                    self.history_data[value['id']] = datetime.now().isoformat()

    def update_history_file(self):
        LOGGER.info('Updating history file...')

        self.history_file.seek(0)
        json.dump(self.history_data, self.history_file, indent=2)
        self.history_file.truncate()

    def post_to_graph(self):
        request_body = {'value': self.send_list}

        try:
            response = requests.post(GRAPH_BULK_POST_URL, headers=self.headers, json=request_body).json()
            self.update_history_data(response)
            self.send_list = []

            return True

        except Exception as ex:
            LOGGER.error('Error sending attributes to Graph API: {0}'.format(str(ex)))

        return False

    def get_request_hash(self, request):
        return str(hash(frozenset({
            k: str(v) for k, v in request.items()
            if k != 'expirationDateTime' and k != 'lastReportedDateTime'
        }.items())))

    def stage_request(self, request_body):
        self.update_headers_if_expired()
        request_body['expirationDateTime'] = self.expiration_date.isoformat()
        request_hash = self.get_request_hash(request_body)
        request_body['indicatorRequestHash'] = request_hash
        self.send_list.append(request_body)

        if len(self.send_list) >= GRAPH_BATCH_SIZE:
            return self.post_to_graph()

        return True

    def prune(self):
        expired_indicators = [x for x in self.history_data if datetime.fromisoformat(self.history_data[x]) <= self.threshold_date]
        expired_count = len(expired_indicators)

        if expired_count == 0:
            LOGGER.info('There are no indicators to prune.')
            return

        LOGGER.info('Pruning {0} expired indicators...'.format(expired_count))

        for i in range(0, expired_count, GRAPH_BATCH_SIZE):
            request_body = {'value': expired_indicators[i: i+GRAPH_BATCH_SIZE]}

            try:
                response = requests.post(GRAPH_BULK_DEL_URL, headers=self.headers, json=request_body)

            except Exception as ex:
                LOGGER.error('Error pruning expired Graph API indicators: {0}'.format(str(ex)))
                return

        [history_data.pop(x) for x in expired_indicators]

        LOGGER.info('Pruning complete.')

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.post_to_graph()
        self.update_history_file()

def get_events(misp):
    LOGGER.info('Fetching MISP events...')

    return misp.search(controller='events', return_format='json', **MISP_EVENT_FILTERS)

def form_requests(parsed_events):
    request_list = []

    for event in parsed_events:
        request_metadata = {}
        request_metadata['action'] = GRAPH_ACTION
        request_metadata['passiveOnly'] = GRAPH_PASSIVE_ONLY
        request_metadata['threatType'] = 'watchlist'
        request_metadata['targetProduct'] = GRAPH_TARGET_PRODUCT

        for field in [x for x in REQUIRED_GRAPH_METADATA if x in event]:
            request_metadata[field] = event[field]

        for field in [x for x in OPTIONAL_GRAPH_METADATA if x in event]:
            request_metadata[field] = event[field]

        for request_object in event['request_objects']:
            request_list.append({
                **request_metadata.copy(),
                **request_object.__dict__,
                'tags': request_metadata.copy()['tags'] + request_object.__dict__['tags']
            })

    return request_list

def parse_events(misp_events):
    parsed_events = []

    LOGGER.info('Beginning processing of MISP events...')

    for event in misp_events:
        misp_event = event['Event']
        parsed_event = {'request_objects':[]}

        for key, mapping in EVENT_MAPPING.items():
            parsed_event[mapping] = misp_event[key]

        parsed_event['tags'] = [x['name'] for x in misp_events[0]['Event']['Tag']]

        for tag in parsed_event['tags']:
            if tag.startswith('tlp'):
                parsed_event['tlpLevel'] = tag.split(':')[1]

        if 'tlpLevel' in parsed_event:
            parsed_event['tlpLevel'] = DEFAULT_TLP

        parsed_event['lastReportedDateTime'] = str(datetime.fromtimestamp(int(parsed_event['lastReportedDateTime'])))

        for attribute in misp_event['Attribute']:
            if attribute['type'] == 'threat-actor':
                parsed_event['activityGroupNames'].append(attribute['value'])

            if attribute['type'] == 'comment':
                parsed_event['description'] += attribute['value']

            if attribute['type'] in MISP_ACTIONABLE_TYPES:
                parsed_event['request_objects'].append(GraphAttribute(attribute))

        parsed_events.append(parsed_event)

        attribute_count = sum([len(x['request_objects']) for x in parsed_events])

        LOGGER.info('{0} attributes will be sent to Graph API in batches of {1}...'.format(attribute_count, GRAPH_BATCH_SIZE))

        with GraphApi() as graph_api:
            for request_body in form_requests(parsed_events):
                stage_success = graph_api.stage_request(request_body)

                if not stage_success:
                    break

    with GraphApi() as graph_api:
        graph_api.prune()

    LOGGER.info('Attribute submission complete!')

def plugin_run(misp, start_fresh=DEFAULT_FULL):
    LOGGER.info('Beginning Graph API run...')
    misp_events = get_events(misp)

    if len(misp_events) > 0:
        parse_events(misp_events)

    else:
        LOGGER.warning('Event list is empty.')

    LOGGER.info('Run complete!')

if __name__ == '__main__':
    misp = misp_user_connection()
    plugin_run(misp)
