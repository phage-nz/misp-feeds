#!/usr/bin/python3

from collections import Counter
from config import *
from datetime import datetime, timedelta
from helpers import disable_ssl_warnings, is_valid_url
from pymisp import MISPEvent, MISPAttribute, ThreatLevel, Distribution, Analysis

import coloredlogs
import json
import logging
import os
import sys
import requests
import time

LOGGER = logging.getLogger('phishmisp')
logging.basicConfig(filename='misp_feeds.log', format='%(asctime)s %(name)s %(levelname)s: %(message)s', level=logging.INFO)
coloredlogs.install(level='INFO')

PLUGIN_NAME = 'Phishing'
PLUGIN_ENABLED = True
PLUGIN_TIMES = ['hourly']

MISP_EVENT_TITLE = 'Phishing indicator feed'
MISP_TO_IDS = False
MISP_PUBLISH_EVENTS = True
MISP_DISTRIBUTION = Distribution.connected_communities

PHISHTANK_URL = 'http://data.phishtank.com/data/YOUR APPLICATION KEY/online-valid.json'
OPENPHISH_URL = 'https://openphish.com/feed.txt'
URLSCAN_URL = 'https://urlscan.io/api/v1/search/'

PHISHTANK_USER = 'YOUR USERNAME'
OPENPHISH_HISTORY_FILE = 'openphish.history'
URLSCAN_KEY = 'YOUR API KEY'
URLSCAN_SEARCHES = [
    {'query':'page.url:o365 OR page.url:office OR page.url:onedrive','malicious_only':True},
    {'query':'filename:nzta.js AND NOT domain:govt.nz','malicious_only':False}
    ]

ATTRIBUTE_PROGRESS = True
SAMPLE_MAX_MINUTES = 70

class FeedIndicator:
  def __init__(self, ref_comment, ref_tags, o_type, o_value):
    self.ref_comment = ref_comment
    self.ref_tags = ref_tags
    self.o_type = o_type
    self.o_value = o_value

def make_new_event(misp):
    LOGGER.info('Creating new fixed event...')
    event = MISPEvent()
    event_date = datetime.now().strftime('%Y-%m-%d')
    event_title = '{0} {1}'.format(MISP_EVENT_TITLE, event_date)

    event.info = event_title
    event.analysis = Analysis.completed
    event.distribution = MISP_DISTRIBUTION
    event.threat_level_id = ThreatLevel.low

    event.add_tag('type:OSINT')
    event.add_tag('tlp:white')

    LOGGER.info('Saving event...')
    time.sleep(1)

    try:
        new_event = misp.add_event(event, pythonify=True)
        return new_event

    except Exception as ex:
        LOGGER.error('Failed to make MISP event: {0}'.format(str(ex)))
        return False

def get_phishtank_list():
    LOGGER.info('Fetching latest online URLs from PhishTank...')
    indicator_list = []

    try:
        headers = {'User-Agent': 'phishtank/{0}'.format(PHISHTANK_USER)}
        response = requests.get(PHISHTANK_URL, headers=headers)

        if response.status_code == 200:
            response_json = json.loads(response.text)
            date_threshold = datetime.now() - timedelta(minutes=SAMPLE_MAX_MINUTES)

            for item in response_json:
                item_timestamp = datetime.strptime(item['submission_time'], '%Y-%m-%dT%H:%M:%S+00:00')

                if item_timestamp < date_threshold:
                    continue

                url = item['url']
                comment = item['phish_detail_url']
                tags = ['PhishTank']

                if not is_valid_url(url):
                    continue

                if item['target'] != 'Other':
                    tags.append(item['target'])

                indicator_list.append(FeedIndicator(comment, tags, 'url', url))

    except Exception as e:
        LOGGER.error('PhishTank request error: {0}'.format(str(e)))

    return indicator_list

def last_openphish_item():
    if not os.path.exists(OPENPHISH_HISTORY_FILE):
        with open(OPENPHISH_HISTORY_FILE, 'w') as history_file:
            pass

    with open(OPENPHISH_HISTORY_FILE, 'r') as history_file:
        return history_file.read()

def write_openphish_history(url):
    LOGGER.info('Updating OpenPhish history file...')

    with open(OPENPHISH_HISTORY_FILE, 'w') as history_file:
        history_file.write(url)

def get_openphish_list():
    LOGGER.info('Fetching latest online URLs from OpenPhish...')
    indicator_list = []

    try:
        response = requests.get(OPENPHISH_URL)

        if response.status_code == 200:
            lines = response.text.splitlines()
            last_item = last_openphish_item()

            if last_item in lines:
                LOGGER.info('Slicing OpenPhish list...')
                item_pos = lines.index(last_item)
                valid_lines = lines[item_pos+1:]

            else:
                LOGGER.info('OpenPhish list is fresh.')
                valid_lines = lines

            for url in valid_lines:
                if not is_valid_url(url):
                    continue

                tags = ['OpenPhish']
                comment = None

                indicator_list.append(FeedIndicator(comment, tags, 'url', url))

                if url == valid_lines[-1]:
                    write_openphish_history(url)

    except Exception as e:
        LOGGER.error('OpenPhish request error: {0}'.format(str(e)))

    return indicator_list

def get_urlscan_list():
    LOGGER.info('Fetching latest URLs from urlscan...')
    indicator_list = []

    for search in URLSCAN_SEARCHES:
        try:
            query_string = '{0} AND date:>now-{1}m'.format(search['query'], str(SAMPLE_MAX_MINUTES))
            params = {'q': query_string}
            LOGGER.info('Running search: {0}'.format(query_string))
            response = requests.get(URLSCAN_URL, params=params, headers={'API-Key': URLSCAN_KEY})

        except Exception as e:
            LOGGER.error('urlscan search request error: {0}'.format(str(e)))

        if response.status_code == 200:
            LOGGER.info('Processing reports...')
            response_json = json.loads(response.text)

            if not 'results' in response_json:
                LOGGER.warning('No results for search.')
                continue

            staging_list = []

            for result in response_json['results']:
                try:
                    if result['page']['url'] in staging_list:
                        continue

                    else:
                        staging_list.append(result['page']['url'])

                    if result['page']['status'] != '200':
                        continue

                    response = requests.get(result['result'], headers={'API-Key': URLSCAN_KEY})

                    if response.status_code != 200:
                        continue

                    response_json = json.loads(response.text)

                    if not all(x in response_json for x in ('verdicts','task')):
                        continue

                    if search['malicious_only']:
                        if not bool(response_json['verdicts']['overall']['malicious']):
                            continue

                    url = response_json['task']['url']

                    if not is_valid_url(url):
                        continue

                    comment = response_json['task']['reportURL']
                    tags = ['urlscan']

                    if 'brands' in response_json['verdicts']['urlscan']:
                        for brand in response_json['verdicts']['urlscan']['brands']:
                            tags.append(brand['name'])

                    indicator_list.append(FeedIndicator(comment, tags, 'url', url))

                except Exception as e:
                    LOGGER.error('urlscan result request error: {0}'.format(str(e)))

    return indicator_list

def process_indicators(misp, indicator_list):
    event = False
    event_date = datetime.now().strftime('%Y-%m-%d')
    event_title = '{0} {1}'.format(MISP_EVENT_TITLE, event_date)

    try:
        event_search = misp.search_index(eventinfo=event_title)

    except Exception as ex:
        LOGGER.error('Failed to search for MISP event: {0}'.format(str(ex)))
        return

    if not event_search == []:
        for result in event_search:
            if result['info'] == event_title:
                event = event_search[0]

    if event:
        LOGGER.warning('Event already exists!')

        if MISP_PUBLISH_EVENTS:
            LOGGER.info('Reapplying distribution policy for event update...')
            event['timestamp'] = int(time.time())
            event['distribution'] = MISP_DISTRIBUTION
            updated_event = misp.update_event(event, event_id=event['id'], metadata=True)

    else:
        event = make_new_event(misp)

    if not event:
        LOGGER.warning('Failed to make or retrieve event.')
        return

    indicator_count = len(indicator_list)
    LOGGER.info('Processing {0} indicators...'.format(indicator_count))

    for i, indicator in enumerate(indicator_list):
        if ATTRIBUTE_PROGRESS and i % 100 == 0:
            progress_value = int(round(100 * (i / float(indicator_count))))
            LOGGER.info('Event completion: {0}%'.format(progress_value))

        #LOGGER.info('Found {0} "{1}" in: {2}'.format(indicator.o_type, indicator.o_value, indicator.ref_url))

        attribute_type = indicator.o_type
        indicator_value = indicator.o_value
        indicator_tags = indicator.ref_tags
        indicator_comment = indicator.ref_comment

        attribute_exists = False

        try:
            attribute_search = misp.search(controller='attributes', value=indicator_value, type=attribute_type)

        except Exception as ex:
            LOGGER.error('Failed to search for MISP attribute: {0}'.format(str(ex)))
            continue

        if not attribute_search['Attribute'] == []:
            for attribute_result in attribute_search['Attribute']:
                if attribute_result['value'] == indicator_value:
                    if int(attribute_result['event_id']) == int(event['id']):
                        attribute_exists = True

        if attribute_exists:
            continue

        if attribute_type == 'url':
            attribute_category = 'Network activity'

        else:
            LOGGER.warning('Unsupported indicator type: {0}'.format(attribute_type))
            continue

        attribute_json = {'category': attribute_category, 'type': attribute_type, 'value': indicator_value, 'comment': indicator_comment, 'to_ids': MISP_TO_IDS}

        try:
            new_attr = misp.add_attribute(event, attribute_json, pythonify=True)

            if indicator_tags:
                for tag in indicator_tags:
                    if tag:
                        misp.tag(new_attr, tag)

        except Exception as ex:
            LOGGER.error('Failed to add MISP attribute: {0}'.format(str(ex)))
            continue

    if MISP_PUBLISH_EVENTS:
        LOGGER.info('Publishing event...')

        try:
            misp.publish(event)

        except Exception as ex:
            LOGGER.error('Failed to publish MISP event: {0}'.format(str(ex)))

def plugin_run(misp):
    urlscan_list = get_urlscan_list()

    if len(urlscan_list) > 0:
        process_indicators(misp, urlscan_list)

    else:
        LOGGER.warning('URLScan list is empty.')

    phishtank_list = get_phishtank_list()

    if len(phishtank_list) > 0:
        process_indicators(misp, phishtank_list)

    else:
        LOGGER.warning('PhishTank list is empty.')

    openphish_list = get_openphish_list()

    if len(openphish_list) > 0:
        process_indicators(misp, openphish_list)

    else:
        LOGGER.warning('OpenPhish list is empty.')

    LOGGER.info('Run complete!')
