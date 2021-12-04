#!/usr/bin/python3

from config import *
from datetime import datetime, timedelta
from helpers import misp_user_connection

import argparse
import coloredlogs
import logging
import os
import sys
import time
import urllib3

LOGGER = logging.getLogger('plaintext')
logging.basicConfig(filename='misp_feeds.log', format='%(asctime)s %(name)s %(levelname)s: %(message)s', level=logging.INFO)
coloredlogs.install(level='INFO')

PLUGIN_NAME = 'Plaintext'
PLUGIN_TYPE = 'export'
PLUGIN_ENABLED = True
PLUGIN_TIMES = ['00','15','30','45']

DEFAULT_FULL = False
PARTIAL_MINUTES = 20
EXPORT_DAYS = 90
EXPORT_PAGE_SIZE = 5000
EXPORT_TAGS = ['tlp:white','tlp:green','tlp:amber','osint:source-type="block-or-filter-list"']
EXPORT_TYPES = ['domain','email-src','email-subject','hostname','url','ip-dst','ip-src','sha256']
EXPORT_MERGE_HOSTNAME = True
EXPORT_PATH = '/var/www/MISP/app/webroot/export'
EXPORT_KEY = 'RANDOM KEY'

def disable_ssl_warnings():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def plugin_run(misp, start_fresh=DEFAULT_FULL):
    LOGGER.info('Loading custom whitelist...')

    with open(WHITELIST_FILE, mode='r', encoding='utf-8') as in_file:
        white_list = [line.rstrip('\n') for line in in_file]

    for attr_type in EXPORT_TYPES:
        if EXPORT_MERGE_HOSTNAME:
            if all(t in EXPORT_TYPES for t in ['domain', 'hostname']) and attr_type == 'domain':
                LOGGER.info('Collecting attribute types: domain, hostname')
                attr_type = ['domain', 'hostname']
                out_path = os.path.join(EXPORT_PATH, 'domain_{0}.txt'.format(EXPORT_KEY))

            if all(t in EXPORT_TYPES for t in ['domain', 'hostname']) and attr_type == 'hostname':
                continue

        if attr_type != ['domain', 'hostname']:
            LOGGER.info('Collecting attribute type: {0}'.format(attr_type))
            file_name = '{0}_{1}.txt'.format(attr_type, EXPORT_KEY)
            out_path = os.path.join(EXPORT_PATH, file_name)

        if not os.path.exists(out_path):
            LOGGER.info('Making new file: {0}'.format(out_path))
            open(out_path, mode='a').close()

        LOGGER.info('Writing to: {0}'.format(out_path))

        attr_page = 0

        if start_fresh:
            LOGGER.info('Performing full update.')
            date_from = (datetime.utcnow() - timedelta(days=EXPORT_DAYS)).strftime('%Y-%m-%d')

        else:
            LOGGER.info('Performing partial update.')
            date_from = (datetime.utcnow() - timedelta(minutes=PARTIAL_MINUTES)).strftime('%Y-%m-%d')

        attr_list = []

        while True:
            attr_search = misp.search(controller='attributes', type_attribute=attr_type, tags=EXPORT_TAGS, date_from=date_from, limit=EXPORT_PAGE_SIZE, page=attr_page, return_format='csv', requested_attributes=['value'], headerless=True, metadata=False, enforce_warninglist=True)
            attr_lines = attr_search.splitlines()

            if len(attr_lines) > 1:
                LOGGER.info('Fetched page: {0}'.format(attr_page))
                page_list = [attr[1:-1] for attr in attr_lines]
                attr_list.extend(page_list)
                attr_page += 1

            else:
                break

        if attr_list:
            if start_fresh:
                LOGGER.info('Saving all attributes...')
                attr_set = set(attr_list)

            else:
                LOGGER.info('Saving new attributes...')

                with open(out_path, mode='rt', encoding='utf-8') as in_file:
                    current_list = [line.rstrip('\n') for line in in_file]

                if current_list:
                    LOGGER.info('Merging with current list...')
                    attr_set = set(current_list + attr_list)

                else:
                    LOGGER.info('File is currently empty.')
                    attr_set = set(attr_list)

            LOGGER.info('Sorting list...')
            sorted_list = sorted(list(attr_set))
            sorted_list = list(filter(None, sorted_list))

            LOGGER.info('Applying whitelist...')
            sorted_list = [attr for attr in sorted_list if attr not in white_list]

            with open(out_path, mode='wt', encoding='utf-8') as out_file:
                out_file.write('\n'.join(sorted_list))

        else:
            LOGGER.warning('No attributes returned.')

    LOGGER.info('Run complete!')

if __name__ == '__main__':
    misp = misp_user_connection()

    parser = argparse.ArgumentParser()
    parser.add_argument('--full', default=False, action='store_true')

    args = parser.parse_args()

    plugin_run(misp, start_fresh=args.full)
