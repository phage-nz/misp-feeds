#!/usr/bin/python3

# Requirements:
# pip3 install coloredlogs pymisp

# References:
# https://buildmedia.readthedocs.org/media/pdf/pymisp/latest/pymisp.pdf

from config import *
from helpers import disable_ssl_warnings, load_plugins, misp_admin_connection, misp_user_connection

import coloredlogs
import logging
import sys
import time

LOGGER = logging.getLogger('mispfeedmanager')
logging.basicConfig(filename='misp_feeds.log', format='%(asctime)s %(name)s %(levelname)s: %(message)s', level=logging.INFO)
coloredlogs.install(level='INFO')

def cache_feed(misp, feed):
    LOGGER.info('Caching feed: {0}'.format(feed.name))

    try:
        misp.cache_feed(feed.id)

    except Exception as ex:
        LOGGER.error('Failed to cache MISP feed: {0}'.format(str(ex)))

def fetch_feed(misp, feed):
    LOGGER.info('Fetching feed: {0}'.format(feed.name))

    try:
        fetch = misp.fetch_feed(feed.id)

    except Exception as ex:
        LOGGER.error('Failed to fetch MISP feed: {0}'.format(str(ex)))
        return

    if 'result' in fetch:
        if 'Pull queued' in fetch['result']:
            LOGGER.info('Feed queued OK!')

            if feed.caching_enabled:
                cache_feed(misp, feed)

    else:
        LOGGER.error('Failed to queue feed.')

def start_worker():
    misp_admin = misp_admin_connection()
    misp_user = misp_user_connection()

    plugin_list = load_plugins()

    if plugin_list:
        enabled_feeds = [x for x in plugin_list if x.PLUGIN_ENABLED == True and x.PLUGIN_TYPE == 'feed']
        enabled_exports = [x for x in plugin_list if x.PLUGIN_ENABLED == True and x.PLUGIN_TYPE == 'export']

        if enabled_feeds:
            LOGGER.info('Feeds enabled:')

            for plugin in enabled_feeds:
                LOGGER.info(plugin.PLUGIN_NAME)

        if enabled_exports:
            LOGGER.info('Exports enabled:')

            for plugin in enabled_exports:
                LOGGER.info(plugin.PLUGIN_NAME)

    LOGGER.info('Starting worker...')

    while True:
        current_time = time.strftime('%H:%M')
        current_minutes = time.strftime('%M')

        if current_minutes == '00':
            LOGGER.info('Beginning hourly system feed run...')

            for feed in misp_admin.feeds(pythonify=True):
                if feed.id in HOURLY_FEEDS:
                    fetch_feed(misp_admin, feed)
                    LOGGER.info('Waiting a moment...')
                    time.sleep(2)

            LOGGER.info('Hourly system feed run complete!')

        if current_time in MISP_TIMES:
            LOGGER.info('Beginning MISP feed run...')

            for feed in misp_admin.feeds(pythonify=True):
                if (feed.source_format == 'misp' and
                  feed.enabled and
                  feed.id not in HOURLY_FEEDS):
                    fetch_feed(misp_admin, feed)
                    LOGGER.info('Waiting a moment...')
                    time.sleep(2)

            LOGGER.info('MISP feed run complete!')

        if current_time in TEXT_TIMES:
            LOGGER.info('Beginning text feed run...')

            for feed in misp_admin.feeds(pythonify=True):
                if (feed.source_format in ['text', 'csv'] and
                  feed.enabled and
                  feed.id not in HOURLY_FEEDS):
                    fetch_feed(misp_admin, feed)
                    LOGGER.info('Waiting a moment...')
                    time.sleep(2)

            LOGGER.info('Text feed run complete!')

        due_feeds = [x for x in enabled_feeds if current_time in x.PLUGIN_TIMES or current_minutes in x.PLUGIN_TIMES]

        if due_feeds:
            for feed in due_feeds:
                LOGGER.info('Beginning {0} plugin run...'.format(feed.PLUGIN_NAME))
                feed.plugin_run(misp_user)

        due_exports = [x for x in enabled_exports if current_time in x.PLUGIN_TIMES or current_minutes in x.PLUGIN_TIMES]

        if due_exports:
            if current_minutes == '00':
                LOGGER.info('Beginning full export run...')

                for export in due_exports:
                    LOGGER.info('Beginning {0} plugin run...'.format(export.PLUGIN_NAME))
                    export.plugin_run(misp_user, start_fresh=True)

                LOGGER.info('Full export run complete!')

            else:
                LOGGER.info('Beginning partial export run...')

                for export in due_exports:
                    LOGGER.info('Beginning {0} plugin run...'.format(export.PLUGIN_NAME))
                    export.plugin_run(misp_user, start_fresh=False)

                LOGGER.info('Partial export run complete!')

        time.sleep(60)

    LOGGER.info('Worker finished!')

if __name__ == '__main__':
    start_worker()
