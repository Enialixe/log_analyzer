#!/usr/bin/env python
# -*- coding: utf-8 -*-


# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';
import itertools
import json
import re
import gzip
import io
import os
import logging
import argparse
from datetime import datetime
from string import Template
from operator import itemgetter

SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_STR = re.compile('^([\d.]+)\s.+\s([\d.-]+)\s\[([^\]]+)\]\s"(?P<url>[^"]+)"'
                     '\s[1-5]\d\d\s\d+\s".+"\s"([^"]+)"\s(".+")\s(".+")'
                     '\s(".+")\s(?P<time>[\d.]+)$')
LOG_FORMAT = re.compile('^nginx-access-ui\.log-(?P<date>\d{8})(\.gz)?$')
DEFAULT_CONFIG_PATH = os.path.join(SCRIPT_PATH, 'config.json')

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": os.path.join(SCRIPT_PATH, "reports"),
    "LOG_DIR": os.path.join(SCRIPT_PATH, "log")
}


def load_conf(conf_path):
    if os.path.isfile(conf_path):
        with open(conf_path, 'rb') as f:
            config = json.load(f, encoding='utf-8')
        return config


def init_logger(log_path):
    logging.basicConfig(filename=log_path, level=logging.DEBUG,
                        format='[%(asctime)s] %(levelname).1s %(message)s',
                        datefmt='%Y.%m.%d %H:%M:%S')
    logging.info('Loggin is started')


def find_last_log(log_dir):
    last_date = None
    last_log = None
    for entry in os.listdir(log_dir):
        match = LOG_FORMAT.match(entry)
        if match:
            date, ext = match.groups()
            try:
                date_dt = datetime.strptime(str(date), '%Y%m%d').date()
            except ValueError as exc:
                logging.debug(f"Incorrect date format for {entry}")
                continue
            if not last_date or date_dt>last_date:
                last_date = date_dt
                last_log = os.path.join(log_dir, entry)
    return last_log, last_date


def find_report_path(report_dir, lastdate):
    report_path = os.path.join(report_dir, "report-" +
                               lastdate.strftime('%Y.%m.%d') + '.html')
    if not os.path.isfile(report_path):
        return report_path


def read_log(log_path, error_limit=None):
    open_log = gzip.open if log_path.endswith('.gz') else io.open
    with open_log(log_path, "rb") as f:
        log_line_count = 0
        error = 0
        for log_line in f:
            log_line = log_line.decode('utf-8')
            log_line_count += 1
            parsed_log_line = parse_log_lines(log_line)
            if not parsed_log_line:
                error += 1
                continue
            yield parsed_log_line
    if error_limit and log_line_count and error / log_line_count > error_limit:
        raise RuntimeError('Too many corrupted data in log')


def parse_log_lines(log_line):
    if LOG_STR.match(log_line):
        searched = LOG_STR.search(log_line)
        url = searched.group('url')
        url = url.split(' ')[1]
        req_time = float(searched.group('time'))
        return url, req_time


def median(lst):
    quotient, remainder = divmod(len(lst), 2)
    if remainder:
        return sorted(lst)[quotient]
    return sum(sorted(lst)[quotient - 1:quotient + 1]) / 2.


def stat_calc(log_generator, report_size):
    stat_table = []
    total_urls = 0
    sorted_log = sorted(log_generator, key=itemgetter(0))
    for url, requests in itertools.groupby(sorted_log,
                                        itemgetter(0)):
        requests = list(requests)
        url_statistics = {
            'url': url,
            'count': len(requests),
            'time_sum': 0,
            'time_max': 0
        }
        time_list = []
        for _, req_time in requests:
            url_statistics['time_sum'] = url_statistics['time_sum'] + req_time
            time_list.append(req_time)
            if req_time > url_statistics['time_max']:
                url_statistics['time_max'] = req_time
        url_statistics['time_avg'] = url_statistics['time_sum'] / len(time_list)
        url_statistics['time_med'] = median(time_list)
        total_urls = total_urls + url_statistics['count']
        stat_table.append(url_statistics)
    for url_statistics in stat_table:
        url_statistics['count_perc'] = url_statistics['count'] / total_urls
    return sorted(stat_table, key=itemgetter('time_sum'),
                  reverse=True)[:report_size]


def write_report(report_path, report, template_path):
    with open(template_path, 'rb') as f:
        template = Template(f.read().decode('utf-8'))
    template = template.safe_substitute(table_json=report)
    with open(report_path, 'wb') as f:
        f.write(template.encode('utf-8'))


def main(config):
    logging.info('Finding last log')
    last_log, last_date = find_last_log(config.get('LOG_DIR'))
    if not last_log:
        logging.debug('No correct log in directory')
        return
    report_path = find_report_path(config.get('REPORT_DIR'),
                                   last_date)
    if not report_path:
        logging.debug('Results is up to date')
        return
    logging.info('Reading and parsing log')
    log_lines = read_log(last_log, config.get['ERROR_LIMIT'])
    logging.info('Making report table')
    res_table = stat_calc(log_lines, config.get('REPORT_SIZE'))
    logging.info('Writing report to ' + report_path)
    if not config.get('TEMPLATE_PATH'):
        config['TEMPLATE_PATH'] = os.path.join(SCRIPT_PATH, 'report.html')
    write_report(report_path, res_table, config['TEMPLATE_PATH'])
    logging.info('Parsing complete successfully')


if __name__ == "__main__":
    commandline_parser = argparse.ArgumentParser()
    commandline_parser.add_argument('--config', default=DEFAULT_CONFIG_PATH)
    args = commandline_parser.parse_args()
    if args.config:
        commandline_config = load_conf(args.config)
        config.update(commandline_config)
    init_logger(config.get('SCRIPT_LOGGING_PATH'))
    try:
        main(config)
    except Exception as E:
        logging.exception(E)
