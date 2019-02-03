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

SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_STR = re.compile('^([\d.]+)\s.+\s([\d.-]+)\s\[([^\]]+)\]\s"(?P<url>[^"]+)"'
                     '\s[1-5]\d\d\s\d+\s".+"\s"([^"]+)"\s(".+")\s(".+")'
                     '\s(".+")\s(?P<time>[\d.]+)$')
LOG_FORMAT = re.compile('^(nginx-access-ui\.log-)(?P<date>\d{8})(\.gz)?$')
DEFAULT_CONFIG_PATH = os.path.join(SCRIPT_PATH, 'config.json')

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": SCRIPT_PATH + "\\reports",
    "LOG_DIR": SCRIPT_PATH + "\\log"
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
    logging.info('Finding last log')

    files = sorted([file for file in os.listdir(log_dir)
                    if LOG_FORMAT.match(file)],
                   key=lambda x: LOG_FORMAT.search(x).group('date'),
                   reverse=True)
    if len(files) > 0:
        logging.debug(files[0])
        lastdate = datetime.strptime(
                LOG_FORMAT.search(files[0]).group('date'), '%Y%m%d')
        logging.debug(lastdate)
        log_path = os.path.join(log_dir, files[0])
        logging.debug(lastdate)
        return log_path
    else:
        logging.debug('No correct log in directory')
        return None


def find_report_path(log_dir, report_dir, log_path):
    lastdate = datetime.strptime(
        LOG_FORMAT.search(os.path.relpath(log_path, log_dir)).group('date'),
        '%Y%m%d')
    report_path = os.path.join(report_dir, "report-" +
                               lastdate.strftime('%Y.%m.%d') + '.html')
    if os.path.isfile(report_path):
        logging.debug('Result is up to date')
        return None
    return report_path


def read_log(log_path, error_limit=None):
    logging.info('Reading and parsing log')
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
    logging.info('Making report table')
    table = []
    total_urls = 0
    for key, group in itertools.groupby(sorted(log_generator,
                                               key=lambda x: x[0]),
                                        lambda x: x[0]):
        group_list = list(group)
        table_element = {
            'url': key,
            'count': len(group_list),
            'time_sum': 0,
            'time_max': 0
        }
        time_list = []
        for element in group_list:
            table_element['time_sum'] = table_element['time_sum'] + element[1]
            time_list.append(element[1])
            if element[1] > table_element['time_max']:
                table_element['time_max'] = element[1]
        table_element['time_avg'] = table_element['time_sum'] / len(time_list)
        table_element['time_med'] = median(time_list)
        table.append(table_element)
        total_urls = total_urls + len(group_list)
    for table_element in table:
        table_element['count_perc'] = table_element['count'] / total_urls
    return sorted(table, key=lambda x: x['time_sum'],
                  reverse=True)[:report_size]


def write_report(report_path, report):
    logging.info('Writing report to ' + report_path)
    with open(os.path.join(SCRIPT_PATH, 'report.html'), 'rb') as f:
        template = Template(f.read().decode('utf-8'))
    template = template.safe_substitute(table_json=report)
    with open(report_path, 'wb') as f:
        f.write(template.encode('utf-8'))


def main(config):
    last_log = find_last_log(config.get('LOG_DIR'))
    if last_log:
        report_path = find_report_path(config.get('LOG_DIR'),
                                       config.get('REPORT_DIR'),
                                       last_log)
        if report_path:
            log_lines = read_log(last_log, config.get['ERROR_LIMIT'])
            res_table = stat_calc(log_lines, config.get('REPORT_SIZE'))
            write_report(report_path, res_table)
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
