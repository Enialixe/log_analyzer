import unittest
from log_analyzer import load_conf, find_last_log, median, parse_log_lines, read_log, make_report
import json
import os
import gzip


class LogParserTestCase(unittest.TestCase):

    def setUp(self):
        self.tests_path = os.path.dirname(os.path.abspath(__file__)) + "\\test"
        self.config = {
            "REPORT_SIZE": 500,
            "REPORT_DIR": self.tests_path,
            "LOG_DIR": self.tests_path,
            "ERROR_LIMIT": 0.6
        }

    def test_load_config(self):
        with open(self.tests_path + '\\test_conf.json', 'w', encoding='utf-8') as f:
            json.dump(self.config, f, ensure_ascii=False)
        self.assertEqual(load_conf(self.tests_path + '\\test_conf.json'), self.config)
        os.remove(self.tests_path + '\\test_conf.json')
        self.assertEqual(load_conf(self.tests_path + '\\test_conf.json'), None)

    def test_find_last_log(self):
        test_log_path_1 = self.config["LOG_DIR"] + '\\nginx-access-ui.log-20170630.gz'
        test_log_path_2 = self.config["LOG_DIR"] + '\\nginx-access-ui.log-20180630'
        test_log_path_3 = self.config["LOG_DIR"] + '\\nginx-access-ui.log-20180630.bz2'
        test_result_path_1 = self.config["REPORT_DIR"] + '\\report-2017.06.30.html'
        test_result_path_2 = self.config["REPORT_DIR"] + '\\report-2018.06.30.html'
        f1 = open(test_log_path_1, 'w')
        f2 = open(test_log_path_2, 'w')
        f3 = open(test_log_path_3, 'w')
        f1.close()
        f2.close()
        f3.close()
        self.assertEqual(find_last_log(self.config["LOG_DIR"], self.config["REPORT_DIR"]),
                         (test_log_path_2, test_result_path_2))
        os.remove(test_log_path_2)
        self.assertEqual(find_last_log(self.config["LOG_DIR"], self.config["REPORT_DIR"]),
                         (test_log_path_1, test_result_path_1))
        os.remove(test_log_path_1)
        os.remove(test_log_path_3)

    def test_median(self):
        test_list = [1, 5, 4, 3, 6]
        self.assertEqual(median(test_list), 4)

    def test_log_parse(self):
        log_string = '1.194.135.240 -  - ' \
                     '[29/Jun/2017:04:08:35 +0300] "GET /api/v2/group/7820986/statistic/sites/?date_type=day&date_'\
                     'from=2017-06-28&date_to=2017-06-28 HTTP/1.1" 200 110 "-" "python-requests/2.13.0" "-" ' \
                     '"1498698515-3979856266-4707-9836344" "8a7741a54297568b" 0.072'
        self.assertEqual(parse_log_lines(log_string), ("/api/v2/group/7820986/statistic/sites/?date_type=day&date_from="
                                                       "2017-06-28&date_to=2017-06-28", 0.072))

    def test_read_log_error_limit(self):
        log_strings = '1.194.135.240 -  - ' \
                      '[29/Jun/2017:04:08:35 +0300] "GET /api/v2/group/7820986/statistic/sites/?date_type=day&date_'\
                      'from=2017-06-28&date_to=2017-06-28 HTTP/1.1" 200 110 "-" "python-requests/2.13.0" "-" ' \
                      '"1498698515-3979856266-4707-9836344" "8a7741a54297568b" 0.072\nkjlj\nkjk\nk\nkjkj\n'

        test_log_path = self.config.get("LOG_DIR") + '\\nginx-access-ui.log-20170630'
        with open(test_log_path, 'wb') as f:
            f.write(log_strings.encode('utf-8'))
        with self.assertRaises(Exception) as context:
            list(read_log(test_log_path, self.config['ERROR_LIMIT']))
        self.assertTrue('Too many corrupted data in log' in str(context.exception))
        os.remove(test_log_path)

    def test_parse_log(self):
        log_strings = '1.194.135.240 -  - ' \
                      '[29/Jun/2017:04:08:35 +0300] "GET /api/v2/group/7820986/statistic/sites/?date_type=day&date_' \
                      'from=2017-06-28&date_to=2017-06-28 HTTP/1.1" 200 110 "-" "python-requests/2.13.0" "-" ' \
                      '"1498698515-3979856266-4707-9836344" "8a7741a54297568b" 0.072\n1.194.135.240 -  - ' \
                      '[29/Jun/2017:04:08:35 +0300] "GET /api/v2/group/7840986/statistic/sites/?date_type=day&date_' \
                      'from=2017-06-28&date_to=2017-06-28 HTTP/1.1" 200 110 "-" "python-requests/2.13.0" "-" ' \
                      '"1498698515-3979856266-4707-9836344" "8a7741a54297568b" 0.1\n1.194.135.240 -  - ' \
                      '[29/Jun/2017:04:08:35 +0300] "GET /api/v2/group/7820976/statistic/sites/?date_type=day&date_' \
                      'from=2017-06-28&date_to=2017-06-28 HTTP/1.1" 200 110 "-" "python-requests/2.13.0" "-" ' \
                      '"1498698515-3979856266-4707-9836344" "8a7741a54297568b" 0.12'
        test_log_path = self.config.get("LOG_DIR") + '\\nginx-access-ui.log-20170630'
        with open(test_log_path, 'wb') as f:
            f.write(log_strings.encode('utf-8'))
        result_table = [
            {'url': '/api/v2/group/7820976/statistic/sites/?date_type=day&date_from=2017-06-28&date_to=2017-06-28',
             'count': 1,
             'time_sum': 0.12,
             'time_max': 0.12,
             'time_avg': 0.12,
             'time_med': 0.12,
             'count_perc': 0.3333333333333333},
            {'url': '/api/v2/group/7840986/statistic/sites/?date_type=day&date_from=2017-06-28&date_to=2017-06-28',
             'count': 1,
             'time_sum': 0.1,
             'time_max': 0.1,
             'time_avg': 0.1,
             'time_med': 0.1,
             'count_perc': 0.3333333333333333},
            {'url': '/api/v2/group/7820986/statistic/sites/?date_type=day&date_from=2017-06-28&date_to=2017-06-28',
             'count': 1,
             'time_sum': 0.072,
             'time_max': 0.072,
             'time_avg': 0.072,
             'time_med': 0.072,
             'count_perc': 0.3333333333333333}]
        self.assertEqual(make_report(read_log(test_log_path), 3), result_table)


if __name__ == "__main__":
    unittest.main()
