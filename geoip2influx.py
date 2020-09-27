#! /usr/bin/env python3

from os.path import exists, isfile
from os import environ as env, stat
from platform import uname
from re import compile, match, search, IGNORECASE
from sys import path, exit
from time import sleep, time
from datetime import datetime
import logging

from geoip2.database import Reader
from geohash2 import encode
from influxdb import InfluxDBClient
from requests.exceptions import ConnectionError
from influxdb.exceptions import InfluxDBServerError, InfluxDBClientError
from IPy import IP as ipadd

# Logging
log_level = env.get('GEOIP2INFLUX_LOG_LEVEL', 'info').upper()
logging.basicConfig(level=log_level, format='%(asctime)s :: %(levelname)s :: %(message)s', datefmt='%d/%b/%Y %H:%M:%S')


class NginxLogParser():
    POLLING_PERIOD = 3
    RE_IPV4 = compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    RE_IPV6 = compile(r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))') # NOQA
    RE_LOGIPV4 = compile(r'(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - (?P<remote_user>.+) \[(?P<dateandtime>\d{2}\/[A-Z]{1}[a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2} ((\+|\-)\d{4}))\](["](?P<method>.+)) (?P<referrer>.+) ((?P<http_version>HTTP\/[1-3]\.[0-9])["]) (?P<status_code>\d{3}) (?P<bytes_sent>\d{1,99})(["](?P<url>(\-)|(.+))["]) (?P<host>.+) (["](?P<user_agent>.+)["])(["](?P<request_time>.+)["]) (["](?P<connect_time>.+)["])', IGNORECASE) # NOQA
    RE_LOGIPV6 = compile(r'(?P<ipaddress>(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))) - (?P<remote_user>.+) \[(?P<dateandtime>\d{2}\/[A-Z]{1}[a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2} ((\+|\-)\d{4}))\](["](?P<method>.+)) (?P<referrer>.+) ((?P<http_version>HTTP\/[1-3]\.[0-9])["]) (?P<status_code>\d{3}) (?P<bytes_sent>\d{1,99})(["](?P<url>(\-)|(.+))["]) (?P<host>.+) (["](?P<user_agent>.+)["])(["](?P<request_time>.+)["]) (["](?P<connect_time>.+)["])', IGNORECASE) # NOQA

    DEFAULT_LOG_PATH = '/config/log/nginx/access.log'
    DEFAULT_INFLUX_HOST = 'localhost'
    DEFAULT_INFLUX_HOST_PORT = '8086'
    DEFAULT_INFLUX_DATABASE = 'geoip2influx'
    DEFAULT_INFLUX_USER = 'root'
    DEFAULT_INFLUX_PASS = 'root'
    DEFAULT_INFLUX_RETENTION = '7d'
    DEFAULT_INFLUX_SHARD = '1d'
    DEFAULT_GEO_MEASUREMENT = 'geoip2influx'
    DEFAULT_LOG_MEASUREMENT = 'nginx_access_logs'
    DEFAULT_SEND_NGINX_LOGS = 'true'

    def __init__(
        self,
        geoip_db_path='/config/geoip2db/GeoLite2-City.mmdb',
        log_path=DEFAULT_LOG_PATH,
        influxdb_host=DEFAULT_INFLUX_HOST,
        influxdb_port=DEFAULT_INFLUX_HOST_PORT,
        influxdb_database=DEFAULT_INFLUX_DATABASE,
        influxdb_user=DEFAULT_INFLUX_USER,
        influxdb_user_pass=DEFAULT_INFLUX_PASS,
        influxdb_retention=DEFAULT_INFLUX_RETENTION,
        influxdb_shard=DEFAULT_INFLUX_SHARD,
        geo_measurement=DEFAULT_GEO_MEASUREMENT,
        log_measurement=DEFAULT_LOG_MEASUREMENT,
        send_nginx_logs=DEFAULT_SEND_NGINX_LOGS,
    ):
        self.geoip_db_path = geoip_db_path
        self.log_path = log_path
        self.influxdb_host = influxdb_host
        self.influxdb_port = influxdb_port
        self.influxdb_database = influxdb_database
        self.influxdb_user = influxdb_user
        self.influxdb_user_pass = influxdb_user_pass
        self.influxdb_retention = influxdb_retention
        self.influxdb_shard = influxdb_shard
        self.geo_measurement = geo_measurement
        self.log_measurement = log_measurement
        self.send_nginx_logs = send_nginx_logs
        self.geoip_db_path = geoip_db_path
        logging.debug(
            'Log parser config:' +
            f'\n geoip_db_path      :: {self.geoip_db_path}' +
            f'\n log_path           :: {self.log_path}' +
            f'\n influxdb_host      :: {self.influxdb_host}' +
            f'\n influxdb_port      :: {self.influxdb_port}' +
            f'\n influxdb_database  :: {self.influxdb_database}' +
            f'\n influxdb_retention :: {self.influxdb_retention}' +
            f'\n influxdb_shard     :: {self.influxdb_shard}' +
            f'\n influxdb_user      :: {self.influxdb_user}' +
            f'\n influxdb_user_pass :: {self.influxdb_user_pass}' +
            f'\n geo_measurement    :: {self.geo_measurement}' +
            f'\n log_measurement    :: {self.log_measurement}' +
            f'\n send_nginx_logs    :: {self.send_nginx_logs}'
        )
        self.influxdb = self.init_influxdb()
        self.geoip = Reader(self.geoip_db_path)
        self.hostname = uname()[1]

    @classmethod
    def from_env(cls):
        # Getting params from envs
        return cls(
            log_path=env.get('NGINX_LOG_PATH', cls.DEFAULT_LOG_PATH),
            influxdb_host=env.get('INFLUX_HOST', cls.DEFAULT_INFLUX_HOST),
            influxdb_port=env.get('INFLUX_HOST_PORT', cls.DEFAULT_INFLUX_HOST_PORT),
            influxdb_database=env.get('INFLUX_DATABASE', cls.DEFAULT_INFLUX_DATABASE),
            influxdb_user=env.get('INFLUX_USER', cls.DEFAULT_INFLUX_USER),
            influxdb_user_pass=env.get('INFLUX_PASS', cls.DEFAULT_INFLUX_PASS),
            influxdb_retention=env.get('INFLUX_RETENTION', cls.DEFAULT_INFLUX_RETENTION),
            influxdb_shard=env.get('INFLUX_SHARD', cls.DEFAULT_INFLUX_SHARD),
            geo_measurement=env.get('GEO_MEASUREMENT', cls.DEFAULT_INFLUX_SHARD),
            log_measurement=env.get('LOG_MEASUREMENT', cls.DEFAULT_LOG_MEASUREMENT),
            send_nginx_logs=env.get('SEND_NGINX_LOGS', cls.DEFAULT_SEND_NGINX_LOGS),
        )

    def regex_tester(self, N=3):
        """Verify the regex to use on log file.

        Try to parse the last N lines of the log file. wait up to 1 min for a valid log.
        If no enriched log can be parsed, only extract the ip, which assu,e default nginx log format.
        """
        time_out = time() + 60
        while True:
            assert N >= 0
            pos = N + 1
            lines = []
            with open(self.log_path) as f:
                while len(lines) <= N:
                    try:
                        f.seek(-pos, 2)
                    except IOError:
                        f.seek(0)
                        break
                    finally:
                        lines = list(f)
                    pos *= 2
            log_lines = lines[-N:]
            for line in log_lines:
                if self.RE_IPV4.match(line):
                    if self.RE_LOGIPV4.match(line):
                        logging.debug(f'Regex is matching {self.log_path} continuing...')
                        return True
                if self.RE_IPV6.match(line):
                    if self.RE_LOGIPV6.match(line):
                        logging.debug(f'Regex is matching {self.log_path} continuing...')
                        return True
                else:
                    logging.debug(f'Testing regex on: {self.log_path}')
                    sleep(2)
            if time() > time_out:
                logging.warning(f'Failed to match regex on: {self.log_path}')
                break

    def file_exists(self):
        """ Verify the log file and geoip db validity."""
        time_out = time() + 30
        while True:
            file_list = [self.log_path, self.geoip_db_path]
            if not exists(self.log_path):
                logging.warning((f'File: {self.log_path} not found...'))
                sleep(1)
            if not exists(self.geoip_db_path):
                logging.warning((f'File: {self.geoip_db_path} not found...'))
                sleep(1)
            if all([isfile(f) for f in file_list]):
                for f in file_list:
                    logging.debug(f'Found: {f}')
                return True
            if time() > time_out:
                if not exists(self.geoip_db_path) and not exists(self.log_path):
                    logging.critical(f"Can't find: {self.geoip_db_path} or {self.log_path} exiting!")
                    break
                elif not exists(self.geoip_db_path):
                    logging.critical(f"Can't find: {self.geoip_db_path}, exiting!")
                    break
                elif not exists(self.log_path):
                    logging.critical(f"Can't find: {self.log_path}, exiting!")
                    break

    def init_influxdb(self):
        client = InfluxDBClient(
            host=self.influxdb_host,
            port=self.influxdb_port,
            username=self.influxdb_user,
            password=self.influxdb_user_pass,
            database=self.influxdb_database,
        )

        try:
            logging.debug('Testing InfluxDB connection')
            version = client.request('ping', expected_response_code=204).headers['X-Influxdb-Version']
            logging.debug(f'Influxdb version: {version}')
        except ConnectionError as e:
            logging.critical(f'Error testing connection to InfluxDB. Please check your url/hostname.\nError: {e}')
            raise

        try:
            databases = [db['name'] for db in client.get_list_database()]
            if self.influxdb_database in databases:
                logging.debug(f'Found database: {self.influxdb_database}')
        except InfluxDBClientError as e:
            logging.critical(f'Error getting database list! Please check your InfluxDB configuration.\nError: {e}')
            raise

        if self.influxdb_database not in databases:
            logging.info(f'Creating database: {self.influxdb_database}')
            client.create_database(self.influxdb_database)

            retention_policies = [policy['name'] for policy in client.get_list_retention_policies(database=self.influxdb_database)]
            if f'{self.influxdb_database} {self.influxdb_retention}-{self.influxdb_shard}' not in retention_policies:
                logging.info(f'Creating {self.influxdb_database} retention policy ({self.influxdb_retention}-{self.influxdb_shard})')
                client.create_retention_policy(name=f'{self.influxdb_database} {self.influxdb_retention}-{self.influxdb_shard}', duration=self.influxdb_retention, replication='1',
                                                    database=self.influxdb_database, default=True, shard_duration=self.influxdb_shard)
        return client

    def store_geo_metric(self, ip, geo_info, log_data):
        geo_metrics = []
        geohash = encode(geo_info.location.latitude, geo_info.location.longitude)
        geohash_fields = {'count': 1}

        geohash_tags = {}
        geohash_tags['geohash'] = geohash
        geohash_tags['ip'] = ip
        geohash_tags['host'] = self.hostname
        geohash_tags['country_code'] = geo_info.country.iso_code
        geohash_tags['country_name'] = geo_info.country.name
        geohash_tags['state'] = geo_info.subdivisions.most_specific.name
        geohash_tags['state_code'] = geo_info.subdivisions.most_specific.iso_code
        geohash_tags['city'] = geo_info.city.name
        geohash_tags['postal_code'] = geo_info.postal.code
        geohash_tags['latitude'] = geo_info.location.latitude
        geohash_tags['longitude'] = geo_info.location.longitude
        geo_metrics = [{
            'tags': geohash_tags,
            'fields': geohash_fields,
            'measurement': self.geo_measurement,
        }]
        logging.debug(f'Geo metrics: {geo_metrics}')
        try:
            self.influxdb.write_points(geo_metrics)
        except (InfluxDBServerError, ConnectionError) as e:
            logging.error(f'Error writing data to InfluxDB! Check your database!\nError: {e}')

    def store_log_metric(self, ip, geo_info, log_data):
        log_data_fields = {
            'count': 1,
            'bytes_sent': int(log_data['bytes_sent']),
            'request_time': float(log_data['request_time']),
        }
        # If several connection times are provided, use the last one
        log_data['connect_time'] = log_data['connect_time'].split(',')[-1]
        if log_data['connect_time'] == '-':
            log_data_fields['connect_time'] = 0.0
        else:
            log_data_fields['connect_time'] = float(log_data['connect_time'])

        log_data_tags = {}
        log_data_tags['ip'] = log_data['ipaddress']
        log_data_tags['datetime'] = datetime.strptime(log_data['dateandtime'], '%d/%b/%Y:%H:%M:%S %z')
        log_data_tags['remote_user'] = log_data['remote_user']
        log_data_tags['method'] = log_data['method']
        log_data_tags['referrer'] = log_data['referrer']
        log_data_tags['host'] = log_data['host']
        log_data_tags['http_version'] = log_data['http_version']
        log_data_tags['status_code'] = log_data['status_code']
        log_data_tags['bytes_sent'] = log_data['bytes_sent']
        log_data_tags['url'] = log_data['url']
        log_data_tags['user_agent'] = log_data['user_agent']
        log_data_tags['request_time'] = log_data['request_time']
        log_data_tags['connect_time'] = log_data['connect_time']
        log_data_tags['city'] = geo_info.city.name if geo_info else "-"
        log_data_tags['country_code'] = geo_info.country.iso_code if geo_info else "-"
        log_data_tags['country_name'] = geo_info.country.name if geo_info else "-"
        log_metrics = [{
            'tags': log_data_tags,
            'fields': log_data_fields,
            'measurement': self.log_measurement,
        }]
        logging.debug(f'NGINX log metrics: {log_metrics}')
        try:
            self.influxdb.write_points(log_metrics)
        except (InfluxDBServerError, InfluxDBClientError, ConnectionError) as e:
            logging.error(f'Error writing data to InfluxDB! Check your database!\nError: {e}')

    def logparse(self):
        inode = stat(self.log_path).st_ino

        # Determine whether to use enriched or basic log parsing
        send_logs = self.send_nginx_logs.lower() == 'true'
        if not self.regex_tester() and send_logs:
            send_logs = False
            logging.warning('NGINX log metrics disabled! Double check your NGINX custom log format..')
        if send_logs:
            re_log_ipv4 = self.RE_LOGIPV4
            re_log_ipv6 = self.RE_LOGIPV6
        else:
            re_log_ipv4 = self.RE_IPV4
            re_log_ipv6 = self.RE_IPV6

        # Main loop to parse access.log file in tailf style with sending metrics.
        with open(self.log_path, 'r') as log_file:
            logging.info('Starting log parsing')
            str_results = stat(self.log_path)
            st_size = str_results[6]
            log_file.seek(st_size)

            # Keep waiting for new logs
            while True:
                where = log_file.tell()
                line = log_file.readline()
                inodenew = stat(self.log_path).st_ino
                if inode != inodenew:
                    # File has changed, we need to reload it, exit this parsing loop
                    break
                if not line:
                    # No new data, wait for a bit
                    sleep(self.POLLING_PERIOD)
                    log_file.seek(where)
                else:
                    re_match = re_log_ipv4.match(line)
                    if not re_match:
                        re_match = re_log_ipv6.match(line)
                    if not re_match:
                        logging.warning(
                            'Failed to match regex that previously matched!? Skipping this line!\n'
                            'Please share the log line below on Discord or Github!\n'
                            f'Line: {line}'
                        )
                        continue
                    log_data = re_match.groupdict()
                    ip = log_data.get('ipaddress', re_match.group(1))
                    if ipadd(ip).iptype() == 'PUBLIC' and ip:
                        geo_info = self.geoip.city(ip)
                        if geo_info:
                            self.store_geo_metric(ip, geo_info, log_data)
                        if send_logs:
                            self.store_log_metric(ip, geo_info, log_data)


def main():
    logging.info('Starting geoip2influx..')
    log_parser = NginxLogParser.from_env()
    # Parsing log file and sending metrics to Influxdb
    while log_parser.file_exists():
        log_parser.logparse()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        exit(0)
