# -*- coding: utf-8 -*-

# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: http://doc.scrapy.org/en/latest/topics/item-pipeline.html
import os

import errno

import datetime
import re

from scrapy import Request
from scrapy.pipelines.files import FilesPipeline
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import subprocess
import requests
from IPy import IP
import csv


def url_analyse(url):
    ip_in_url = -1
    is_long_url = -1
    is_shortened_url = -1
    at_in_url = -1
    is_redirect = -1
    dash_in_domain = -1
    subdomain_depth = -1
    is_https = -1
    registration_length = -1
    has_non_standart_ports = -1
    https_in_domain = -1

    age_of_domain = -1
    dns_record = -1

    standart_ports = {21, 22, 23, 80, 443, 445, 1433, 1521, 3306, 3389}

    domain = urlparse(url).netloc

    try:
        ip_in_url = IP(domain)
        ip_in_url = 1
    except ValueError as e:
        pass

    url_len = len(url)
    if 21 < url_len < 54:
        is_long_url = 0
    elif url_len >= 54:
        is_long_url = 1

    try:
        resp = requests.get(url, allow_redirects=False)
        if resp.status_code < 300 and resp.url != url:
            is_tiny_url = 1
    except requests.exceptions.ConnectionError as e:
        pass

    if "@" in url:
        at_in_url = 1

    if url.count("//") > 1:
        is_redirect = 1

    if "-" in domain:
        dash_in_domain = 1

    # Count number of subdomains, but ignore top level domain and www, if it is present
    subdomain_depth = domain.count(".")
    if "www." in url:
        subdomain_depth -= 1
    if subdomain_depth <= 1:
        subdomain_depth = -1
    elif subdomain_depth <= 2:
        subdomain_depth = 0
    else:
        subdomain_depth = 1

    if url.startswith("https"):
        is_https = 1

    p = subprocess.Popen(["whois", domain], stdout=subprocess.PIPE)
    out, err = p.communicate()
    if out:
        out = out.decode('utf-8')
    if err:
        err = err.decode('utf-8')
    if out.startswith("No match for"):
        pass
    else:
        dns_record = 1
        searchDate = re.search(r'Creation Date: (.*)', out)
        if searchDate:
            registration_date = searchDate.group(1)
            registration_months = int(registration_date[:4]) * 12 + int(registration_date[5:7])
            now = datetime.datetime.now()
            months_now = 12 * now.year + now.month
            if months_now - registration_months >= 6:
                registration_length = 1
                age_of_domain = 1

    port_tokens = url.split(":")
    try:
        if len(port_tokens) > 1:

            port = int(port_tokens[-1])
            if port not in standart_ports:
                has_non_standart_ports = 1
    except ValueError:
        pass

    if "https" in domain:
        https_in_domain = 1

    return (
            ("https_in_domain", https_in_domain),
            ("registration_length", registration_length),
            ("is_redirect", is_redirect),
            ("age_of_domain", age_of_domain),
            ("is_long_url", is_long_url),
            ("is_shortened_url", is_shortened_url),
            ("at_in_url", at_in_url),
            ("ip_in_url", ip_in_url),
            ("is_https", is_https),
            ("dash_in_domain", dash_in_domain),
            ("subdomain_depth", subdomain_depth),
            ("dns_record", dns_record),
            ("has_non_standart_ports", has_non_standart_ports)
        )




def process(url, url_number):
    o = urlparse(url)
    splitted = o.path.split('/')
    folder, name = splitted[:-1], splitted[-1]
    folder = '/'.join(folder)
    return {
        'name': name,
        'path_to_folder': folder,
        'url_number': url_number
    }


class BasicPhishingFilesPipeline(FilesPipeline):
    def __init__(self, store_uri, download_func=None, settings=None):
        super(BasicPhishingFilesPipeline, self).__init__(store_uri, download_func, settings)
        self.domain = 'example.com'

    def get_media_requests(self, item, info):
        def append_host(path):
            return urljoin(item['response'].url, path)

        try:
            return [Request(append_host(x), meta=process(x, item['url_number']))
                    for x in item.get(self.DEFAULT_FILES_URLS_FIELD, [])]
        except ValueError as e:
            self.log('Bad url error:\n' + str(e) + '\n\n')

    def file_path(self, request, response=None, info=None):
        return '%s/%s/%s' % (request.meta['url_number'], request.meta['path_to_folder'], request.meta['name'])

    def log(self, param):
        with open('process_log.txt', 'a+') as f:
            f.write(param)


class WhoisSavePipeline(object):
    def process_item(self, item, spider):
        domain = urlparse(item['response'].url).netloc

        filename = "scrapyres/%s/whois.txt" % item['url_number']
        dirname = os.path.dirname(filename)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        with open(filename, "w+") as out:
            subprocess.Popen(["whois", domain],
                             stdout=out)

        filename = "scrapyres/%s/host.txt" % item['url_number']
        dirname = os.path.dirname(filename)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        with open(filename, "w+") as out:
            subprocess.Popen(["host", domain],
                             stdout=out)

        filename = "scrapyres/%s/url.txt" % item['url_number']
        dirname = os.path.dirname(filename)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        with open(filename, "w+") as out:
            out.write(item['response'].url)

        return {
            'response': item['response'],
            'url_number': item['url_number']
        }


class SaveHtmlFilesAndProcessFeaturesPipeline(object):
    def process_item(self, item, spider):
        features = url_analyse(item['response'].url)

        # filename = 'scrapyres/%s/features.csv' % item['url_number']
        filename = 'scrapyres/features.csv'
        dirname = os.path.dirname(filename)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        with open(filename, 'a') as f:
            row = item['response'].url + ','
            flen = len(features)
            for idx in range(flen):
                row += str(features[idx][1])
                if idx != flen-1:
                    row += ','
                else:
                    row += '\n'
            f.write(row)


class ExternalInfoSpiderPipeline(object):
    def process_item(self, item, spider):
        soup = BeautifulSoup(item['response_body'])
        res = soup.find(id='search')

        features = {
            'google_index': 0,  # google_index (so so)
        }

        if res is not None:
            if len(res.text) > 0:
                features['google_index'] = 1

        filename = 'scrapyres/%s/external_features.csv' % item['url_number']
        dirname = os.path.dirname(filename)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        with open(filename, 'wb') as f:
            w = csv.DictWriter(f, features.keys())
            w.writerow(features)
