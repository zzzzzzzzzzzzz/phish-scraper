# -*- coding: utf-8 -*-

# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: http://doc.scrapy.org/en/latest/topics/item-pipeline.html
import os

import errno
from scrapy import Request
from scrapy.pipelines.files import FilesPipeline
from urlparse import urlparse, urljoin
import io
from BeautifulSoup import BeautifulSoup
import subprocess


def process(url, domain):
    o = urlparse(url)
    splitted = o.path.split('/')
    folder, name = splitted[:-1], splitted[-1]
    folder = '/'.join(folder)
    return {
        'name': name,
        'path_to_folder': folder,
        'domain': domain
    }


class BasicPhishingFilesPipeline(FilesPipeline):
    def __init__(self, store_uri, download_func=None, settings=None):
        super(BasicPhishingFilesPipeline, self).__init__(store_uri, download_func, settings)
        self.domain = 'example.com'

    def get_media_requests(self, item, info):
        def append_host(path):
            return urljoin(item['response'].url, path)

        self.domain = urlparse(item['response'].url).netloc
        try:
            return [Request(append_host(x), meta=process(x, item['domain']))
                    for x in item.get(self.DEFAULT_FILES_URLS_FIELD, [])]
        except ValueError, e:
            self.log('Bad url error:\n' + str(e) + '\n\n')

    def file_path(self, request, response=None, info=None):
        return '%s/%s/%s' % (request.meta['domain'], request.meta['path_to_folder'], request.meta['name'])

    def log(self, param):
        with open('process_log.txt', 'a+') as f:
            f.write(param)


class WhoisSavePipeline(object):
    def process_item(self, item, spider):
        response = item['response']
        domain = urlparse(item['response'].url).netloc

        filename = "results/%s/whois.txt" % domain
        dirname = os.path.dirname(filename)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        with io.open(filename, "w+") as out:
            subprocess.Popen(["whois", domain],
                             stdout=out)

        filename = "results/%s/host.txt" % domain
        dirname = os.path.dirname(filename)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        with io.open(filename, "w+") as out:
            subprocess.Popen(["host", domain],
                             stdout=out)

        return {
            'response': response,
            'domain': domain
        }


class SaveHtmlFilesPipeline(object):
    def process_item(self, item, spider):
        filename = 'results/%s/index.html' % item['domain']
        soup = BeautifulSoup(item['response'].body)
        for link in soup.findAll('link'):
            if link.has_key('href'):
                o = urlparse(link['href'])
                link['href'] = o.path[1:]
        for script in soup.findAll('script'):
            if script.has_key('src'):
                o = urlparse(script['src'])
                script['src'] = o.path[1:]
        for img in soup.findAll('img'):
            if img.has_key('src'):
                o = urlparse(img['src'])
                img['src'] = o.path[1:]
        if not os.path.exists(os.path.dirname(filename)):
            try:
                os.makedirs(os.path.dirname(filename))
            except OSError as exc:  # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise
        with io.open(filename, 'w+') as f:
            f.write(unicode(soup))  # превращаем абсолютные пути в относительные
            # Ещё надо сделать так, чтобы пути типо /abc/defg/a.html
            # Превратились в abc/defg/a.html
