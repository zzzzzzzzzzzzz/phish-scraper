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
        except ValueError, e:
            self.log('Bad url error:\n' + str(e) + '\n\n')

    def file_path(self, request, response=None, info=None):
        return '%s/%s/%s' % (request.meta['url_number'], request.meta['path_to_folder'], request.meta['name'])

    def log(self, param):
        with open('process_log.txt', 'a+') as f:
            f.write(param)


class WhoisSavePipeline(object):
    def process_item(self, item, spider):
        domain = urlparse(item['response'].url).netloc

        filename = "results/%s/whois.txt" % item['url_number']
        dirname = os.path.dirname(filename)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        with io.open(filename, "w+") as out:
            subprocess.Popen(["whois", domain],
                             stdout=out)

        filename = "results/%s/host.txt" % item['url_number']
        dirname = os.path.dirname(filename)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        with io.open(filename, "w+") as out:
            subprocess.Popen(["host", domain],
                             stdout=out)

        filename = "results/%s/url.txt" % item['url_number']
        dirname = os.path.dirname(filename)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        with io.open(filename, "w+") as out:
            out.write(unicode(item['response'].url))

        return {
            'response': item['response'],
            'url_number': item['url_number']
        }


class SaveHtmlFilesAndProcessFeaturesPipeline(object):
    def process_item(self, item, spider):
        domain = urlparse(item['response'].url).netloc
        soup = BeautifulSoup(item['response'].body)
        features = {
            'favicon': 0,
            'request_url': 0,
            'url_of_anchor': 0,
            'links_in_meta_script_and_link': 0,
            'sfh': 0,
            'subm_inf_to_email': 0,
            'status_bar_customization': 0,
            'disabling_right_click': 0,
            'using_popup_window': 0,
            'iframe_redirection': 0,
        }

        for iframe in soup.findAll('iframe'):
            if iframe.has_key('frameborder'):
                features['iframe_redirection'] = 1
                break

        for link in soup.findAll('link'):
            if link.has_key('href'):
                o = urlparse(link['href'])
                if link.has_key('rel'):
                    if 'icon' in link['rel']:
                        if (o.netloc == domain) | (o.netloc is None):
                            features['favicon'] = 1
                if (o.netloc != domain) & (o.netloc is not None):
                    features['links_in_meta_script_and_link'] = 1

                if 'mailto:' in link['href']:
                    features['subm_inf_to_email'] = 1

                link['href'] = o.path[1:]

        for source in soup.findAll('source'):
            if source.has_key('src'):
                o = urlparse(source['src'])
                if (o.netloc != domain) & (o.netloc is not None):
                    features['request_url'] = 1
                    break

        for meta in soup.findAll('meta'):
            if meta.has_key('content'):
                o = urlparse(meta['content'])
                if (o.netloc != domain) & (o.netloc is not None):
                    features['links_in_meta_script_and_link'] = 1
                    break

        for form in soup.findAll('form'):
            if form.has_key('action'):
                if features['sfh'] & features['subm_inf_to_email']:
                    break
                o = urlparse(form['action'])
                if (o.netloc != domain) | (form['action'] == 'about:blank') | (form['action'] == ''):
                    features['sfh'] = 1
                if 'mailto:' in form['action']:
                    features['subm_inf_to_email'] = 1

        for button in soup.findAll('button'):
            if button.has_key('formaction'):
                if features['sfh'] & features['subm_inf_to_email']:
                    break
                o = urlparse(button['formaction'])
                if (o.netloc != domain) | (button['formaction'] == 'about:blank') | (button['formaction'] == ''):
                    features['sfh'] = 1
                if 'mailto:' in button['formaction']:
                    features['subm_inf_to_email'] = 1

        for script in soup.findAll('script'):
            if script.has_key('src'):
                o = urlparse(script['src'])
                if (o.netloc != domain) & (o.netloc is not None):
                    features['links_in_meta_script_and_link'] = 1
                script['src'] = o.path[1:]

            if script.text != '':
                if '.button==2' in script.text.replace(' ',''):
                    features['disabling_right_click'] = 1

        for a in soup.findAll('a'):
            if a.has_key('href'):
                o = urlparse(a['href'])
                if (o.netloc != domain) | ((o.path == '') & (o.fragment is not None)):
                    features['url_of_anchor'] = 1

                if a.has_key('onclick'):
                    if 'return false' in a['onclick'].lower():
                        features['status_bar_customization'] = 1

        for img in soup.findAll('img'):
            if img.has_key('src'):
                o = urlparse(img['src'])
                if (o.netloc != domain) & (o.netloc is not None):
                    features['request_url'] = 0
                img['src'] = o.path[1:]

        filename = 'results/%s/features.txt' % item['url_number']
        with io.open(filename, 'w+') as f:
            f.write(unicode(features))

        filename = 'results/%s/index.html' % item['url_number']
        if not os.path.exists(os.path.dirname(filename)):
            try:
                os.makedirs(os.path.dirname(filename))
            except OSError as exc:  # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise
        with io.open(filename, 'w+') as f:
            f.write(unicode(soup))
