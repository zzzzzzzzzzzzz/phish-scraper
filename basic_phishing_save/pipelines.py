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
from itertools import izip


def process(url, pn):
    o = urlparse(url)
    splitted = o.path.split('/')
    folder, name = splitted[:-1], splitted[-1]
    folder = ''.join(folder)
    # если захочется как-нибудь их более красиво распихать
    # if name.lower().split('.')[-1] == 'js':
    #     folder = 'js/' + ''.join(folder)
    # else:
    #     if 'css' in name.lower().split('.')[-1] == 'css':
    #         folder = 'css/' + ''.join(folder)
    #     else:
    #         folder = 'images/' + ''.join(folder)
    return {
        'name': name,
        'path_to_folder': folder,
        'page_number': pn
    }


class BasicPhishingFilesPipeline(FilesPipeline):
    def get_media_requests(self, item, info):
        def append_host(path):
            return urljoin(item['response'].url, path)

        try:
            return [Request(append_host(x), meta=process(x, item['page_number']))
                    for x in item.get(self.DEFAULT_FILES_URLS_FIELD, [])]
        except ValueError, e:
            self.log('Bad url error:\n' + str(e) + '\n\n')

    def file_path(self, request, response=None, info=None):
        return '%d/%s/%s' % (request.meta['page_number'], request.meta['path_to_folder'], request.meta['name'])

    def log(self, param):
        with open('process_log.txt', 'a+') as f:
            f.write(param)


class BasicPhishingSavePipeline(object):
    def process_item(self, item, spider):
        response = item['response']
        #       Здесь я хотел менять ссылки в исходной странице, но пока не понял как
        #        for css_pages_link in izip(range(len(css_ready_paths)), response.css('link::attr(href)')):
        #            css_pages_link.data = css_ready_paths[css_pages_link[0]]
        #        for js_pages_link in izip(range(len(js_ready_paths)), response.css('script::attr(src)')):
        #            js_pages_link.data = css_ready_paths[js_pages_link[0]]
        #        for img_link in izip(range(len(images_ready_paths)), response.css('img::attr(src)')):
        #            img_link.data = css_ready_paths[img_link[0]]

        return {
            'response_handled': response, # исторически осталось
            'page_number': item['page_number']
        }


class SaveHtmlFilesPipeline(object):
    def process_item(self, item, spider):
        filename = 'results/%d/index.html' % item['page_number']
        if not os.path.exists(os.path.dirname(filename)):
            try:
                os.makedirs(os.path.dirname(filename))
            except OSError as exc:  # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise
        with open(filename, 'w+') as f:
            f.write(
                item['response'].body.replace(item['response'].url, ''))  # превращаем абсолютные пути в относительные
                                                                          # Ещё надо сделать так, чтобы пути типо /abc/defg/a.html
                                                                          # Превратились в abc/defg/a.html
