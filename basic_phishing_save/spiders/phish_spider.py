from urlparse import urlparse

import scrapy
from scrapy.utils.project import get_project_settings


def round_robin(arr):
    to_yield_idx = 0
    length = len(arr)
    while True:
        yield arr[to_yield_idx % length]
        to_yield_idx += 1


class PhishSpider(scrapy.Spider):
    name = "phish"

    def __init__(self, *args, **kwargs):
        super(PhishSpider, self).__init__(*args, **kwargs)
        self.settings = get_project_settings()
        if self.settings['PROXY_LIST']:
            self.proxy_iter = round_robin(self.settings['PROXY_LIST'])

    def start_requests(self):
        urls = [
            'http://www.rbc.ru/',
            'http://lurkmore.to/',
            'https://vk.com/'
        ]
        for url in urls:
            request = scrapy.Request(url=url, callback=self.parse)
            if self.settings['PROXY_LIST']:
                request.meta['proxy'] = next(self.proxy_iter)
            yield request

    def parse(self, response):
        css_pages = []
        js_pages = []
        img_pages = []
        for css_pages_link in response.css('link::attr(href)').extract():
            css_pages.append(css_pages_link)
        for js_pages_link in response.css('script::attr(src)').extract():
            js_pages.append(js_pages_link)
        for img_link in response.css('img::attr(src)').extract():
            img_pages.append(img_link)
        yield {
            'file_urls': css_pages + js_pages + img_pages,
            'response': response,
            'domain': urlparse(response.url).netloc
        }
