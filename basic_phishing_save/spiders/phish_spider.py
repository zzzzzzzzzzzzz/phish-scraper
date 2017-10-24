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
    handle_httpstatus_list = [200, 302, 404]

    def __init__(self, *args, **kwargs):
        super(PhishSpider, self).__init__(*args, **kwargs)
        self.settings = get_project_settings()
        self.urls = []
        self.redirect_counter = 0
        self.url_number = 0
        if 'filename' not in kwargs:
            print("\n\nYou haven't specified filename with urls!\n\n")
        else:
            with open(kwargs['filename'], "r") as input:
                self.urls = [line.rstrip('\n') for line in input]
        if self.settings['PROXY_LIST']:
            self.proxy_iter = round_robin(self.settings['PROXY_LIST'])

    def start_requests(self):
        for url in self.urls:
            request = scrapy.Request(url=url, callback=self.parse)
            if self.settings['PROXY_LIST']:
                request.meta['proxy'] = next(self.proxy_iter)
            yield request

    def parse(self, response):
        # css_pages = []
        # js_pages = []
        # img_pages = []
        # for css_pages_link in response.css('link::attr(href)').extract():
        #     css_pages.append(css_pages_link)
        # for js_pages_link in response.css('script::attr(src)').extract():
        #     js_pages.append(js_pages_link)
        # for img_link in response.css('img::attr(src)').extract():
        #     img_pages.append(img_link)

        if response.status == 404:
            print("Drop 404 status")

        if response.status == 200:
            self.url_number += 1
            yield {
                #    'file_urls': css_pages + js_pages + img_pages,
                'response': response,
                'url_number': self.url_number,
                'redirect_count': self.redirect_counter
            }
            self.redirect_counter = 0
        if response.status == 302:
            self.redirect_counter += 1
