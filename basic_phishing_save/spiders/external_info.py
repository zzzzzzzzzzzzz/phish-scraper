import scrapy
from scrapy.utils.project import get_project_settings

from phish_spider import round_robin


class ExternalInfoSpider(scrapy.Spider):
    name = "external"
    custom_settings = {
        'ITEM_PIPELINES': {
            'basic_phishing_save.pipelines.ExternalInfoSpiderPipeline': 100
        }
    }

    def __init__(self, *args, **kwargs):
        super(ExternalInfoSpider, self).__init__(*args, **kwargs)
        self.settings = get_project_settings()
        self.urls = [
                'https://google.com/search?q=site:https://yandex.ru/',
                'https://google.com/search?q=site:https://vk.com/',
                'https://google.com/search?q=site:https://suspicious254.000webhostapp.com/info-account.html?login-your-fbaccount=65965344'
        ]
        self.url_number = 0
        if 'filename' not in kwargs:
            print "\n\nYou haven't specified filename with urls!\n\n"
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
        self.url_number += 1
        yield {
            'response_body': response.body,
            'url_number': self.url_number
        }
