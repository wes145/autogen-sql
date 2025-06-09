import time
import logging
import random

class RandomDelayMiddleware(object):
    def __init__(self, delay):
        self.delay = delay

    @classmethod
    def from_crawler(cls, crawler):
        delay = crawler.spider.settings.get("DOWNLOAD_DELAY", 0.5)  # The default value is set to 0.5 seconds
        if not isinstance(delay, (int, float)):
            raise ValueError("RANDOM_DELAY needs an int or float")
        return cls(delay)

    def process_request(self, request, spider):
        delay = random.uniform(0, self.delay)
        logging.debug("### Random delay: %s seconds ###" % delay)
        time.sleep(delay)
