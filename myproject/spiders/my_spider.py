import scrapy
import random
import time
import os
import json
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlsplit, urlparse, unquote_plus, urlunparse, urlencode
from scrapy_playwright.handler import Page  # Import Playwright Page for advanced rendering

USER_AGENT_LIST = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
    'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/56.0',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0'
]

ACCEPT_LANGUAGE_LIST = [
    'en-US,en;q=0.9',
    'fr-FR,fr;q=0.9,en;q=0.8',
    'de-DE,de;q=0.9,en;q=0.8',
]

ACCEPT_ENCODING_LIST = [
    'gzip, deflate, br',
    'gzip, deflate',
]

REFERER_LIST = [
    'http://www.google.com/',
    'http://www.bing.com/',
]

class MySpider(scrapy.Spider):
    name = 'myspider'
    allowed_domains = []

    custom_settings = {
        'DUPEFILTER_CLASS': 'scrapy.dupefilters.RFPDupeFilter',
        'DEPTH_PRIORITY': 1,
        'CONCURRENT_REQUESTS_PER_DOMAIN': 1,
        'CONCURRENT_REQUESTS': 1,
        'COOKIES_ENABLED': True,
        'COOKIES_DEBUG': True,
        'ROBOTSTXT_OBEY': False,
        'DOWNLOAD_DELAY': random.uniform(2, 10),
        'RANDOMIZE_DOWNLOAD_DELAY': True,
        'PLAYWRIGHT_DEFAULT_NAVIGATION_TIMEOUT': 120000,  # Increased timeout to 120 seconds
        'PLAYWRIGHT_BROWSER_TYPE': 'chromium',
        'PLAYWRIGHT_LAUNCH_OPTIONS': {
            #"headless": False, #this is for debugging purposes only
            #"proxy": {
                #"server": "http://127.0.0.1:8081"
            #}
        }
    }

    def __init__(self, start_url=None, depth_limit=None, cookies_file=None, auth_token=None, *args, **kwargs):
        super(MySpider, self).__init__(*args, **kwargs)
        self.start_urls = [start_url] if start_url else []
        if start_url:
            parsed_url = urlparse(start_url)
            self.allowed_domains.append(parsed_url.netloc)

        if cookies_file:
            with open(cookies_file, 'r') as f:
                self.cookies = json.load(f)
        else:
            self.cookies = []

        self.auth_token = auth_token
        self.request_headers = {}
        self.headers_dir = "headers"
        self.depth_limit = int(depth_limit) if depth_limit else 2
        self.output_file = "output_urls.txt"

        if os.path.exists(self.headers_dir):
            for file in os.listdir(self.headers_dir):
                file_path = os.path.join(self.headers_dir, file)
                if os.path.isfile(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    os.rmdir(file_path)
        else:
            os.makedirs(self.headers_dir)

        # Clear the output file if it already exists
        if os.path.exists(self.output_file):
            os.remove(self.output_file)

        # Define the list of button selectors for different runs
        self.button_selectors = [
            "div[role='button']",
            "div > footer > div > div > div > div > div > div > div > div[role='button']"
        ]
        self.current_selector_index = 0

    def stealth_mode(self):
        headers = self.get_random_headers()
        #proxy = self.get_random_proxy()
        self.random_delay()
        return headers #, proxy


    def get_random_headers(self):
        headers = {
            'User-Agent': self.get_random_user_agent(),
            'Accept-Language': random.choice(ACCEPT_LANGUAGE_LIST),
            'Accept-Encoding': random.choice(ACCEPT_ENCODING_LIST),
            'Referer': random.choice(REFERER_LIST),
        }
        if self.auth_token:
            headers['Authorization'] = f'Bearer {self.auth_token}'
        return headers

    async def random_delay(self):
        delay = random.uniform(2, 10)
        self.logger.debug(f"Sleeping for {delay:.2f} seconds")
        await asyncio.sleep(delay)

    def get_random_user_agent(self):
        return random.choice(USER_AGENT_LIST)

    def start_requests(self):
        for url in self.start_urls:
            #headers = self.stealth_mode()
            self.save_new_url(url)

            yield scrapy.Request(
                url,
                callback=self.parse_with_playwright,
                #headers=headers,
                cookies=self.cookies,
                meta={
                    'playwright': True,  # Enables Playwright for this request
                    'playwright_include_page': True,  # Include page object
                    'handle_httpstatus_list': [403, 429, 503],
                    'depth_limit': self.depth_limit,
                    #'proxy': proxy,  # Include proxy
                    'selector_index': self.current_selector_index
                }
            )

    async def parse_with_playwright(self, response):
        page = response.meta.get("playwright_page")
        if page:
            try:
                # Navigate to the URL
                await page.goto(response.url, wait_until='domcontentloaded', timeout=120000)

                # Scroll the page to load all content
                await page.evaluate("""
                    () => {
                        return new Promise((resolve) => {
                            let totalHeight = 0;
                            let distance = 100;
                            let timer = setInterval(() => {
                                window.scrollBy(0, distance);
                                totalHeight += distance;

                                if (totalHeight >= document.body.scrollHeight) {
                                    clearInterval(timer);
                                    resolve();
                                }
                            }, 100);
                        });
                    }
                """)

                # Extract all links from the page
                links = await page.evaluate("""
                    () => Array.from(document.querySelectorAll('a[href]')).map(a => a.href)
                """)

                # Deduplicate links using a set
                unique_links = set(links)

                # Normalise and save unique links
                for link in unique_links:
                    resolved_link = self.normalize_url(link)
                    self.logger.info(f"Found URL: {resolved_link}")

                    # Save only internal links
                    if self.is_internal_link(resolved_link, urlparse(response.url).netloc):
                        print(f"Found URL: {resolved_link}")
                        self.save_new_url(resolved_link)

            except Exception as e:
                self.logger.error(f"Error processing {response.url}: {e}")

            finally:
                await page.close()



    def save_new_url(self, url):
        with open(self.output_file, 'a') as f:
            f.write(url + "\n")

    def capture_headers(self, url, response=None):
        if response:
            headers = response.request.headers.to_unicode_dict()
        else:
            headers = {
                'User-Agent': self.get_random_user_agent(),
                'Referer': url,
            }
        self.request_headers[url] = headers
        self.write_headers_to_file(url, headers)

    def write_headers_to_file(self, url, headers):
        filename = os.path.join(self.headers_dir, f"{self.safe_filename(url)}.txt")
        with open(filename, 'w') as f:
            f.write(f"URL: {url}\n")
            f.write("Captured Headers:\n")
            for key, value in headers.items():
                f.write(f"{key}: {value}\n")
        self.logger.debug(f"Headers for {url} saved to {filename}")

    def safe_filename(self, url):
        return url.replace('http://', '').replace('https://', '').replace('/', '_').replace(':', '_')

    def extract_links(self, content, base_url):
        all_links = set()
        domain = urlsplit(base_url).netloc.lower()
        soup = BeautifulSoup(content, 'html.parser')

        for tag in soup.find_all('a', href=True):
            href = tag['href'].split('#')[0]
            full_url = urljoin(base_url, href)
            normalized_url = self.normalize_url(full_url)
            if self.is_internal_link(normalized_url, domain):
                all_links.add(normalized_url)

        return list(all_links)

    def is_internal_link(self, url, domain):
        parsed_url = urlparse(url)
        return parsed_url.netloc.lower().endswith(domain)

    def extract_forms(self, response):
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')

        form_data_list = []
        for form in forms:
            form_data = self.extract_form_data(form, response.url)
            if form_data:
                form_data_list.append(form_data)

        return form_data_list

    def extract_form_data(self, form, base_url):
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()

        form_fields = {}
        for input_tag in form.find_all('input'):
            name = input_tag.get('name', '')
            value = input_tag.get('value', '')
            form_fields[name] = value

        cgi_params = urlencode(form_fields)

        if action:
            action_url = urljoin(base_url, action)
        else:
            action_url = base_url

        if method == 'GET' and cgi_params:
            action_url += '?' + cgi_params

        return {
            'url': action_url,
            'method': method,
            'form_fields': form_fields,
            'cgi_params': cgi_params
        }
    
    def normalize_url(self, full_url):
        parsed_url = urlparse(full_url)
        old = parsed_url.path
        # decode any percent-encoded characters in the URL's path (e.g: %20 for space)
        new = unquote_plus(old)
        parsed_url._replace(path=new)
        # preserve fragment (#) in the URL
        normalized_url = urlunparse(parsed_url)
        return normalized_url



