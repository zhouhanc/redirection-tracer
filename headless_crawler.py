# -*- coding: utf-8 -*-
from selenium import webdriver
# from selenium.webdriver.common.by import By
# from selenium.webdriver.support.ui import WebDriverWait
# from selenium.webdriver.support import expected_conditions as EC
from urllib.parse import urlparse
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.common.proxy import Proxy, ProxyType
import random
import numpy as np
from pprint import pprint
import time
import util
import argparse
import multiprocessing
import subprocess
import json
import pymongo
from collections import defaultdict
import re
import os
from fake_useragent import UserAgent
import traceback
import sys
import requests
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from urllib.parse import urlparse, urlsplit, urlunsplit
ua = UserAgent()


class IPRotator(object):
    """docstring for IPRotator"""
    def __init__(self, server='local'):
        self.servers = ['USA_Washington.ovpn',
           'USA_Miami.ovpn',
           'USA_Seattle.ovpn',
           'USA_SanFrancisco.ovpn',
           'USA_NewYork.ovpn',
           'USA_LosAngeles.ovpn',
           'USA_Chicago.ovpn',
           'USA_Austin.ovpn',
           # 'United_Kingdom.ovpn',
           # 'Germany.ovpn',
           # 'France.ovpn',
           # 'Canada.ovpn',
           # 'Belgium.ovpn',
           # 'Austria.ovpn',
           # 'Denmark.ovpn',
           # 'Iceland.ovpn',
           # 'Norway.ovpn',
           # 'Singapore.ovpn'
           ]

        self.counter = 0
        self.process = None
        self.server = server
        cmd = ['sudo', 'pkill', '-f', 'openvpn']
        process = subprocess.Popen(cmd,
                              shell=False,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        code = process.wait()    
        print('kill current openvpn proess, return code is {}'.format(code))


    def switch_ip(self):
        # kill current process
        # if self.process is not None:
        #     self.process.terminate()
        #     time.sleep(12)
        self.terminate()
        if self.server == 'local':
            cmd = ['sudo', '-S', '/usr/local/Cellar/openvpn/2.4.8/sbin/openvpn', '--config', 
                '/Users/zc/Downloads/openvpn_configs/OpenVPN256/{}'.format(self.servers[self.counter]), 
                '--auth-user-pass', '/Users/zc/Downloads/openvpn_configs/OpenVPN256/pass.txt']
        else:
            cmd = ['sudo', '-S', 'openvpn', '--config', 
                '/home/centos/openvpn_configs/OpenVPN256/{}'.format(self.servers[self.counter]), 
                '--auth-user-pass', '/home/centos/openvpn_configs/OpenVPN256/pass.txt']

        server_location = self.servers[self.counter]
        self.counter = (self.counter+1) % len(self.servers)
    
        self.process = subprocess.Popen(cmd,
                              shell=False,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              stdin=subprocess.PIPE)
        print('returncode and pid:', self.process.returncode, self.process.pid)
        time.sleep(15)
        print('15 seconds ip warm up...')
        ip = requests.get('https://api.ipify.org').text
        print('new ip address is {}'.format(ip))
        return ip, server_location


    def terminate(self):
        # kill openvpn process
        cmd = ['sudo', 'pkill', '-f', 'openvpn']
        process = subprocess.Popen(cmd,
                              shell=False,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        code = process.wait()    
        print('kill current openvpn proess, return code is {}'.format(code))
        time.sleep(8)

    

#caps["pageLoadStrategy"] = "eager"  #  interactive
def smartproxy(index):
    prox = Proxy()
    prox.proxy_type = ProxyType.MANUAL
    from smartproxy_list import proxy_list
    
    HOSTNAME = proxy_list[index][0]
    PORT = proxy_list[index][1]
    print(HOSTNAME, PORT)

    prox.http_proxy = '{hostname}:{port}'.format(hostname = HOSTNAME, port = PORT)
    prox.ssl_proxy = '{hostname}:{port}'.format(hostname = HOSTNAME, port = PORT)

    capabilities = webdriver.DesiredCapabilities.CHROME
    prox.add_to_capabilities(capabilities)
    
    capabilities["pageLoadStrategy"] = "none" 
    capabilities["loggingPrefs"] = {'performance': 'ALL', 'browser':'ALL', 'network':'ALL'}
#     print(capabilities)
#     exit()
    return capabilities


def test_crawler():
    broswer_log = 'temp.log'
    html_log = '/home/zc/'
    prefix = 'test'
    crawler = HeadlessCrawler(broswer_log=broswer_log, 
                                  html_log=html_log, 
                                  prefix=prefix,
                                  save_html=False,
                                  use_proxy=False)
    crawler.html_filename = 'test_filename'
    
    url = crawler.get_page('http://ip.smartproxy.com/')
    print(url)

    body_text = crawler.driver.find_element_by_tag_name('body').text
    print(body_text)
    
    redirection_chain = crawler.get_redirection_chain()
    pprint(redirection_chain)
    crawler.close()


class HeadlessCrawler(object):
    """docstring for ClassName"""
    def __init__(self, broswer_log, html_log, prefix, save_html=False, show_head=False, ip_rotate=False, ip_index=None):
        # super(HeadlessCrawler, self).__init__()
        self.broswer_log = broswer_log
        self.html_log = html_log
        self.prefix = prefix
        self.save_html = save_html
        
        if ip_rotate:
            caps = smartproxy(ip_index)
        else:
            caps = DesiredCapabilities().CHROME
            caps["pageLoadStrategy"] = "none" 
            caps["loggingPrefs"] = {'performance': 'ALL', 'browser':'ALL', 'network':'ALL'}  # log more events (network, timeline)
                
        chrome_options = Options()
        
        # chrome_options.binary_location = '/usr/bin/google-chrome'
        if not show_head:
            chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-extensions")
        # chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--allow-running-insecure-content")
        chrome_options.add_argument("--ignore-certificate-errors")
        chrome_options.add_argument("--disable-popup-blocking")
        
        chrome_options.add_experimental_option('w3c', False)
        
        userAgent = ua.random
        chrome_options.add_argument('user-agent={}'.format(userAgent))
        
        if ip_rotate:
#             chrome_options.AddUserProfilePreference("profile.managed_default_content_settings.images", 2);
#             options.addArguments("headless","--blink-settings=imagesEnabled=false");
            prefs={"profile.managed_default_content_settings.images": 2}
            chrome_options.add_experimental_option('prefs', prefs)
        
#         prefs={'disk-cache-size': 4096}
#         chrome_options.add_experimental_option('prefs', prefs)

        self.driver = webdriver.Chrome(
            executable_path=util.ChromeDriverPath,
            desired_capabilities=caps,
#             desired_capabilities=smartproxy(),
            chrome_options=chrome_options, 
            service_args=["--verbose", "--log-path={0}".format(self.broswer_log)],
            )
        self.driver.set_page_load_timeout(15)

    def get_page_all(self, urls):
        # urls += ['123://12.com', 'http://gooblog.site/mIRysf']
        self.urls = urls
        self.valid_url = []
        for index, url in enumerate(urls):
            print(index, url)
            try:
                print(self.get_page(url))
                self.valid_url.append(url)
                self.write_log_to_mongo()
                self.driver.close()
            except Exception as e:
                print('exception when getting page {}'.format(url))
                print(e)
                pass
    
    def get_page_and_execute(self, url, command):
        self.driver.get(url)
        return self.driver
        # time.sleep(5)
        # result = self.driver.execute_script(command)
        # return result

    def get_page(self, url, wait_time=5):
        self.driver.get(url)
        
        # body = driver.find_element_by_tag_name("body")
        # wait = WebDriverWait(driver, 1, poll_frequency=0.05)
        # wait.until(lambda driver: driver.current_url != "http://www.website.com/wait.php")
        # wait.until(EC.staleness_of(body))
        # print(driver.current_url)

        # if self.driver.switch_to.alert:
        #     self.driver.switch_to.alert.accept()

        time.sleep(wait_time)
        try:
            WebDriverWait(self.driver, 1).until(EC.alert_is_present(),
                                   'Timed out waiting for PA creation ' +
                                   'confirmation popup to appear.')

            alert = self.driver.switch_to.alert
            alert.accept()
            print("alert accepted")
        except TimeoutException:
            print("no alert")

        if self.save_html:
            normalized_url = re.sub('[^A-Za-z0-9]+', '', url)[:100]
            self.html_filename = self.html_log + '/' + normalized_url + '.html'
            with open(self.html_filename, 'w') as f:
                f.write(self.driver.page_source)
            
            self.driver.save_screenshot("{}/{}.png".format(self.html_log, normalized_url))

        return self.driver.current_url

    def close(self):
        self.driver.quit()
    
    def get_performance_log(self):
        print(self.driver.log_types)
        perfs = self.driver.get_log('performance')
        for row in perfs:
            message = json.loads(row['message'])
            if message['message']['method'] == 'Network.responseReceived':
                pprint(message['message']['params']['frameId'])
                pprint(message['message']['params']['type'])
                pprint(message['message']['params']['response']['remoteIPAddress'])
                pprint(message['message']['params']['response']['mimeType'])
                pprint(message['message']['params']['response']['url'])
                print()
        # perfs = self.driver.get_log('driver')
        # pprint(perfs)

    def write_one_record(self, collection, record):
        # pprint(record)
        inserted_id = collection.insert_one(record).inserted_id
        pprint("inserted_id: {}".format(inserted_id))
    
    def get_redirection_chain(self):
        perfs = self.driver.get_log('performance')
        redirection_chain = []
        main_frameid = None
        first_request = True
        network_communication = []
        for row in perfs:
            message = json.loads(row['message'])
            if message['message']['method'] == 'Network.requestWillBeSent' and first_request:
                # documentURL is more structured
                input_url = message['message']['params']['documentURL']
                first_request = False
                # if message['message']['params']['documentURL'][:-1] == url or \
                #    message['message']['params']['documentURL'] == url:
                main_frameid = message['message']['params']['frameId']
                

            if message['message']['method'] == 'Network.requestWillBeSent':
                if 'redirectResponse' in message['message']['params']:
                    redirectResponse = message['message']['params']['redirectResponse']
                    if 'requestHeaders' in redirectResponse:
                        from_url = message['message']['params']['redirectResponse']['url']
                        to_url = message['message']['params']['documentURL']
                        redirection_chain.append({'method': 'Network.requestWillBeSent', 'from_url': from_url, 'to_url': to_url})

            if message['message']['method'] == 'Page.frameNavigated' and message['message']['params']['frame']['id'] == main_frameid:
                url = message['message']['params']['frame']['url']
                redirection_chain.append({'method': 'Page.frameNavigated', 'url': url})

            if message['message']['method'] == 'Page.frameScheduledNavigation' and message['message']['params']['frameId'] == main_frameid:
                url = message['message']['params']['url']                
                redirection_chain.append({'method': 'Page.frameScheduledNavigation', 'url': url})


            if message['message']['method'] == 'Network.requestWillBeSent':
                try:
                    if message['message']['params']['frameId'] == main_frameid:
                        if 'redirectResponse' in message['message']['params'] and 'remoteIPAddress' in message['message']['params']['redirectResponse']:
                            # requestHeaders also helpful
                            result = {
                                    'frameId': message['message']['params']['frameId'],
                                    'type': message['message']['params']['type'],
                                    'remoteIPAddress': message['message']['params']['redirectResponse']['remoteIPAddress'],
                                    'mimeType': message['message']['params']['redirectResponse']['mimeType'],
                                    'url': message['message']['params']['redirectResponse']['url'],
                                    'status': message['message']['params']['redirectResponse']['status'],
                                    'timestamp': message['message']['params']['timestamp']
                            }
                            pprint('same frame redirectResponse identified!!!')
                            pprint(result)
                            network_communication.append(result)
                except Exception as e:
                    print('ERROR, not able to retrieve data from Network.requestWillBeSent')
                    print(e)

            if message['message']['method'] == 'Network.responseReceived':
                try:
                    if 'remoteIPAddress' not in message['message']['params']['response']:
                        pass
                    else:
                        result = {
                            'frameId': message['message']['params']['frameId'],
                            'type': message['message']['params']['type'],
                            'remoteIPAddress': message['message']['params']['response']['remoteIPAddress'],
                            'mimeType': message['message']['params']['response']['mimeType'],
                            'url': message['message']['params']['response']['url'],
                            'status': message['message']['params']['response']['status'],
                            'timestamp': message['message']['params']['timestamp']
                            }
                        network_communication.append(result)
                except Exception as e:
                    print('ERROR, not able to retrieve data from Network.responseReceived')
                    print(e)

        # write redirection_chain for last url
        has_frontend_redirect, sub_redirect_chain = get_final_domain_from_chain(input_url, redirection_chain)
        final_domain = sub_redirect_chain[-1]
        final_domain_normalized = util.get_normalized_domain(final_domain)
        
        record = {'url': input_url,
                 'redirection_chain': redirection_chain, 
                 'prefix': self.prefix, 
                 'network_communication': network_communication,
                 'source_filename': self.html_filename,
                 'final_domain_normalized': final_domain_normalized}
        return record
    
    
    def write_one_url_to_mongo(self, collection, input_url, user=None):
        perfs = self.driver.get_log('performance')
        redirection_chain = []
        main_frameid = None
        first_request = True
        network_communication = []
        for row in perfs:
            message = json.loads(row['message'])
            if message['message']['method'] == 'Network.requestWillBeSent' and first_request:
                # documentURL is more structured
                input_url = message['message']['params']['documentURL']
                first_request = False
                # if message['message']['params']['documentURL'][:-1] == url or \
                #    message['message']['params']['documentURL'] == url:
                main_frameid = message['message']['params']['frameId']
                

            if message['message']['method'] == 'Network.requestWillBeSent':
                if 'redirectResponse' in message['message']['params']:
                    redirectResponse = message['message']['params']['redirectResponse']
                    if 'requestHeaders' in redirectResponse:
                        from_url = message['message']['params']['redirectResponse']['url']
                        to_url = message['message']['params']['documentURL']
                        redirection_chain.append({'method': 'Network.requestWillBeSent', 'from_url': from_url, 'to_url': to_url})

            if message['message']['method'] == 'Page.frameNavigated' and message['message']['params']['frame']['id'] == main_frameid:
                url = message['message']['params']['frame']['url']
                redirection_chain.append({'method': 'Page.frameNavigated', 'url': url})

            if message['message']['method'] == 'Page.frameScheduledNavigation' and message['message']['params']['frameId'] == main_frameid:
                url = message['message']['params']['url']                
                redirection_chain.append({'method': 'Page.frameScheduledNavigation', 'url': url})

            if message['message']['method'] == 'Network.responseReceived':
                try:
                    if 'remoteIPAddress' not in message['message']['params']['response']:
                        pass
                    else:
                        result = {
                            'frameId': message['message']['params']['frameId'],
                            'type': message['message']['params']['type'],
                            'remoteIPAddress': message['message']['params']['response']['remoteIPAddress'],
                            'mimeType': message['message']['params']['response']['mimeType'],
                            'url': message['message']['params']['response']['url']
                            }
                        network_communication.append(result)
                except Exception as e:
                    print('ERROR, not able to retrieve data from Network.responseReceived')
                    print(e)

        # write redirection_chain for last url
        has_frontend_redirect, sub_redirect_chain = get_final_domain_from_chain(input_url, redirection_chain)
        final_domain = sub_redirect_chain[-1]
        final_domain_normalized = util.get_normalized_domain(final_domain)
        
        record = {'url': input_url,
                 'redirection_chain': redirection_chain, 
                 'prefix': self.prefix, 
                 'network_communication': network_communication,
                 'tweet_info': user,
                 'source_filename': self.html_filename,
                 'final_domain_normalized': final_domain_normalized}
        self.write_one_record(collection, record)
        return

    def write_log_to_mongo(self):
        # print(self.driver.log_types)
        # performance, broswer, and driver types available
        perfs = self.driver.get_log('performance')
        redirection_chain = []
        
        counter = 0
        next_url = self.valid_url[counter]
        main_frameid = None
        for row in perfs:
            message = json.loads(row['message'])

            if message['message']['method'] == 'Network.requestWillBeSent':
                if message['message']['params']['documentURL'][:-1] == next_url or \
                   message['message']['params']['documentURL'] == next_url:
                    if counter > 0:
                        # write data to mongodb, update next_url
                        # inserted_id = db.my_collection.insert_one({"x": 10}).inserted_id
                        # pprint(inserted_id)
                        record = {'url': self.valid_url[counter-1], 'redirection_chain': redirection_chain, 'prefix': self.prefix}
                        self.write_one_record(record)
                        # pprint(redirection_chain)
                        redirection_chain = []

                    if counter+1 < len(self.valid_url):
                        counter += 1
                        next_url = self.valid_url[counter]
                    else:
                        next_url = None

                    # pprint(message['message']['params']['documentURL'])
                    main_frameid = message['message']['params']['frameId']

            if message['message']['method'] == 'Network.requestWillBeSent':
                if 'redirectResponse' in message['message']['params']:
                    redirectResponse = message['message']['params']['redirectResponse']
                    if 'requestHeaders' in redirectResponse:
                        from_url = message['message']['params']['redirectResponse']['url']
                        to_url = message['message']['params']['documentURL']
                        redirection_chain.append({'method': 'Network.requestWillBeSent', 'from_url': from_url, 'to_url': to_url})

            if message['message']['method'] == 'Page.frameNavigated' and message['message']['params']['frame']['id'] == main_frameid:
                url = message['message']['params']['frame']['url']
                redirection_chain.append({'method': 'Page.frameNavigated', 'url': url})

            if message['message']['method'] == 'Page.frameScheduledNavigation' and message['message']['params']['frameId'] == main_frameid:
                url = message['message']['params']['url']                
                redirection_chain.append({'method': 'Page.frameScheduledNavigation', 'url': url})

        # write redirection_chain for last url
        record = {'url': self.valid_url[-1], 'redirection_chain': redirection_chain, 'prefix': self.prefix}
        self.write_one_record(record)
        return


def get_final_domain_from_chain(input_url, redirection_chain):
    has_frontend_redirect = False
    previous_url = urlparse(input_url).netloc
    # 1. init sub_redirect_chain with the first level URL
    sub_redirect_chain = [previous_url]
    for index, chain in enumerate(redirection_chain):
        method = chain['method']
        if method == 'Page.frameScheduledNavigation':
            url_domain = urlparse(chain['url']).netloc
            if url_domain != previous_url:
                
                sub_redirect_chain.append(url_domain)
                has_frontend_redirect = True
            previous_url = urlparse(chain['url']).netloc

        if method == 'Network.requestWillBeSent':
            url_from = urlparse(chain['from_url']).netloc
            url_to = urlparse(chain['to_url']).netloc
            if url_from == previous_url and url_from != url_to:
                
                sub_redirect_chain.append(url_to)
                previous_url = url_to

    return has_frontend_redirect, sub_redirect_chain


def embedded_url(prefix):
    # TODO: we can store information about retweet, quote or comment, to support other types of social interaction graphs
    urls = []
    #prefix = 'twitter_suspicious_tld2019-09-06_01:21:53'
    filename = util.RawDataPath + prefix + '_tweet.txt'
    print(filename)
    for t in util.loadjson(filename):
        # print(t['user'])
        # store the text for future NLP use
        # extract the full (not truncated) text
        if 'extended_tweet' not in t:
            if 'full_text' in t:
                text = t['full_text']
            else:
                text = t['text']
        else:
            text = t['extended_tweet']['full_text']

        for url in util.get_embedded_url(t):
            actor_info = {'screen_name': t['user']['screen_name'],
                          'user_id': t['user']['id'],
                          'tweet_id': t['id'],
                          'created_at': t['created_at'],
                          'text': text
                        }
            urls.append((url, actor_info))
    return urls


def add_href_if_same_origin(href, final_domain):
        if href is None:
            return False
        part = urlsplit(href)
        path = part.path
        netloc = part.netloc
        if netloc.startswith('www.'):
            netloc = netloc[4:]
        if netloc == '' or netloc == final_domain:
            if (path.count('-') >= 3 or path.count('_') >= 3):
                # and 'help' not in href
                # print(path)
                return True
            else:
                return False
#             elif 'id=' in href:
#                 if href[0] != '/':
#                     href = '/' + href
#                 print('id== {}'.format(href))
#                 return True
        else:
            return False
                

# write each url trace into a json, 
# and save html file, 
# and take a screenshot
import socket
def crawl_suspicious_news(url_list, log_dir, prefix, use_vpn, overwrite, server, show_head, query_type, ip_rotate, ip_index):
    if use_vpn:
        rotator = IPRotator(server=server)
        client_ip, client_server_location = rotator.switch_ip()
    broswer_log = 'temp.log'
    num_url_visited = 0
    IP_SWITCH_THRESHOLD = 20
    for index, url in enumerate(url_list):
        if query_type == 'domain':
            url = url.lower()
            url = util.get_normalized_domain(url)
        trace = {}
        trace['input_url'] = url
        trace['index'] = index
        trace['prefix'] = prefix
        if use_vpn:
            trace['client_ip'] = client_ip
            trace['client_server_location'] = client_server_location
        record = []
        html_log = '{}/{}/'.format(log_dir, url.replace('.', '_').replace('/', '_').replace(':', '_').replace('?', '_'))
        if os.path.isdir(html_log) is False:
#             print('WARNING!!! ignore none-existent folders !!!')            
            print('[index] -- {} -- create {}'.format(index, html_log))
            os.makedirs(html_log)

        else:
            if os.path.isfile('{}/trace.json'.format(html_log)):
                trace = json.load(open('{}/trace.json'.format(html_log), 'r'))
                if len(trace['record']) > 0 and 'is_redirect' in trace['record'][-1]:
                    if trace['record'][-1]['is_redirect']:
                        print('{} is redirected !!!'.format(url))
                        print(len(trace['record']))

                if not overwrite:
                    continue
        
        if not url.startswith('http'):
            url = 'http://' + url
        url_split = urlsplit(url)
        final_domain = url_split.netloc
        if final_domain.startswith('www.'):
            final_domain = final_domain[4:]

        try:
            ip = socket.gethostbyname(final_domain)
            print('{} is on ip {}'.format(final_domain, ip))
            trace['ip'] = ip
        except Exception as e:
            print(e)
            trace['error'] = 'cannot resolve IP address'
            trace['record'] = record
            trace['ip'] = None
            # save trace to a json
            json.dump(trace, open('{}/{}'.format(html_log, 'trace.json'), 'w'))
            continue
        
        # if we can resolve the IP, proceed with a crawler
        crawler = HeadlessCrawler(broswer_log=broswer_log, 
                                  html_log=html_log, 
                                  prefix=prefix,
                                  save_html=True,
                                  show_head=show_head,
                                  ip_rotate=ip_rotate,
                                  ip_index=ip_index)            
        
        redirection_return_result = []
        try:

            ### switch IP address if necessary
            if use_vpn:
                if num_url_visited == IP_SWITCH_THRESHOLD:
                    client_ip, client_server_location = rotator.switch_ip()
                    num_url_visited = 0
                num_url_visited += 1

            # might be more efficient with a while loop
            trial = 0
            WAIT_TIME_BASE = 5
            crawler.get_page(url, wait_time=WAIT_TIME_BASE+3*random.random())
            redirection_chain = crawler.get_redirection_chain()
            
            redirect_domain_tld = '.'.join(
                redirection_chain['final_domain_normalized'].split('.')[-2:])
            final_domain_tld = '.'.join(final_domain.split('.')[-2:])
            
            # pprint(redirection_chain['redirection_chain'])
            if redirect_domain_tld != final_domain_tld:
                record.append({"trial": trial, 
                          "record": redirection_chain,
                          "is_redirect": True})
                trial = 2
                # pprint(redirection_chain['redirection_chain'])
                print('find redirection !!! ')
                res = util.get_redirection_chain(redirection_chain, {})
                redirection_return_result = res
                pprint(res)
                
            else:
                record.append({"trial": trial, 
                          "record": redirection_chain,
                          "is_redirect": False})

                if len(redirection_chain['redirection_chain']) == 1 and \
                   redirection_chain['redirection_chain'][0]['url'] == "chrome-error://chromewebdata/":
                    trace['error'] = 'chrome-data error [server respond 200]'
                    print(trace['error'])
                    trial = 2
            
            while trial < 2:
                elems = crawler.driver.find_elements_by_xpath("//a[@href]")
                print('extract href...')
                next_url = None
                article_url = None
                for elem in elems:
                    current_href = elem.get_attribute("href")
                    if 'refer' in current_href and 'key' in current_href:
                        next_url = current_href
                    if add_href_if_same_origin(current_href, final_domain):
                        article_url = current_href

                if next_url is not None:
                    trial += 1
                    print('get next url, has redirect {}...'.format(next_url))
                    crawler.get_page(next_url)
                    record.append({"trial": trial, 
                                  "record": crawler.get_redirection_chain(), 
                                  "is_redirect": True})
                    break
                    
                elif article_url is not None:
                    if trial == 0:
                        trial += 1
                        print('get a news article {}...'.format(article_url))
                        crawler.get_page(article_url)
                        record.append({"trial": trial, 
                                      "record": crawler.get_redirection_chain(),
                                      "is_redirect": False})
                    else:
                        trace['error'] = 'cannot find suspicious links'
                        print(trace['error'])
                        break
                else:
                    trace['error'] = 'cannot find news-like links'
                    print(trace['error'])
                    break
                
        except Exception:
            pprint(traceback.format_exc())
            pprint(sys.exc_info())
            trace['error'] = str(traceback.format_exc())
            pass
        finally:
            crawler.close()
            trace['record'] = record
            # save trace to a json
            json.dump(trace, open('{}/{}'.format(html_log, 'trace.json'), 'w'))
        print('finish....., sleep ')

    if use_vpn:
        rotator.terminate()

    return redirection_return_result


def crawl_one(url_list, log_dir):
    broswer_log = log_dir + '/temp.log'
    # create html log if not exists
    html_log = log_dir + '/html/'
    if os.path.isdir(html_log) is False:
        print('create %s' % (html_log))
        os.makedirs(html_log)

    # url_list = ['http://cutiesss.xyz/?p=tch-2433731&FhR=6hZhPk94aM&ykHAy', 'http://gooblog.site/mIRysf']
    # url_list = ['http://breitbart.com', 'http://rawstory.com']
    # url_list = ['http://u000u.info', 'http://u999u.info']
    for index, url in enumerate(url_list):
        crawler = HeadlessCrawler(broswer_log=broswer_log, 
                                  html_log=html_log, 
                                  prefix='twitter_test',
                                  save_html=True,
                                  show_head=False)
        try:
            crawler.get_page(url)
            crawler.get_performance_log()
            
            elems = crawler.driver.find_elements_by_xpath("//a[@href]")
            print('show href')
            links = set([])
            for elem in elems:
                print(elem.get_attribute("href"))

            # crawler.write_one_url_to_mongo(db.my_collection, url)
        except Exception as e:
            print(e)
            pass
        finally:
            crawler.close()

def crawl_all(prefix, start_index, end_index, log_dir):
    # urls = embedded_url(prefix)
    suspicious_urls = json.load(open('malware_domains.json', 'r'))['response']['domains']
    suspicious_urls = [i['name'] for i in suspicious_urls]
    # urls = list(set([i for i in urls if 'boxfresh' not in i]))
    # suspicious_tld = set(['.work', '.info', '.xyz', '.site', '.win', '.bid', '.club', '.review', '.stream'])
    # suspicious_urls = []
    # for url in urls:
        # for tld in suspicious_tld:
        #     if tld in url:
                # suspicious_urls.append(url)
                # break

    urls = suspicious_urls
    print(urls)
    print(len(urls))
    print(len(set(urls)))
    #LOG_TO_READ = "/mnt/research/direct.log"
    #broswer_log = "/mnt/research/direct_.log"

    import os.path
    for index, url_list in enumerate(np.array_split(urls, 20)):
        broswer_log = log_dir + "/" + prefix + "_" + str(index) + ".log"
        if not os.path.isfile(broswer_log) and (index >= start_index and index <= end_index):
            crawler = HeadlessCrawler(log_dir = broswer_log)
            crawler.get_page_all(urls=url_list)
            crawler.close()


def crawl_alexa_top(prefix, log_dir, start_index=0, end_index=40):
    urls = []
    # read alexa top csv file
    with open("/mnt/research/top-1m.csv", "r") as f:
        for line in f:
            entries = line.split(",")
            urls.append("http://" + entries[1].strip())
    
    urls = urls[:10000]  
    print(urls[:100])  

    import os.path
    for index, url_list in enumerate(np.array_split(urls, 20)):
        broswer_log = log_dir + "/" + prefix + "_" + str(index) + ".log"
        if not os.path.isfile(broswer_log) and (index >= start_index and index <= end_index):
            crawler = HeadlessCrawler(log_dir = broswer_log)
            crawler.get_page_all(urls=url_list)
            crawler.close()


def crawl_multithread(prefix, log_dir, n_process, collection):
    url_user = embedded_url(prefix)
    urls = list(set([url for url, _ in url_user if 'boxfresh' not in url]))

    print("do not filter out any URL...")
    suspicious_urls = set(urls)
    urls = defaultdict(list)
    for url, user in url_user:
        if url in suspicious_urls:
            urls[url].append(user)    

    url_user_pair = list(urls.items())
    print(len(url_user_pair))
    # url_user_pair = [(url, user) for url, user in url_user_pair if len(user) < 1500]

    # A website is significant if at least 3 people tweet about it
    url_user_pair = [(url, user) for url, user in url_user_pair if len(user) > 2]
    print(len(url_user_pair))

    jobs = []
    import os.path
    # create html log if not exists
    html_log = log_dir + '/' + prefix + '/'
    if os.path.isdir(html_log) is False:
        print('create %s' % (html_log))
        os.makedirs(html_log)

    # create index if it does not exist
    temp_mongo_client = pymongo.MongoClient(**util.mongo_config)
    temp_db = temp_mongo_client.redirection
    result = temp_db[collection].create_index([('url', pymongo.ASCENDING)], unique=True)
    print(result)

    for index, url_user_subpair in enumerate(np.array_split(url_user_pair, n_process)):
        broswer_log = log_dir + "/" + prefix + "_" + str(index) + ".log"
        if not os.path.isfile(broswer_log):
            p = multiprocessing.Process(target=worker, args=(index, list(url_user_subpair), broswer_log, html_log, prefix, collection))
            jobs.append(p)
            p.start()
            
    for proc in jobs:
        proc.join()
    print('finish processing all URLs')


def worker(procnum, url_user_list, broswer_log, html_log, prefix, collection):
    '''worker function'''
    print(broswer_log)
    mongo_client = pymongo.MongoClient(**util.mongo_config)
    db = mongo_client.redirection
    db_collection = db[collection]

    for index, url_user in enumerate(url_user_list):
        url, user = url_user
        print("process {} -- {} -- {}".format(procnum, index, url))
        crawler = HeadlessCrawler(broswer_log=broswer_log, html_log=html_log, prefix=prefix, save_html=True)
        try:
            crawler.get_page(url)
            crawler.write_one_url_to_mongo(db_collection, url, user)
        except Exception as e:
            print(e)
            pass
        finally:
            crawler.close()

    # val = []
    # count = 0
    # for embedded_url in urls:
    #     if count % 5 == 0:
    #         print("%d processed %d urls" %(procnum, count))
    #     count += 1

    #     results = unshorten_url(embedded_url, 1, {})
    #     resolved_url = results[max(results.keys())]
        
    #     val.append((embedded_url, resolved_url))
    # return_dict[procnum] = val
# crawler.get_page_all(urls=urls[:20])
# crawler.parse_log(log_dir=LOG_TO_READ, urls=urls[:20])
# pprint(crawler.url_chain)



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('--prefix', type=str, required=True, help='prefix of log file')
    parser.add_argument('--n_process', type=int, help='number of processes to run in parallel')
    parser.add_argument('--log_dir', type=str, required=True, help='directory for logging files')
    parser.add_argument('--url', type=str, help='url to test for crawl one')
    parser.add_argument('--collection', type=str, required=False, default=None, help='name of mongo db collection')
    parser.add_argument('--use_vpn', default=False, required=False, action='store_true', help='whether to use vpn or not')
    parser.add_argument('--ip_rotate', default=False, required=False, action='store_true', help='whether to rotate IP or not')
    parser.add_argument('--ip_index', type=int, default=None, required=False, help='which vantage point to use')
    parser.add_argument('--overwrite', default=False, action='store_true', help='whether to overwrite existing folder')
    parser.add_argument('--data_source', type=str, default='viewdns')
    parser.add_argument('--server', type=str, default='local', help='type of environment [local/brooklyn/...]')
    parser.add_argument('--query_type', type=str, default='domain', help='options are [domain|url]')
    parser.add_argument('--show_head', default=False, action='store_true', help='show chrome head when the argument is set')
    # TODO: add data_source as an argument
    ###
    ###

    args = parser.parse_args()
    #prefix = 'twitter_suspicious_tld2019-09-06_01:21:53'
    #crawl_alexa_top(args.prefix)
    #crawl_all(args.prefix, args.start_index, args.end_index, args.log_dir)
#     crawl_one([args.url], args.log_dir)
    
#     test_crawler()
    
    ##### get domains from viewdns json record
    prefix = args.prefix.replace('.', '_').replace('/', '_').replace(':', '_').replace('?', '_')

    if args.data_source == 'viewdns':
        domains = json.load(open('reverse_lookup_json/reverse_lookup_{}.json'.format(prefix), 'r'))['response']['domains']
    #     domains = [d['name'] for d in domains]
        # import pandas as pd
        # df = pd.DataFrame(domains)
        # df.to_csv('suspicious_domains')
        domains = sorted(domains, key=lambda x: x['last_resolved'], reverse=True)
        domains = [d['name'] for d in domains]
        
    ##### get domains from politifact CSV files (later also check buzzfeed 2017, 2018)
    elif args.data_source == 'fake_list':
        import pandas as pd
        df = pd.read_csv('seed_files/{}_fake_list.csv'.format(args.prefix))
        domains = df['domain']

    elif args.data_source == 'user_input':
        domains = ['nativestuff.us']
        # nirty.org
        # 2efu.com
        # baito2ch.com
        # shineyclub.com
        # tinuru.com

    elif args.data_source == 'milk':
        import pandas as pd
        df = pd.read_csv('seed_files/{}_milk_list.csv'.format(args.prefix))
        domains = df['domain']
        args.query_type = 'url'

    else:
        print('data_source not available!')
        exit()
    
    pprint(len(domains))
    ##### get domains from json files
#     discovered = json.load(open('/Users/zc/Documents/twitter_data/network_data/impeach_20191029_timeline/impeach_20191029_timeline_usersimilarity_threshold_08_sub_0_node_2238.json', 'r'))
#     domains = [entry['url'] for entry in discovered['top_fake_domain']]

#     domains = ['laksa141.com']
#     101board.com
#     laksa141.com
#     16wmpo.com
#     thetrumpmedia.com 
# ktvuchannel2news.com
    
    #     domains = ['DailyNews10.com']    
#     domains = ['2020maga.pro', 'alchemistzhao.com', 'aznewsroundup.com', 'chezflan.com', 'childrenofnine.com', 'dospalosnews.com', 'fortunstarinv.com', 'gayrehoboth.com', 'gnzmedia.com', 'lintsremover.com', 'maga2020.pro', 'matchnetworkcom.com', 'newsleno.com', 'thecubenews.com']

    LOG_DIR = "{}/{}".format(args.log_dir, prefix)
#     test_crawler()
    crawl_suspicious_news(domains, LOG_DIR, prefix, args.use_vpn, args.overwrite, args.server, args.show_head, args.query_type, args.ip_rotate, args.ip_index)
#     crawl_multithread(args.prefix, args.log_dir, args.n_process, args.collection)

# when the redirection happens on the server side, Page.frameNavigated only stores final landing URL, not the initial URL
# we can always read the original url from COMMAND Navigate

# to get in-browser redirection, parse
# DEVTOOLS EVENT Page.frameScheduledNavigation

# to get 3XX type of redirection: [6.789][DEBUG]: DEVTOOLS EVENT Network.requestWillBeSent {
# 'documentURL': url will be redirected to
# 'redirectResponse'['requestHeaders']['host']
# key, must have 'requestHeaders' key!, there are other types of same domain, js request redirections

