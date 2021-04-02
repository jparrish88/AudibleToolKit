import re
import sys
import time
import datetime
import os
import logging
import base64
import hashlib
import urllib
import binascii
import wget
import requests
import shutil
import json
import selenium
#from seleniumwire import webdriver
from selenium import webdriver
from optparse import OptionParser
from getpass import getpass


class aud_downloader:
    debug = False
    data_path = ''
    base_url = 'https://www.audible.com'
    lang = "us"
    player_id = ''

    username = ""
    password = ""

    driver = None
    books_downloaded = 0
    max_pages = 0
    unprocessed_path = ''
    metadata_path = ''

    def __init__(self, **kwargs):
        if 'debug' in kwargs.keys():
            self.debug = kwargs['debug']
        if 'data_path' in kwargs.keys():
            self.data_path = kwargs['data_path']
        if 'base_url' in kwargs.keys():
            self.base_url = kwargs['base_url'].rstrip('/')
        if 'lang' in kwargs.keys():
            self.lang = kwargs['lang']
        if 'player_id' in kwargs.keys():
            self.player_id = kwargs['player_id']
        if 'username' in kwargs.keys():
            self.username = kwargs['username']
        if 'password' in kwargs.keys():
            self.password = kwargs['password']

        if os.getenv("DEBUG"):
            self.debug = True

        if self.data_path:
            # Convert path to abspath (creates path Chrome can use on Windows)
            # Must happen before we add separator
            self.data_path = os.path.abspath(self.data_path)

            # if not self.data_path.endswith(os.path.sep):
            #     self.data_path += os.path.sep

            self.__create_dir(self.data_path)

            self.unprocessed_path = self.data_path+'/unprocessed'
            self.__create_dir(self.unprocessed_path)

            self.metadata_path = self.data_path+'/metadata'
            self.__create_dir(self.metadata_path)

            logging.info('data_path: '+self.data_path)
        else:
            logging.error('aud_downloader: Missing data_path arg')
            sys.exit(1)

        if self.lang != "us" and self.base_url.endswith(".com"):
            self.base_url = self.base_url.replace('.com', "." + self.lang)

    def __create_dir(self, path):
        if not os.path.exists(path):
            logging.warning("directory doesn't exist, creating " + path)
            os.makedirs(path)

        if not os.access(path, os.W_OK):
            logging.error("directory " + path + " not writable")
            sys.exit(1)

    # Download all the audio books for this account
    def run(self, **kwargs):
        logging.info("Starting downloader")

        # Download chrome driver, if needed

        # Setup Chrome Driver
        self.__configure_browser()

        self.__login_audible()

        # Open Audible library
        logging.info("Opening Audible library")
        self.driver.get(self.base_url+"/lib")
        time.sleep(2)

        self.__loop_pages()

        logging.info("Downloader complete!")


    def __configure_browser(self):
        logging.info("Configuring browser")

        opts = webdriver.ChromeOptions()

        # This user agent will give us files w. download info
        # This is the old user agent, we are not getting metadata files anymore
        #opts.add_argument("user-agent=Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko")

        opts.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36")
        chromePrefs = {
            "profile.default_content_settings.popups": "0",
            "download.default_directory": self.unprocessed_path,
            }
        opts.add_experimental_option("prefs", chromePrefs)

        if sys.platform == 'win32':
            chromedriver_path = "..\\bin\\chromedriver.exe"
        else:
            chromedriver_path = "../bin/chromedriver"

        logging.info("Starting browser")

        logging.debug("Chrome Driver Path: "+chromedriver_path)

        self.driver = webdriver.Chrome(
            options=opts,
            executable_path=chromedriver_path,
            )
        self.driver.implicitly_wait(3) # seconds

    def __login_audible(self):
        base_url = self.base_url

        # Step 1
        if '@' in self.username: # Amazon login using email address
            login_url = "https://www.amazon.com/ap/signin?"
        else:
            # Audible member login using username (untested!)
            login_url = self.base_url+"/sign-in/ref=ap_to_private?forcePrivateSignIn=true&rdPath="+urllib.parse.quote_plus(self.base_url+"/?")

        # Setup a player id
        # keep this same to avoid hogging activation slots
        player_id = base64.encodebytes(binascii.unhexlify(self.player_id)).rstrip()

        logging.debug("[*] Player ID is %s" % player_id)
        payload = {
            'openid.ns':           'http://specs.openid.net/auth/2.0',
            'openid.identity':     'http://specs.openid.net/auth/2.0/identifier_select',
            'openid.claimed_id':   'http://specs.openid.net/auth/2.0/identifier_select',
            'openid.mode':         'logout',
            'openid.assoc_handle': 'amzn_audible_' + self.lang,
            'openid.return_to':    self.base_url + '/player-auth-token?playerType=software&playerId=%s=&bp_ua=y&playerModel=Desktop&playerManufacturer=Audible' % (player_id)
            }
        query_string = urllib.parse.urlencode(payload)
        url = login_url + query_string
        logging.info("Opening Audible for language %s" % (self.lang))
        self.driver.get(self.base_url + '/?ipRedirectOverride=true')
        logging.info("Logging in to Amazon/Audible")
        self.driver.get(url)
        search_box = self.driver.find_element_by_id('ap_email')
        search_box.send_keys(self.username)
        search_box = self.driver.find_element_by_id('ap_password')
        search_box.send_keys(self.password)
        if self.debug: # enable if you hit CAPTCHA or 2FA or other "security" screens
            logging.warning("[!] Running in DEBUG mode. You will need to login in a semi-automatic way, wait for the login screen to show up ;)")
            time.sleep(32)
        else:
            search_box.submit()

    def __loop_pages(self):
        books_downloaded = 0

        self.max_pages = int(self.driver.find_elements_by_class_name('pageNumberElement')[-1].get_attribute('data-value'))
        logging.info("Found %s pages of books" % self.max_pages)

        pagenum = 1
        while True:
            logging.info("Processing page %s" % pagenum)

            script = "var style = document.createElement('style'); style.type = 'text/css'; style.innerText = '.selected-row {border: 3pt solid red !important; padding: 2px !important;}'; document.head.appendChild(style);"
            self.driver.execute_script(script)

            # Download books on page
            self.__download_files_on_page()
            time.sleep(5)

            if pagenum == self.max_pages:
                break

            # Go to next page
            button = self.driver.find_element_by_class_name('nextButton')
            link = button.find_element_by_tag_name('a')

            script = "arguments[0].click();"
            self.driver.execute_script(script, link)

            pagenum += 1

        logging.info("Downloaded or skipped a total of %s books" % (self.books_downloaded,))

    def __download_files_on_page(self):
        # Find each row
        rows = self.driver.find_elements_by_class_name('adbl-library-content-row')
        for row in rows:
            meta = {
                'audible_id': '',
                'verified':   False,
                'title':      '',
                'author':     '',
                'narrator':   '',
                'series':     '',
                'book_num':   -1,
                'file_size':  0,
            }

            self.driver.execute_script("arguments[0].scrollIntoView();", row)

            # Add row color
            element = row.find_element_by_class_name('bc-row-responsive')
            self.driver.execute_script("arguments[0].classList.add('selected-row');", element)

            meta['audible_id'] = row.find_element_by_name('asin').get_attribute('value')

            try:
                meta['title'] = row.find_element_by_class_name('bc-size-headline3').text
            except selenium.common.exceptions.NoSuchElementException:
                pass

            try:
                meta['author'] = row.find_element_by_class_name('authorLabel').find_element_by_class_name('bc-size-callout').text
            except selenium.common.exceptions.NoSuchElementException:
                pass

            try:
                meta['narrator'] = row.find_element_by_class_name('narratorLabel').find_element_by_class_name('bc-size-callout').text
            except selenium.common.exceptions.NoSuchElementException:
                pass

            try:
                meta['series'] = row.find_element_by_class_name('seriesLabel').find_element_by_class_name('bc-size-callout').text
            except selenium.common.exceptions.NoSuchElementException:
                pass

            try:
                meta['series'] = row.find_element_by_class_name('seriesLabel').find_element_by_class_name('bc-size-callout').text
            except selenium.common.exceptions.NoSuchElementException:
                pass

            meta['clean_title'] = re.sub(' ', '_', re.sub(r'[^A-Za-z0-9 ]+', '', meta['title'].lower()))

            meta['file_id'] = meta['audible_id']+"-"+meta['clean_title'][:25].rstrip('_')

            logging.info("Found item: (%s) %s by: %s, nat: %s" % (meta['audible_id'], meta['title'], meta['author'], meta['narrator']))

            # Check meta data to see if we have already downloaded this file
            file_name = meta['file_id']+'.json'

            full_file_path = os.path.normpath(self.metadata_path+'/'+file_name)
            if os.path.isfile(full_file_path):
                with open(full_file_path, "r") as f:
                    try:
                        metadata = json.load(f)

                        if metadata['verified'] == True:
                            logging.info('Book verified downloaded, skipping...')
                            continue
                    except ValueError:  # includes simplejson.decoder.JSONDecodeError
                        logging.warning("Decoding JSON file '"+file_name+"' has failed")

            logging.info('Searching for download button')

            # Disable wait to speed up button search
            self.driver.implicitly_wait(0)

            # Look for download button
            buttons = row.find_elements_by_class_name('bc-text')

            # Look for download button
            buttons = row.find_elements_by_class_name('adbl-lib-action-download')

            # Search for button that says "Download"
            link = ''
            for button in buttons:
                logging.info('next button')
                button_text = button.find_element_by_class_name('bc-text').text.strip()

                logging.info('Found button: '+button_text)

                if button_text == 'Download':
                    logging.debug('Found download button!')
                    link = button.find_element_by_tag_name('a')
                    break

            # Disable wait to speed up this search
            self.driver.implicitly_wait(3)

            if not link:
                logging.info('(-1) No download button, Skipping...')
                continue

            url = link.get_attribute('href')
            logging.info("Download Link: '%s'" % (url,))

            if meta['verified']:
                logging.info('Book already verified, Skipping...')
                continue

            # Check "Content-Length" of file
            response = requests.head(url, allow_redirects=True)
            remote_file_size = response.headers.get('content-length', 0)

            if meta['file_size'] and meta['file_size'] == remote_file_size:
                logging.info("Book already download and same size, skipping downloading")
                meta['file_size'] = remote_file_size
                meta['verified'] = True

            else:
                tmp_file = wget.download(url)
                logging.info("\nDownloaded file: "+file_name)

                #rename file and move to unprocssed folder
                _, file_extension = os.path.splitext(tmp_file)
                meta['file_name'] = meta['file_id']+file_extension

                local_file_size = os.path.getsize(tmp_file)

                logging.info('remote_file_size: '+str(remote_file_size))
                logging.info('local_file_size: '+str(local_file_size))

                if int(remote_file_size) == int(local_file_size):
                    full_file_path = self.unprocessed_path+'/'+meta['file_name']
                    shutil.move(tmp_file, full_file_path)
                    meta['file_size'] = remote_file_size
                    meta['verified'] = True

                    self.books_downloaded = self.books_downloaded + 1
                    logging.info("Download verified")

            # Save metadata file
            full_metadata_path = os.path.normpath(self.metadata_path+'/'+meta['file_id']+'.json')

            with open(full_metadata_path, "w") as f:
                json.dump(meta, f, indent=4, sort_keys=True)
                logging.info('writing metadata')

            sys.exit(-1)

    def __wait_for_download_or_die(self, file_path, timeout):
        retry = 0
        dl_sleep = 5
        while (dl_sleep*retry) < timeout and not os.path.isfile(file_path):
            logging.info("%s not downloaded yet, sleeping %s seconds (retry #%s)" % (file_path, dl_sleep, retry))
            retry = retry + 1
            time.sleep(dl_sleep)
        if not os.path.isfile(file_path):
            logging.critical("Chrome used more than %s seconds to download %s, something is wrong, exiting" % (dl_sleep*retry, file_path))
            sys.exit(1)

if __name__ == "__main__":
    def main():
        parser = OptionParser(usage="Usage: %prog [options]", version="%prog 0.2")
        parser.add_option("-d", "--debug",
                        action="store_true",
                        dest="debug",
                        default=False,
                        help="run program in debug mode, enable this for 2FA enabled accounts or for authentication debugging")
        parser.add_option("-l", "--lang",
                        action="store",
                        dest="lang",
                        default="us",
                        help="us (default) / de / fr",)
        parser.add_option("-p",
                        action="store",
                        dest="player_id",
                        default=None,
                        help="Player ID in hex (optional)",)
        parser.add_option("-w",
                        action="store",
                        dest="dw_dir",
                        default="/mnt/audibletoolkit/unprocessed",
                        help="Download directory (must exist)",)
        parser.add_option("--user",
                        action="store",
                        dest="username",
                        default=None,
                        help="Username (optional, will be asked for if not provied)",)
        parser.add_option("--password",
                        action="store",
                        dest="password",
                        default=None,
                        help="Password (optional, will be asked for if not provied)",)

        dt = datetime.datetime.now().strftime("%Y-%m-%dT%H-%M-%S")

        basepath = os.path.dirname(os.path.realpath(__file__))
        os.chdir(basepath)

        data_path = os.path.abspath(basepath+'/../files/')
        logpath = os.path.normpath(data_path+'/../log')

        # Make log dir if needed
        if not os.path.exists(logpath):
            os.makedirs(logpath)

        logging.basicConfig(
            format='%(levelname)s(#%(lineno)d):%(message)s',
            level=logging.INFO,
            #level=logging.DEBUG,
            filename=logpath+"/audible-download-%s.log" % (dt)
        )
        logging.getLogger('undetected_chromedriver').level = logging.INFO
        logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))

        (options, args) = parser.parse_args()

        if options.username:
            username = options.username
        else:
            username = raw_input("Username: ")

        if options.password:
            password = options.password
        else:
            password = getpass("Password: ")

        dl = aud_downloader(
            data_path = data_path,
            username  = username,
            password  = password,
        )
        dl.run()

    main()
