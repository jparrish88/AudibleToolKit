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
import tempfile
import selenium
#from seleniumwire import webdriver
import chromedriver_autoinstaller
from optparse import OptionParser
from getpass import getpass

from aud_metadata import aud_metadata

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
#from webdriver_manager.chrome import ChromeDriverManager


def strtobool(val):
    """Convert a string representation of truth to true (1) or false (0).
    True values are 'y', 'yes', 't', 'true', 'on', and '1'; false values
    are 'n', 'no', 'f', 'false', 'off', and '0'.  Raises ValueError if
    'val' is anything else.
    """
    if isinstance(val, bool):
        return val

    val = val.lower()
    if val in ('y', 'yes', 't', 'true', 'on', '1'):
        return 1
    elif val in ('n', 'no', 'f', 'false', 'off', '0'):
        return 0
    else:
        raise ValueError("invalid truth value %r" % (val,))


class aud_downloader:
    debug = False
    data_path = ''
    base_url = 'https://www.audible.com'
    lang = "us"
    player_id = ''
    activation_bytes = ''

    username = ""
    password = ""

    driver = None
    rsession = None
    books_downloaded = 0
    max_pages = 0
    unprocessed_path = ''
    metadata_path = ''
    chromedriver_path = ''
    headless = True

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
        if 'activation_bytes' in kwargs.keys():
            self.activation_bytes = kwargs['activation_bytes']
        if 'chromedriver_path' in kwargs.keys():
            self.chromedriver_path = kwargs['chromedriver_path']
        if 'headless' in kwargs.keys():
            self.headless = kwargs['headless']

        if os.getenv("DEBUG"):
            self.debug = True

        if self.data_path:
            # Convert path to abspath (creates path Chrome can use on Windows)
            # Must happen before we add separator
            self.data_path = os.path.abspath(self.data_path)

            # if not self.data_path.endswith(os.path.sep):
            #     self.data_path += os.path.sep

            self.__create_dir(self.data_path)

            self.metadata_path = os.path.join(self.data_path, 'metadata')
            self.__create_dir(self.metadata_path)

            self.unprocessed_path = os.path.join(self.data_path, 'unprocessed')
            self.__create_dir(self.unprocessed_path)

            logging.info('data_path: '+self.data_path)
        else:
            logging.error('Missing data_path arg')
            sys.exit(1)

        if self.lang != "us" and self.base_url.endswith(".com"):
            self.base_url = self.base_url.replace('.com', "." + self.lang)

        self.rsession = requests.Session()

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

        chrome_options = webdriver.ChromeOptions()

        chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36")

        if self.headless:
            logging.info("Configuring headless mode")
            chrome_options.add_argument('headless')
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--window-size=1024,768")
            chrome_options.add_argument("--disable-dev-shm-usage")

        chromePrefs = {
            "profile.default_content_settings.popups": "0",
            "download.default_directory": self.unprocessed_path,
            }
        chrome_options.add_experimental_option("prefs", chromePrefs)

        logging.info("Starting browser")

        logging.debug("Chrome Driver Path: "+self.chromedriver_path)

        self.driver = webdriver.Chrome(
            options=chrome_options,
            service=Service(self.chromedriver_path),
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
        search_box = self.driver.find_element(By.ID, 'ap_email')
        search_box.send_keys(self.username)
        search_box = self.driver.find_element(By.ID, 'ap_password')
        search_box.send_keys(self.password)
        if self.debug: # enable if you hit CAPTCHA or 2FA or other "security" screens
            logging.warning("[!] Running in DEBUG mode. You will need to login in a semi-automatic way, wait for the login screen to show up ;)")
            time.sleep(32)
        else:
            search_box.submit()

        # Check for alert boxes for errors
        try:
            logging.info("Checking for alert box")
            alert_box = self.driver.find_element(By.CLASS_NAME, 'a-alert-content')
            logging.error(alert_box.text)
            logging.error("Quitting!")
            exit(21)
        except selenium.common.exceptions.NoSuchElementException:
            pass

    def __loop_pages(self):
        books_downloaded = 0

        pagenum = 1
        while True:
            logging.info("Processing page %s" % pagenum)

            script = "var style = document.createElement('style'); style.type = 'text/css'; style.innerText = '.selected-row {border: 3pt solid red !important; padding: 2px !important;}'; document.head.appendChild(style);"
            self.driver.execute_script(script)

            # Download books on page
            self.__download_files_on_page()
            time.sleep(5)

            # Find the next button
            button = self.driver.find_element(By.CLASS_NAME, 'nextButton')

            if 'bc-button-disabled' in button.get_attribute('class').split():
                break

            link = button.find_element(By.TAG_NAME, 'a')

            # Go to next page
            script = "arguments[0].click();"
            self.driver.execute_script(script, link)

            pagenum += 1

        logging.info("Downloaded or skipped a total of %s books" % (self.books_downloaded,))

    def __download_files_on_page(self):
        # Find each row
        rows = self.driver.find_elements(By.CLASS_NAME, 'adbl-library-content-row')
        for row in rows:

            self.driver.execute_script("arguments[0].scrollIntoView();", row)

            # Add row color
            element = row.find_element(By.CLASS_NAME, 'bc-row-responsive')
            self.driver.execute_script("arguments[0].classList.add('selected-row');", element)

            audible_id = row.find_element(By.NAME, 'asin').get_attribute('value')


            # Check for metadata file
            files = self.__search_for_aud_file(self.metadata_path, audible_id, 'json')

            if len(files) > 0:
                # if metadata file exists, load it
                meta = aud_metadata(activation_bytes = self.activation_bytes, filename=files[0])
            else:
                meta = aud_metadata(activation_bytes = self.activation_bytes)

            # Load in scaped in metadata
            meta.set('audible_id', audible_id)

            try:
                title = row.find_element(By.CLASS_NAME, 'bc-size-headline3').text
                title = re.sub(r', Book (.*)', '', title) # Remove serires book number

                meta.set('title', title)
            except selenium.common.exceptions.NoSuchElementException:
                pass

            try:
                meta.set('author', row.find_element(By.CLASS_NAME, 'authorLabel').find_element(By.CLASS_NAME, 'bc-size-callout').text)
            except selenium.common.exceptions.NoSuchElementException:
                pass

            try:
                meta.set('narrator', row.find_element(By.CLASS_NAME, 'narratorLabel').find_element(By.CLASS_NAME, 'bc-size-callout').text)
            except selenium.common.exceptions.NoSuchElementException:
                pass

            try:
                meta.set('series', row.find_element(By.CLASS_NAME, 'seriesLabel').find_element(By.CLASS_NAME, 'bc-size-callout').text)
            except selenium.common.exceptions.NoSuchElementException:
                pass

            try:
                seriesLabel = row.find_element(By.CLASS_NAME, 'seriesLabel').text

                search = re.search('Book ([\d.-]+)', seriesLabel)
                meta.set('book_num', search.group().replace('Book ', ''))
            except AttributeError:
                pass
            except selenium.common.exceptions.NoSuchElementException:
                pass

            # Build metadata file path
            clean_title = re.sub(' ', '_', re.sub(r'[^A-Za-z0-9 ]+', '', meta.get('title').lower()))
            item_file_id = audible_id+"-"+clean_title[:25].rstrip('_')

            metadata_file = os.path.join(self.metadata_path, item_file_id+'.json')

            # Search for aax file
            files = self.__search_for_aud_file(self.unprocessed_path, audible_id, 'aax')

            if len(files) > 0:
                full_file_path = files[0]
                if os.path.isfile(full_file_path):
                    # If we have an existing ecrypted file, use it
                    meta.set('encrypted_file_name', os.path.basename(full_file_path))
                    logging.info('Found existing aax file: '+meta.get('encrypted_file_name'))

            # If we dont have have an encrypted file, generate its file name
            if meta.get('encrypted_file_name') == '':
                meta.set('encrypted_file_name', item_file_id+'.aax')

            # Log out metadata
            meta.log_data()

            if meta.get('encrypted_file_size') > 0:
                meta.set('encrypted_verified', True)

                meta.save(metadata_file)
                logging.info('Book verified downloaded, skipping...')
                continue

            logging.info('Searching for download button')

            # Disable wait to speed up button search
            self.driver.implicitly_wait(0)

            # Look for download button
            #buttons = row.find_element(By.CLASS_NAME, 'bc-text')

            # Look for download button
            buttons = row.find_elements(By.CLASS_NAME, 'adbl-lib-action-download')

            # Search for button that says "Download"
            link = ''
            for button in buttons:
                logging.info('next button')
                button_text = button.find_element(By.CLASS_NAME, 'bc-text').text.strip()

                logging.info('Found button: '+button_text)

                if button_text == 'Download':
                    logging.debug('Found download button!')
                    link = button.find_element(By.TAG_NAME, 'a')
                    break

            # Disable wait to speed up this search
            self.driver.implicitly_wait(3)

            if not link:
                logging.info('(-1) No download button, Skipping...')
                continue

            url = link.get_attribute('href')
            logging.info("Download Link: '%s'" % (url,))

            if meta.get('encrypted_verified'):
                logging.info('Book already encrypted_verified, Skipping...')
                continue

            # If the saved file size is empty, check the existing file
            local_file = os.path.join(self.unprocessed_path, meta.get('encrypted_file_name'))
            if meta.get('encrypted_file_size') < 1 and os.path.isfile(local_file):
                logging.warning("saved file size invalid, updating from local file")
                meta.set('encrypted_file_size', os.path.getsize(local_file))

            # Check "Content-Length" of file
            self.__sync_cookies()
            response = self.rsession.head(url, allow_redirects=True)
            remote_file_size = response.headers.get('content-length', 0)

            logging.info('remote_file_size: '+str(remote_file_size))

            if meta.get('encrypted_file_size') == int(remote_file_size):
                logging.info("Book already download and same size, skipping downloading")
                meta.set('encrypted_file_size', int(remote_file_size))
                meta.set('encrypted_verified', True)

            else:
                if meta.get('encrypted_file_size') > 0:
                    logging.warning("File size not correct, expected "+str(meta.get('encrypted_file_size'))+", found "+str(remote_file_size))

                local_file_size = 0
                tmp_file = "audfile_"+next(tempfile._get_candidate_names())+".aax"
                try:
                    logging.info("Downloading file")

                    self.__sync_cookies()
                    tmp_file = self.__download_with_status(url, filename=tmp_file)

                    logging.info("\nDownloaded file: "+tmp_file)

                    _, file_extension = os.path.splitext(tmp_file)
                    meta.set('encrypted_file_name', item_file_id+file_extension)

                    local_file_size = os.path.getsize(tmp_file)

                    logging.info('remote_file_size: '+str(remote_file_size))
                    logging.info('local_file_size: '+str(local_file_size))

                except urllib.error.ContentTooShortError:
                    print("\n")
                    logging.warning("Downloading file has failed (ContentTooShortError), skipping book")
                except urllib.error.HTTPError as err:
                    print("\n")
                    logging.error(err)
                except Exception as err:
                    logging.error(err)
                    logging.error(url)

                #rename file and move to unprocssed folder
                if int(local_file_size) > 0 and int(remote_file_size) == int(local_file_size):
                    full_file_path = os.path.join(self.unprocessed_path, meta.get('encrypted_file_name'))
                    shutil.move(tmp_file, full_file_path)
                    meta.set('encrypted_file_size', int(remote_file_size))
                    meta.set('encrypted_verified', True)
                    meta.set('decrypted', False)

                    self.books_downloaded = self.books_downloaded + 1
                    logging.info("Download verified")

                # Clean up tmp file
                if os.path.exists(tmp_file):
                    os.remove(tmp_file)

            # Save metadata file
            meta.save(metadata_file)

    def __sync_cookies(self):
        request_cookies_browser = self.driver.get_cookies()
        c = [self.rsession.cookies.set(c['name'], c['value']) for c in request_cookies_browser]

        # resp = s.post(url, params) #I get a 200 status_code

        # #passing the cookie of the response to the browser
        # dict_resp_cookies = resp.cookies.get_dict()
        # response_cookies_browser = [{'name':name, 'value':value} for name, value in dict_resp_cookies.items()]
        # c = [driver.add_cookie(c) for c in response_cookies_browser]

    def __download_file(self, url, filename):
        with self.rsession.get(url, stream=True) as dl:
            dl.raise_for_status()
            with open(filename, 'wb') as f:
                shutil.copyfileobj(dl.raw, f)

        return filename

    def __download_with_status(self, url, filename):
        import functools
        import pathlib
        from tqdm.auto import tqdm

        r = self.rsession.get(url, stream=True, allow_redirects=True)
        if r.status_code != 200:
            r.raise_for_status()  # Will only raise for 4xx codes, so...
            raise RuntimeError(f"Request to {url} returned status code {r.status_code}")
        file_size = int(r.headers.get('Content-Length', 0))

        path = pathlib.Path(filename).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)

        desc = "(Unknown total file size)" if file_size == 0 else ""
        r.raw.read = functools.partial(r.raw.read, decode_content=True)  # Decompress if needed
        with tqdm.wrapattr(r.raw, "read", total=file_size, desc=desc, ncols=100) as r_raw:
            with path.open("wb") as f:
                shutil.copyfileobj(r_raw, f)

        return str(path)

    def __search_for_aud_file(self, folder, audible_id, ext = ''):
        files = []
        for fileitem in os.listdir(folder):
            if os.path.isfile(os.path.join(folder, fileitem)) and fileitem.startswith(audible_id):
                if not ext or os.path.splitext(fileitem)[-1].lower():
                    files.append(os.path.join(folder, fileitem))

        return files


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
        parser.add_option("--data-path",
                        action="store",
                        dest="data_path",
                        default="/mnt/media/downloads/audibletoolkit",
                        help="data directory",)
        parser.add_option("--log-path",
                        action="store",
                        dest="log_path",
                        default="/mnt/media/downloads/audibletoolkit/logs",
                        help="log directory",)
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
        parser.add_option("--activation_bytes",
                        action="store",
                        dest="activation_bytes",
                        default=None,
                        help="activation_bytes (optional, will be asked for if not provied)",)
        parser.add_option("--account-file",
                        action="store",
                        dest="account_file",
                        default=None,
                        help="JSON Account file (optional)",)
        parser.add_option("--headless",
                        action="store",
                        dest="headless",
                        default=True,
                        help="Run in headless mode (optional)",)
        (options, args) = parser.parse_args()

        dt = datetime.datetime.now().strftime("%Y-%m-%dT%H-%M-%S")

        basepath = os.path.dirname(os.path.realpath(__file__))

        # Dont change to the script path since we want to work from whereever
        #os.chdir(basepath)

        data_path = options.data_path
        log_path = options.log_path

        # Make log dir if needed
        if not os.path.exists(log_path):
            os.makedirs(log_path)

        logging.basicConfig(
            format='%(levelname)s(#%(lineno)d):%(message)s',
            level=logging.INFO,
            #level=logging.DEBUG,
            filename=log_path+"/aud-download-%s.log" % (dt)
        )
        logging.getLogger('undetected_chromedriver').level = logging.INFO
        logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))

        username = ''
        password = ''
        player_id = ''

        if options.account_file:
            logging.info('Loading account info from json file')
            acc_file_path = os.path.abspath(options.account_file)
            print(acc_file_path)
            if os.path.isfile(acc_file_path):
                with open(acc_file_path, "r") as f:
                    try:
                        acc_data = json.load(f)

                        print(acc_data)

                        username = acc_data['user']
                        password = acc_data['pass']
                        player_id = acc_data['player_id']
                        activation_bytes = acc_data['activation_bytes']
                    except ValueError:  # includes simplejson.decoder.JSONDecodeError
                        logging.warning("Decoding Acc JSON file '"+acc_file_path+"' has failed")
            else:
                logging.warning("Unable to find account file: '"+acc_file_path+"'")

        if options.username:
            username = options.username
        if options.password:
            password = options.password
        if options.activation_bytes:
            activation_bytes = options.activation_bytes

        # ask for user info if not provided already
        if sys.__stdin__.isatty():
            if not username:
                username = input("Username: ")
            if not password:
                password = getpass("Password: ")
            if not activation_bytes:
                password = getpass("Activation Bytes: ")

        if sys.platform == 'win32':
            chromedriver_path = os.path.abspath(basepath+"\\..\\bin\\")
        else:
            chromedriver_path = os.path.abspath(basepath+"/../bin/")

        # Check if the current version of chromedriver exists
        # and if it doesn't exist, download it automatically,
        # then add chromedriver to path
        chromedriver_path = chromedriver_autoinstaller.install(path = chromedriver_path)

        dl = aud_downloader(
            data_path = data_path,
            username  = username,
            password  = password,
            activation_bytes = activation_bytes,
            #player_id = player_id, #disable player_id for now since this is broken
            chromedriver_path = chromedriver_path,
            headless = bool(strtobool(options.headless)),
        )
        dl.run()

    main()
