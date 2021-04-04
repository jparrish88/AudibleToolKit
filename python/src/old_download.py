#!/usr/bin/env python

from __future__ import print_function
from getpass import getpass
from optparse import OptionParser
import sys
import time
from selenium import webdriver
#import chromedriver_autoinstaller
from urllib import urlencode
from urlparse import urlparse, parse_qs
import urlparse
from urllib import urlretrieve, FancyURLopener
import urllib
import urllib2
import hashlib
import base64
import os
import binascii
import logging
import selenium
from selenium.webdriver.support.ui import Select
import cgi # cgi.parse_header
import datetime
import socket
import json


# Global Vars
basepath = os.path.dirname(os.path.realpath(__file__))
username = ''

os.chdir(basepath)

def login_audible(driver, options, username, password, base_url, lang):
    # Step 1
    if '@' in username: # Amazon login using email address
        login_url = "https://www.amazon.com/ap/signin?"
    else:
        login_url = "https://www.audible.com/sign-in/ref=ap_to_private?forcePrivateSignIn=true&rdPath=https%3A%2F%2Fwww.audible.com%2F%3F" # Audible member login using username (untested!)
    if lang != "us": # something more clever might be needed
        login_url = login_url.replace('.com', "." + lang)
        base_url = base_url.replace('.com', "." + lang)
    player_id = base64.encodestring(hashlib.sha1("").digest()).rstrip() # keep this same to avoid hogging activation slots
    if options.player_id:
        player_id = base64.encodestring(binascii.unhexlify(options.player_id)).rstrip()
    logging.debug("[*] Player ID is %s" % player_id)
    payload = {
        'openid.ns':'http://specs.openid.net/auth/2.0',
        'openid.identity':'http://specs.openid.net/auth/2.0/identifier_select',
        'openid.claimed_id':'http://specs.openid.net/auth/2.0/identifier_select',
        'openid.mode':'logout',
        'openid.assoc_handle':'amzn_audible_' + lang,
        'openid.return_to':base_url + 'player-auth-token?playerType=software&playerId=%s=&bp_ua=y&playerModel=Desktop&playerManufacturer=Audible' % (player_id)
        }
    query_string = urlencode(payload)
    url = login_url + query_string
    logging.info("Opening Audible for language %s" % (lang))
    driver.get(base_url + '?ipRedirectOverride=true')
    logging.info("Logging in to Amazon/Audible")
    driver.get(url)
    search_box = driver.find_element_by_id('ap_email')
    search_box.send_keys(username)
    search_box = driver.find_element_by_id('ap_password')
    search_box.send_keys(password)
    if os.getenv("DEBUG") or options.debug: # enable if you hit CAPTCHA or 2FA or other "security" screens
        logging.warning("[!] Running in DEBUG mode. You will need to login in a semi-automatic way, wait for the login screen to show up ;)")
        time.sleep(32)
    else:
        search_box.submit()

def configure_browser(options):
    logging.info("Configuring browser")

    opts = webdriver.ChromeOptions()
    
    # Chrome user agent will download files for us
    #opts.add_argument("user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36")
    
    # This user agent will give us files w. download info
    opts.add_argument("user-agent=Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko")
    chromePrefs = {
        "profile.default_content_settings.popups": "0", 
        "download.default_directory": options.dw_dir
        }
    opts.add_experimental_option("prefs", chromePrefs)
    
    if sys.platform == 'win32':
        chromedriver_path = "../bin/chromedriver.exe"
    else:
        chromedriver_path = "../bin/chromedriver"
    
    logging.info("Starting browser")
    
    logging.debug("Chrome Driver Path: "+chromedriver_path)

    driver = webdriver.Chrome(
        chrome_options=opts,
        executable_path=chromedriver_path,
        )
    driver.implicitly_wait(3) # seconds
    
    return driver

class HeadRequest(urllib2.Request):        
    def get_method(self):
        return "HEAD"

class LyingFancyURLopener(FancyURLopener):        
    def __init__(self):
        self.version = 'Audible ADM 6.6.0.19;Windows Vista Service Pack 1 Build 7601'
        FancyURLopener.__init__(self)


def wait_for_download_or_die(datafile):
    retry = 0
    dw_sleep = 5
    while retry < 5 and not os.path.isfile(datafile):
        logging.info("%s not downloaded yet, sleeping %s seconds (retry #%s)" % (datafile, dw_sleep, retry))
        retry = retry + 1
        time.sleep(dw_sleep)
    if not os.path.isfile(datafile):
        logging.critical("Chrome used more than %s seconds to download %s, something is wrong, exiting" % (dw_sleep*retry, datafile))
        sys.exit(1)

def print_progress(block_count, block_size, total_size):
    #The hook will be passed three arguments; 
    #    a count of blocks transferred so far, 
    #    a block size in bytes, 
    #    and the total size of the file. (may be -1, ignored) 

    prev_bytes_complete = (block_count-1)*block_size
    prev_percent = float(prev_bytes_complete)/float(total_size) * 100.0
    prev_progress = "%.0f" % prev_percent
    
    bytes_complete = block_count*block_size
    percent = float(bytes_complete)/float(total_size) * 100.0
    progress = "%.0f" % percent

    if (progress != prev_progress) and (block_count == 0 or int(progress) % 5 == 0 or int(progress) >= 100):
        logging.info("Download: %s%% (%s of %s bytes)" % \
                 (progress, 
                  bytes_complete, 
                  total_size))

def download_file(audible_id, datafile, meta, book, page, maxpage):
    with open(datafile) as f:
        logging.info("Parsing %s, creating download url" % datafile)
        lines = f.readlines()

    dw_options = parse_qs(lines[0])

    metadata = {}
    metadata['datfile'] = dw_options
    metadata['ameta'] = meta

    # Add default metadata vars
    metadata['ameta']['user'] = username
    metadata['ameta']['file_checked'] = False
    metadata['ameta']['file_decrypted'] = False
    metadata['ameta']['audible_id'] = audible_id

    url = dw_options["assemble_url"][0]

    # Build Download URL
    params = {}
    for param in ["user_id", "product_id", "codec", "awtype", "cust_id"]:
        if dw_options[param][0] == "LC_64_22050_stereo":
            params[param] = "LC_64_22050_ster"
        else:
            params[param] = dw_options[param][0]

    url_parts = list(urlparse.urlparse(url))
    query = dict(urlparse.parse_qsl(url_parts[4]))
    query.update(params)

    url_parts[4] = urlencode(query)

    url = urlparse.urlunparse(url_parts)
    logging.info("Book URL: %s" % url)

    logging.info("Downloading file data")
    request_head = HeadRequest(url)
    request_head.add_header('User-Agent', 'Audible ADM 6.6.0.19;Windows Vista Service Pack 1 Build 7601')

    tries = 0
    head_ok = False
    while head_ok == False:
        try:
            head = urllib2.urlopen(request_head)
            head_ok = True
        except urllib2.HTTPError as e_head:
            if tries < 5: 
                tries = tries + 1
                time.sleep(60)
            else:
                raise e_head
        except socket.error as se:
            if tries < 5: 
                tries = tries + 1
                time.sleep(60)
            else:
                raise e_head

    val, par = cgi.parse_header(head.info().dict['content-disposition']) 
    filename = par['filename'].split("_")[0]
    filename = filename + "." +  par['filename'].split(".")[-1]
    size = head.info().dict['content-length']

    # Add file data to metadata
    metadata['ameta']['file_name'] = filename
    metadata['ameta']['file_size'] = size

    logging.info("Filename: %s" % filename)
    logging.info("Size: %s" % size)

    path = "%s%s" % (options.dw_dir, filename)

    logging.info("Book %s of 20 on page %s of %s" % (book, page, maxpage))

    if os.path.isfile(path):
        logging.info("File %s exist, checking size", path)
        if int(size) == os.path.getsize(path):
            logging.info("File %s has correct size, not downloading" % (path,))
            metadata['ameta']['file_checked'] = True
        else:
            logging.warning("File %s had unexpected size, deleting file" % (path,))
            wait_for_file_delete(path)


    if not os.path.isfile(path):
        logging.info("Downloading file %s" % (path,))

        try:
            opener = LyingFancyURLopener() 
            local_filename, headers = opener.retrieve(url, path, reporthook=print_progress)

            logging.info("Completed download of '%s' to %s" % (meta['title'], path))
        except urllib.ContentTooShortError:
            logging.warning("Error downloading file %s, deleting..." % (path,))
            wait_for_file_delete(path)

    # Save data to metadata file
    metadata_path = os.path.normpath(basepath+'/../files/metadata')
    file_name = audible_id+'.json'

    full_file_path = os.path.normpath(metadata_path+'/'+file_name)

    with open(full_file_path, "w") as f:
        f.write(json.dumps(metadata, f, indent=4, sort_keys=True))
        logging.debug('writing metadata')

    logging.info('Sleeping for 20 seconds')
    time.sleep(20)

    return 1

def wait_for_file_delete(file):
    os.remove(file)
    retry = 0
    dw_sleep = 2
    while retry < 5 and os.path.isfile(file):
        logging.info("%s not deleted, sleeping %s seconds (retry #%s)" % (file, dw_sleep, retry))
        retry = retry + 1
        time.sleep(dw_sleep)
    if os.path.isfile(file):
        logging.critical("OS used more than %s seconds to delete %s, something is wrong, exiting" % (file, dw_sleep*retry,))
        sys.exit(1)

def download_files_on_page(driver, page, maxpage, debug):
    books_downloaded = 0

    # Find each row
    rows = driver.find_elements_by_class_name('adbl-library-content-row')
    for row in rows:
        meta = {
            'title': '',
            'author': '',
            'narrator': '',
            'series': '',
            'book_num': -1,
        }

        driver.execute_script("arguments[0].scrollIntoView();", row)

        # Add row color
        element = row.find_element_by_class_name('bc-row-responsive')
        driver.execute_script("arguments[0].classList.add('selected-row');", element)

        audible_id = row.find_element_by_name('asin').get_attribute('value')

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

        logging.info("Found item: (%s) %s by: %s, nat: %s" % (audible_id, meta['title'], meta['author'], meta['narrator']))

        # Check meta data to see if we have already downloaded this file
        metadata_path = os.path.normpath(basepath+'/../files/metadata')
        file_name = audible_id+'.json'

        full_file_path = os.path.normpath(metadata_path+'/'+file_name)
        if os.path.isfile(full_file_path):
            with open(full_file_path, "r") as f:
                try:
                    metadata = json.load(f)

                    if metadata['ameta']['file_checked'] == True:
                        logging.info('Book confirmed downloaded, skipping...')
                        continue
                except ValueError:  # includes simplejson.decoder.JSONDecodeError
                    logging.warning("Decoding JSON file '"+file_name+"' has failed")

        logging.info('Searching for download button')

        # Disable wait to speed up button search
        driver.implicitly_wait(0)

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
        driver.implicitly_wait(3)

        if not link:
            logging.info('(-1) No download button, Skipping...')
            continue

        logging.debug("Download Link: '%s'" % (link.get_attribute('href'),))

        #link.click()
        #logging.info("Waiting for Chrome to complete download of datafile")

        #datafile = "%s%s" % (options.dw_dir, "admhelper")
        #wait_for_download_or_die(datafile)

        #logging.debug("Datafile downloaded")

        books_downloaded = books_downloaded + 1
        download_file(audible_id, datafile, meta, books_downloaded, page, maxpage)
        wait_for_file_delete(datafile)

    return books_downloaded

def configure_audible_library(driver, lang):
    logging.info("Opening Audible library")
    lib_url = "https://www.audible.com/lib"
    if lang != "us":
        lib_url = lib_url.replace('.com', "." + lang)

    driver.get(lib_url)
    time.sleep(2)


def loop_pages(logging, driver):
    books_downloaded = 0

    maxpage = int(driver.find_elements_by_class_name('pageNumberElement')[-1].get_attribute('data-value'))
    logging.info("Found %s pages of books" % maxpage)

    pagenum = 1
    while True:
        logging.info("Processing page %s" % pagenum)

        script = "var style = document.createElement('style'); style.type = 'text/css'; style.innerText = '.selected-row {border: 3pt solid red !important; padding: 2px !important;}'; document.head.appendChild(style);"
        driver.execute_script(script)

        # Download books on page
        books_downloaded = books_downloaded + download_files_on_page(driver, pagenum, maxpage, debug=False)
        time.sleep(5)

        if pagenum == maxpage:
            break

        # Go to next page
        button = driver.find_element_by_class_name('nextButton')
        link = button.find_element_by_tag_name('a')

        script = "arguments[0].click();"
        driver.execute_script(script, link)

        #link.click()

        pagenum += 1

    logging.info("Downloaded or skipped a total of %s books" % (books_downloaded,))

if __name__ == "__main__":
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

    basepath = sys.path[0]
    logpath = os.path.normpath(basepath+'/../log')

    # Make log dir if needed
    if not os.path.exists(logpath):
        os.makedirs(logpath)

    logging.basicConfig(format='%(levelname)s(#%(lineno)d):%(message)s', 
        level=logging.INFO, filename=logpath+"/audible-download-%s.log" % (dt))
    logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))

    (options, args) = parser.parse_args()

    # Convert path to abspath (creates path Chrome can use on Windows)
    # Must happen before we add separator
    options.dw_dir = os.path.abspath(options.dw_dir)

    if not options.dw_dir.endswith(os.path.sep):
        options.dw_dir += os.path.sep

    if not os.path.exists(options.dw_dir):
        logging.info("download directory doesn't exist, creating " + options.dw_dir)
        os.makedirs(options.dw_dir)

    if not os.access(options.dw_dir, os.W_OK):
        logging.error("download directory " + options.dw_dir + " not writable")
        sys.exit(1)

    if not options.username:
        username = raw_input("Username: ")
    else:
        username = options.username
    if not options.password:
        password = getpass("Password: ")
    else:
        password = options.password

    base_url = 'https://www.audible.com/'
    lang = options.lang

    driver = configure_browser(options)
    try:
        wait_for_file_delete("%s%s" % (options.dw_dir, "admhelper"))
    except OSError:
        pass

    login_audible(driver, options, username, password, base_url, lang)
    configure_audible_library(driver, lang)
    loop_pages(logging, driver)

    logging.info("Jobs done!")
    #driver.quit()
    #quit()
