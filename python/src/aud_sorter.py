import os
import sys
import datetime
import logging
import glob
import json
import re
import shutil
from pathlib import Path

from aud_metadata import aud_metadata

import pathvalidate as pathval
#from pathvalidate import ValidationError, validate_filename, sanitize_filepath, sanitize_filename
from optparse import OptionParser
from pathlib import Path

class aud_sorter:
    debug = False
    data_path = ''
    media_path = ''
    one_file = ''

    unprocessed_path = ''
    metadata_path = ''

    def __init__(self, **kwargs):
        if 'debug' in kwargs.keys():
            self.debug = kwargs['debug']
        if 'data_path' in kwargs.keys():
            self.data_path = kwargs['data_path']
        if 'media_path' in kwargs.keys():
            self.media_path = kwargs['media_path']
        if 'one_file' in kwargs.keys():
            self.one_file = kwargs['one_file']

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

            self.processed_path = os.path.join(self.data_path, 'processed')
            self.__create_dir(self.processed_path)

            logging.info('data_path: '+self.data_path)
        else:
            logging.error('Missing data_path arg')
            sys.exit(1)

    def __create_dir(self, path):
        if not os.path.exists(path):
            logging.warning("directory doesn't exist, creating " + path)
            os.makedirs(path)

        if not os.access(path, os.W_OK):
            logging.error("directory " + path + " not writable")
            sys.exit(1)

    def __valid_filepath(self, path):
        #path = path.replace("&", "and")
        path = path.replace(":", "-")

        # Replace these chars
        # /, :, *, ?, ", <, >, |
        chars = '\:*?"<>|'
        path = re.sub('['+chars+']', '', path)

        return path

    def __clean_string(self, s):
        s = str(s)
        s = s.replace("/", " ")
        s = s.replace("®", "")
        s = s.strip()

        return s

    def __iremoveprefix(self, haystack, needle):
        return re.sub('^'+needle, '', haystack, flags=re.I)

    def __iremovesuffix(self, haystack, needle):
        return re.sub(needle+'$', '', haystack, flags=re.I)

    def __ireplace(self, haystack, needle, replace):
        return re.sub(needle, replace, haystack, flags=re.I)

    def __isascii(self, s):
        """Check if the characters in string s are in ASCII, U+0-U+7F."""
        return len(s) == len(s.encode())

    # Decrypt all the audio books
    def run(self, **kwargs):
        logging.info("Starting sorter")

        count = 0

        my_file = Path(self.one_file)
        if my_file.is_file():
            file_list = [self.one_file]
        else:
            file_list = glob.glob(os.path.join(self.metadata_path, '*.json'))

        for metadata_file in file_list:
            meta = aud_metadata(filename = metadata_file)

            count = count + 1

            # Check for correct metadata status
            if not meta.get('encrypted_verified'):
                logging.warning('verified is not true, skipping...')
                logging.debug(metadata_file)
                continue

            # File not decrypted, skipping
            if not meta.get('decrypted'):
                logging.info('Book not decrypted, skipping...')
                logging.debug(metadata_file)
                continue

            if meta.get('complete'):
                logging.info('complete flag set, skipping...')
                logging.debug(metadata_file)
                continue

            # Ignore path check if override is set
            if meta.get('path_override'):
                meta.set('path_check', True)

            # Check if decrypted file exists
            source_file = os.path.join(self.processed_path, meta.get('decrypted_file_name'))
            if not os.path.isfile(source_file):
                logging.error('decrypted file is missing, skipping...')
                logging.debug(metadata_file)
                continue

            author = self.__clean_string(meta.get('author'))
            author = author.replace("- editor", "")
            author = author.replace("- translator", "")
            author = author.strip()

            series_name = ""

            title = self.__clean_string(meta.get('title'))
            title = self.__ireplace(title, "\(Adapted\)", "")
            title = self.__ireplace(title, "\(Abridged\)", "")
            title = self.__ireplace(title, "\(Unabridged\)", "")
            title = self.__iremovesuffix(title, ": An Audible Original Drama")
            title = self.__iremovesuffix(title, ": An Audible Original")
            title = self.__iremovesuffix(title, ": A Sci-Fi LitRPG")
            title = title.strip()

            # Remove A Novel from the end
            title = self.__iremovesuffix(title, ': A Novel')

            logging.info('Processing "'+title+'" by "'+author+'"')

            # Generate save path
            if not meta.get('path_override'):

                # Check if book is in a series
                if meta.get('book_num') == -1 and not meta.get('series'):
                    meta.set('save_path', os.path.join(
                        self.media_path,
                        author,
                        title,
                        meta.get('decrypted_file_name')
                        )
                    )
                else:
                    series_name = self.__clean_string(meta.get('series'))
                    series_name = self.__ireplace(series_name, "\(Adapted\)", "")
                    series_name = self.__ireplace(series_name, "\(Abridged\)", "")
                    series_name = self.__ireplace(series_name, "\(Unabridged\)", "")
                    series_name = self.__ireplace(series_name, "\(Author's Preferred Order\)", "")
                    series_name = self.__iremoveprefix(series_name, "The ")
                    series_name = series_name.strip()

                    if not series_name.lower().endswith("trilogy") and \
                        not series_name.lower().endswith("novels") and \
                        not series_name.lower().endswith("series"):
                        series_name = series_name+" Series"

                    if meta.get('book_num') and meta.get('book_num') != "-1":
                        book_num = self.__clean_string(meta.get('book_num'))

                        if len(book_num) == 1:
                            book_num = '0'+book_num

                    # Get base series
                    base_series = meta.get('series').strip()
                    base_series = self.__ireplace(base_series, "\(Adapted\)", "")
                    base_series = self.__ireplace(base_series, "\(Abridged\)", "")
                    base_series = self.__ireplace(base_series, "\(Unabridged\)", "")
                    base_series = self.__ireplace(base_series, "\(Author's Preferred Order\)", "")
                    base_series = self.__iremovesuffix(base_series, 'trilogy')
                    base_series = self.__iremovesuffix(base_series, 'novels')
                    base_series = self.__iremovesuffix(base_series, 'series')
                    base_series = base_series.strip()

                    # Remove the series name from title
                    title = self.__iremovesuffix(title, ": "+base_series)
                    title = self.__iremovesuffix(title, ": The "+base_series)
                    title = self.__iremovesuffix(title, ": "+base_series.removeprefix("The ").strip())
                    title = self.__iremovesuffix(title, ": "+base_series+" Series")
                    title = self.__iremovesuffix(title, ": A "+base_series+" Novel")
                    title = self.__iremovesuffix(title, ": An "+base_series+" Novel")
                    title = self.__iremovesuffix(title, ": The "+base_series+" Trilogy")
                    title = self.__iremovesuffix(title, ": "+base_series+": The Complete Stories")
                    title = self.__iremovesuffix(title, ": Book (.*) of "+base_series)
                    title = self.__iremovesuffix(title, ": Book (.*) of The "+base_series)
                    title = self.__iremovesuffix(title, ": "+base_series+": Book (.*)")

                    # Add book number to title
                    if meta.get('book_num') and str(meta.get('book_num')) != "-1":
                        title = ("Book {0} - "+title).format(book_num)

                    # if meta.get('audible_id') == "B002V1BPOQ":
                    #     print("base_series: "+base_series)
                    #     print("title:       "+title)
                    #     sys.exit()

                    meta.set('save_path', os.path.join(
                        self.media_path,
                        author,
                        series_name,
                        title,
                        meta.get('decrypted_file_name')
                        )
                    )

                meta.set('path_check', True)

                # Check if the file path is clean
                matches = [
                    "novel",
                    "novella",
                    "series",
                    "trilogy",
                    "unabridged",
                    "editor",
                    "translator",
                ]
                if any(x in title.lower() for x in matches):
                    logging.warning("title:  "+title)
                    meta.set('path_check', False)

                if any(x in author.lower() for x in matches):
                    logging.warning("author:  "+author)
                    meta.set('path_check', False)

                matches = [
                    "unabridged",
                    "editor",
                    "translator",
                ]
                if any(x in series_name.lower() for x in matches):
                    logging.warning("series_name:  "+series_name)
                    meta.set('path_check', False)

            # Check for weird file paths
            try:
                file_name = os.path.basename(meta.get('save_path'))
                file_path = os.path.dirname(meta.get('save_path'))

                pathval.validate_filename(platform = "windows", filename = file_name)
                pathval.validate_filepath(platform = "windows", file_path = file_path)
            except pathval.ValidationError as e:
                logging.warning('Invalid chars in safe path')
                logging.debug(e)
                meta.set('path_check', False)

            if not meta.get('path_check'):
                logging.warning("path check failed, skipping... "+metadata_file)
                meta.save(metadata_file)
                continue


            # Check if file already exists
            if os.path.isfile(meta.get('save_path')):
                if os.path.getsize(source_file) != os.path.getsize(meta.get('save_path')):
                    logging.info('bad final audio file found, deleting...')
                    logging.debug('metadata_file: '+metadata_file)
                    logging.debug('save_path:     '+meta.get('save_path'))
                    os.remove(meta.get('save_path'))
                else:
                    logging.info('valid file already exists, skipping...')
                    meta.set('complete', True)
                    meta.save(metadata_file)
                    continue

            #copy file to path
            logging.info('Starting copy of "'+meta.get('title')+'"')

            folder_path = os.path.dirname(meta.get('save_path'))
            Path(folder_path).mkdir(parents=True, exist_ok=True)

            shutil.copyfile(source_file, meta.get('save_path'))

            logging.info('copy complete')

            # Confim file is correct size
            if os.path.getsize(source_file) == os.path.getsize(meta.get('save_path')):
                logging.info('audio file copied successfully')
                meta.set('complete', True)
            else:
                logging.info('bad save file found, deleting... '+metadata_file)
                os.remove(meta.get('save_path'))

            # Save meta data
            meta.save(metadata_file)
            logging.info("")

        logging.info("Total Book Count: "+str(count))


if __name__ == "__main__":
    def main():
        parser = OptionParser(usage="Usage: %prog [options]", version="%prog 0.2")
        parser.add_option("-d", "--debug",
                        action="store_true",
                        dest="debug",
                        default=False,
                        help="run program in debug mode, enable this for 2FA enabled accounts or for authentication debugging")
        parser.add_option("--data-path",
                        action="store",
                        dest="data_path",
                        default="/mnt/media/downloads/audibletoolkit",
                        help="data directory",)
        parser.add_option("--media-path",
                        action="store",
                        dest="media_path",
                        default="/mnt/media/books/audiobooks",
                        help="data directory",)
        parser.add_option("--log-path",
                        action="store",
                        dest="log_path",
                        default="/mnt/media/downloads/audibletoolkit/logs",
                        help="log directory",)
        parser.add_option("--one-file",
                        action="store",
                        dest="one_file",
                        default="",
                        help="",)
        (options, args) = parser.parse_args()

        dt = datetime.datetime.now().strftime("%Y-%m-%dT%H-%M-%S")

        basepath = os.path.dirname(os.path.realpath(__file__))
        os.chdir(basepath)

        data_path = options.data_path
        media_path = options.media_path
        log_path = options.log_path

        one_file = options.one_file

        # Make log dir if needed
        if not os.path.exists(log_path):
            os.makedirs(log_path)

        log_level = logging.INFO
        if options.debug:
            log_level = logging.DEBUG

        logging.basicConfig(
            format='%(levelname)s(#%(lineno)d):%(message)s',
            level=log_level,
            filename=log_path+"/aud-sorter-%s.log" % (dt)
        )
        logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))

        sorter = aud_sorter(
            data_path = data_path,
            media_path = media_path,
            one_file = one_file,
        )
        sorter.run()

    main()
