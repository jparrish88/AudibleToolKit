import os
import json
import logging

class aud_metadata:
    meta = {
        'audible_id':          '',
        'title':               '',
        'author':              '',
        'narrator':            '',
        'series':              '',
        'book_num':            -1,
        'encrypted_verified':  False,
        'encrypted_file_name': '',
        'encrypted_file_size': 0,
        'decrypted':           False,
        'decrypted_file_name': '',
        'decrypted_file_size': 0,
        'activation_bytes':    '', # Activation bytes from audible
        'save_path':           '', # Final path to save decrypted file
        'path_check':          False, # Check if save_path is valid
        'path_override':       False, # Override save_path if if the auto-detected path is funky
        'complete':            False, # Mark whole process as complete
    }

    def __init__(self, **kwargs):
        if 'activation_bytes' in kwargs.keys():
            self.meta['activation_bytes'] = kwargs['activation_bytes']
        if 'filename' in kwargs.keys():
            self.load(kwargs['filename'])

    # Load metadata file
    def load(self, filename):
        with open(filename, "r") as f:
            try:
                saved_meta = json.load(f)
            except ValueError:  # includes simplejson.decoder.JSONDecodeError
                logging.error("Decoding metadata file '"+filename+"' has failed")
                return False

        # Fix formatting of saved_meta from old versions
        try:
            saved_meta['encrypted_file_size'] = int(saved_meta['encrypted_file_size'])
        except KeyError:
            pass

        try:
            saved_meta['encrypted_verified'] = saved_meta['verified']
            saved_meta.pop('verified')
        except KeyError:
            pass

        # Override activation_bytes if provided
        if self.meta['activation_bytes'] != '':
            saved_meta.pop('activation_bytes')

        # Merge incomming data with defaults
        self.meta = {**self.meta, **saved_meta}

    def save(self, filename):
        filepath = os.path.abspath(filename)

        with open(filepath, "w") as f:
            json.dump(self.meta, f, indent=4, sort_keys=True)
            logging.debug('writing metadata')

    def get(self, item):
        return self.meta[item]

    def set(self, item, value):
        self.meta[item] = value

    def log_data(self):
        logging.info("")
        for key in self.meta:
            logging.info("%s -> %s" % (key.ljust(20), str(self.meta[key])))
        logging.info("")
