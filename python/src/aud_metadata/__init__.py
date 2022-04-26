


class aud_metadata:
    logging = {}
    meta = {
        'audible_id':          '',
        'verified':            False,
        'decrypted':           False,
        'title':               '',
        'author':              '',
        'narrator':            '',
        'series':              '',
        'book_num':            -1,
        'encrypted_file_name': '',
        'encrypted_file_size': 0,
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

        # Fix formatting of saved_meta
        try:
            saved_meta['encrypted_file_size'] = int(metadata_save['encrypted_file_size'])
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
            logging.info('writing metadata')

    def get(self, item):
        return self.meta[item]

    def put(self, item, value):
        self.meta[item] = value

    def logout(self, item):
        logging.info("")
        for key in self.meta:
            logging.info(key, '->', self.meta[key])
        logging.info("")
