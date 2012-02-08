from struct import pack, unpack
from hashlib import sha256
from Crypto.Cipher import AES
from StringIO import StringIO

class KdbReaderException(Exception):
    pass

class KdbReaderFileParseError(KdbReaderException):
    pass

class KdbReaderDecodeFailError(KdbReaderException):
    pass

class KdbReader(object):
    DB_HEADER_SIZE   = 124
    DB_SIG_1         = 0x9AA2D903
    DB_SIG_2_v1      = 0xB54BFB65
    DB_SIG_2_v2      = 0xB54BFB67
    DB_VER_DW        = 0x00030002
    DB_FLAG_SHA2     = 1
    DB_FLAG_RIJNDAEL = 2
    DB_FLAG_ARCFOUR  = 4
    DB_FLAG_TWOFISH  = 8

    def __init__(self, filename):
        with open(filename) as infile:
            header = infile.read(self.DB_HEADER_SIZE)
            data = infile.read()

        print 'read in %d+%d bytes' % (len(header), len(data))
        self.header = self.parse_header(header)
        self.data = data
        self.is_parsed  = False

    def parse(self, password):
        try:
            cleartext = self.decrypt_body(password, self.data)
            self.parse_body(cleartext)
            self.is_parsed  = True
            return True, ""
        except KdbReaderException as e:
            raise e

    def parse_body(self, cleartext):
        self.groups, pos = self.parse_groups(cleartext, 0)
        self.entries, pos = self.parse_entries(cleartext, pos)
        assert len(cleartext) == pos, 'too much data'

    def parse_entries(self, data,pos):
        n_entries = self.header['n_entries']
        entries = []
        entry = {}
        while n_entries:
            type = unpack('H', data[pos:pos+2])[0]
            pos += 2
            assert pos <= len(data), 'Data out of bounds'
            size = unpack('L', data[pos:pos+4])[0]
            pos += 4
            assert pos + size <= len(data), 'Data out of bounds'

            if type == 1:
             #   print size
             #   entry['id'] = unpack('L', data[pos:pos+4])[0]
                pass
            elif type == 2:
                entry['group_id'] = unpack('L', data[pos:pos+4])[0]
            elif type == 4:
                entry['title'] = data[pos:pos+size-1]
            elif type == 5:
                entry['url'] = data[pos:pos+size-1]
            elif type == 6:
                entry['username'] = data[pos:pos+size-1]
            elif type == 7:
                entry['password'] = data[pos:pos+size-1]
            elif type == 8:
                entry['comment'] = data[pos:pos+size-1]
            elif type == 0xFFFF:
                entries.append(entry)
                entry = {}
                n_entries -= 1
            else:
                # TODO: fill in more info for entries
                pass
            pos += size

        return entries, pos

    def parse_groups(self, data, pos):
        n_groups = self.header['n_groups']
        groups = {}
        group = {}
        while n_groups:
            type = unpack('H', data[pos:pos+2])[0]
            pos += 2
            assert pos < len(data), 'Data out of bounds'
            size = unpack('L', data[pos:pos+4])[0]
            pos += 4
            assert pos + size <len(data), 'Data out of bounds'

            if type == 0xFFFF:
                groups[group['id']] = group
                group = {}
                n_groups -= 1
            elif type == 1:
                group['id'] = unpack('L', data[pos:pos+4])[0]
            elif type == 2:
                group['title'] = data[pos:pos+size-1]
            else:
                # TODO: Fill in more info for groups
                pass

            pos += size

        return groups, pos

    def decrypt_body(self, password, data):
        key = sha256(password).digest()
        hdr = self.header

        # sha256 the password, encrypt it upon itself 50000 times, sha256 it again, and sha256 it again concatenated with a random number :|
        cipher = AES.new(hdr['seed_key'], AES.MODE_ECB)
        for x in range(hdr['seed_rot_n']):
            key = cipher.encrypt(key)
        key = sha256(key).digest()
        key = sha256(hdr['seed_rand'] + key).digest()
        cipher = AES.new(key, AES.MODE_CBC, hdr['enc_iv'])
        body = cipher.decrypt(data)

        # remove some padding
        padding = unpack("b", body[-1])[0]
        body = body[:-padding]

        if sha256(body).digest() != hdr['checksum']:
            raise KdbReaderDecodeFailError()

        return body

    def parse_header(self, data):
        magic_number = unpack('LL', data[0:8])
        assert magic_number[0] == self.DB_SIG_1, 'Not a KeePassX file'
        assert magic_number[1] == self.DB_SIG_2_v1, 'Not a KeePassX v1 file'
        assert len(data) >= self.DB_HEADER_SIZE, 'Truncated file'

        # read in the header
        fields =         ('sig1', 'sig2', 'flags', 'ver','seed_rand','enc_iv','n_groups','n_entries','checksum','seed_key','seed_rot_n')
        unpacked = unpack('L       L       L        L     16s         16s      L          L           32s        32s        L', data)
        hdr = dict(zip(fields, unpacked))

        assert hdr['ver'] & 0xFFFFFF00 == self.DB_VER_DW & 0xFFFFFF00, 'Wrong DB_VER_DW'

        if hdr['flags'] & self.DB_FLAG_RIJNDAEL:
            hdr['enc_type'] = 'aes256'
        else:
            assert False, "Unsupported encryption"

        return hdr

    def list(self):
        assert self.is_parsed
        output = StringIO()
        for each in self.entries:
            print >>output, 'Title:    ', each['title']
            print >>output, 'Group:    ', self.groups[each['group_id']]['title']
            print >>output, 'Url:      ', each['url']
            print >>output, 'Username: ', each['username']
            print >>output, 'Password: ', each['password']
            print >>output, 'Comment:  ', each['comment']
            print >>output, '-' * 25
        
        return output.getvalue()

    def search(self, term):
        def is_in_dict(term, dict):
            for each in dict.values():
                if isinstance(each, (str, unicode)) and term.lower() in each.lower():
                    return True
            return False

        assert self.is_parsed
        output = StringIO()
        for each in self.entries:
            if is_in_dict(term, each):
                print >>output, 'Title:    ', each['title']
                print >>output, 'Group:    ', self.groups[each['group_id']]['title']
                print >>output, 'Url:      ', each['url']
                print >>output, 'Username: ', each['username']
                print >>output, 'Password: ', each['password']
                print >>output, 'Comment:  ', each['comment']
                print >>output, '-' * 25

        return output
