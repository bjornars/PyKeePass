from struct import pack, unpack
from hashlib import sha256
from Crypto.Cipher import AES

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

    def __init__(self, filename, password):
        self.pw = sha256(password).digest()
        self.data = open(filename).read()
        self.is_inited = False

    def list(self):
        assert self.is_inited
        for each in self.entries:
            print 'Title:    ', each['title']
            print 'Group:    ', self.groups[each['group_id']]['title']
            print 'Url:      ', each['url']
            print 'Username: ', each['username']
            print 'Password: ', each['password']
            print 'Comment:  ', each['comment']
            print '-' * 25

    def search(self, term):
        def is_in_dict(term, dict):
            for each in dict.values():
                if isinstance(each, (str, unicode)) and term.lower() in each.lower():
                    return True
            return False

        assert self.is_inited
        for each in self.entries:
            if is_in_dict(term, each):
                print 'Title:    ', each['title']
                print 'Group:    ', self.groups[each['group_id']]['title']
                print 'Url:      ', each['url']
                print 'Username: ', each['username']
                print 'Password: ', each['password']
                print 'Comment:  ', each['comment']
                print '-' * 25

    def parse(self):
        self.parse_header()
        self.decrypt_body()
        self.parse_body()
        self.is_inited = True

    def parse_body(self):
        self.groups = self.parse_groups()
        self.entries = self.parse_entries()

    def parse_entries(self):
        n_entries = self.header['n_entries']
        entries = []
        entry = {}
        pos = 0
        while n_entries:
            type = unpack('H', self.data[pos:pos+2])[0]
            pos += 2
            assert pos <= len(self.data), 'Data out of bounds'
            size = unpack('L', self.data[pos:pos+4])[0]
            pos += 4
            assert pos + size <= len(self.data), 'Data out of bounds'

            if type == 1:
             #   print size
             #   entry['id'] = unpack('L', self.data[pos:pos+4])[0]
                pass
            elif type == 2:
                entry['group_id'] = unpack('L', self.data[pos:pos+4])[0]
            elif type == 4:
                entry['title'] = self.data[pos:pos+size-1]
            elif type == 5:
                entry['url'] = self.data[pos:pos+size-1]
            elif type == 6:
                entry['username'] = self.data[pos:pos+size-1]
            elif type == 7:
                entry['password'] = self.data[pos:pos+size-1]
            elif type == 8:
                entry['comment'] = self.data[pos:pos+size-1]
            elif type == 0xFFFF:
                entries.append(entry)
                entry = {}
                n_entries -= 1
            else:
                # TODO: fill in more info for entries
                pass
            pos += size

        self.data = self.data[pos:]
        return entries

    def parse_groups(self):
        n_groups = self.header['n_groups']
        groups = {}
        group = {}
        pos = 0
        while n_groups:
            type = unpack('H', self.data[pos:pos+2])[0]
            pos += 2
            assert pos < len(self.data), 'Data out of bounds'
            size = unpack('L', self.data[pos:pos+4])[0]
            pos += 4
            assert pos + size <len(self.data), 'Data out of bounds'

            if type == 0xFFFF:
                groups[group['id']] = group
                group = {}
                n_groups -= 1
            elif type == 1:
                group['id'] = unpack('L', self.data[pos:pos+4])[0]
            elif type == 2:
                group['title'] = self.data[pos:pos+size-1]
            else:
                # TODO: Fill in more info for groups
                pass

            pos += size

        self.data = self.data[pos:]
        return groups

    def decrypt_body(self):
        h = self.header
        key = self.pw

        # sha256 the password, encrypt it upon itself 50000 times, sha256 it again, and sha256 it again concatenated with a random number :|
        cipher = AES.new(h['seed_key'], AES.MODE_ECB)
        for x in range(h['seed_rot_n']):
            key = cipher.encrypt(key)
        key = sha256(key).digest()
        key = sha256(h['seed_rand'] + key).digest()
        cipher = AES.new(key, AES.MODE_CBC, h['enc_iv'])
        self.data = cipher.decrypt(self.data)

        # remove some padding
        padding = unpack("b", self.data[-1])[0]
        self.data = self.data[:-padding]

        assert sha256(self.data).digest() == h['checksum'], 'Couldn\'t decrypt, wrong password?'

    def parse_header(self):
        magic_number = unpack('LL', self.data[0:8])
        assert magic_number[0] == self.DB_SIG_1, 'Not a KeePassX file'
        assert magic_number[1] == self.DB_SIG_2_v1, 'Not a KeePassX v1 file'
        assert len(self.data) >= self.DB_HEADER_SIZE, 'Truncated file'

        # read in the header
        h = dict(zip(
                      ('sig1', 'sig2', 'flags', 'ver','seed_rand','enc_iv','n_groups','n_entries','checksum','seed_key','seed_rot_n'),
                unpack('L       L       L        L      16s        16s      L          L           32s        32s        L',
                    self.data[0:self.DB_HEADER_SIZE])))

        assert h['ver'] & 0xFFFFFF00 == self.DB_VER_DW & 0xFFFFFF00, 'Wrong DB_VER_DW'

        if h['flags'] & self.DB_FLAG_RIJNDAEL:
            h['enc_type'] = 'aes256'
        else:
            assert False, "Unsupported encryption"

        self.data = self.data[self.DB_HEADER_SIZE:]
        self.header = h

if __name__ == '__main__':
    from getpass import getpass
    filename = raw_input('Password file: ')
    password = getpass()

    kr = KdbReader(filename, password)
    kr.parse()

    print "File read and decoded successfully"
    while 1:
        try:
            term = raw_input('Search term (or blank): ')

            if term:
                kr.search(term)
            else:
                kr.list()
            raw_input('Done?')

        except EOFError:
            break
        finally:
            # clear screen
            print '\033[2J'

