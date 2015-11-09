import sys
import zlib as z
import hashlib as h
import argparse

#-------------------------------------------------------------------------------------------------

class PyHashHelperParser(argparse.ArgumentParser):
    """
        Simple argparse argument parser. Takes in a target (either a string literal, or a file),
        and the desired hashing algorithm.
    """

    def __init__(self):
        super().__init__(description='Calculates the hash of a string literal or a file')

        self.add_argument('-f', '--file', type=argparse.FileType('r'), required=False)
        self.add_argument('-s', '--string', type=str, required=False)

        hash_choices = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'adler32', 'crc32']
        self.add_argument('-x', '--hash', type=str, choices=hash_choices, required=True)


    def error(self, message):
        """ Writes an error message, and the help message, to stderr then exits with code 2. """
        sys.stderr.write("\nError: {}\n\n".format(message))
        self.print_help()
        sys.exit(2)

#-------------------------------------------------------------------------------------------------

def get_string_hash(target, which_hash):

    hash_flags = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'adler32', 'crc32']
    hash_funcs = [h.md5, h.sha1, h.sha224, h.sha256, h.sha384, h.sha512, z.adler32, z.crc32]
    function_map = dict(zip(hash_flags, hash_funcs))

    hash_result = function_map[which_hash](target)

    if which_hash in ('crc32', 'adler32'):
        return format(hash_result, 'x')

    return hash_result.hexdigest()


def get_file_hash(target, which_hash):

    hashlib_flags = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
    hashlib_funcs = [h.md5, h.sha1, h.sha224, h.sha256, h.sha384, h.sha512]
    hashlib_map = dict(zip(hashlib_flags, hashlib_funcs))

    if which_hash == 'adler32':
        hash_sum = 1
        with open(target, 'rb') as f:
            while True:
                data = f.read(2**20)
                if not data:
                    break
                hash_sum = z.adler32(data, hash_sum)
                if hash_sum < 0:
                    hash_sum += 2**32
            return format(hash_sum, 'x')

    elif which_hash == 'crc32':
        prev = 0
        for line in open(target, 'rb'):
            prev = z.crc32(line, prev)
        return format(prev & 0xFFFFFFFF, 'x')

    else:
        func = hashlib_map[which_hash]()
        target = open(target, 'rb')
        while True:
            data = target.read(2**20)
            if not data:
                break
            func.update(data)

        return func.hexdigest()

#----------------------------------------------------------------------

if __name__ == '__main__':

    args = PyHashHelperParser().parse_args()

    if not (args.file or args.string):
        print('\nMust provide either a file or a string literal to be hashed.')
        sys.exit(2)

    if args.string:
        hashed = get_string_hash(args.string.encode('utf-8'), args.hash)
    else:
        hashed = get_file_hash(args.file.name, args.hash)

    print('\n{}'.format(hashed))
