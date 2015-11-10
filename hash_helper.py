import sys
import zlib as z
import hashlib as h
import argparse

#-------------------------------------------------------------------------------------------------

BLOCK_SIZE = 1024*1024*256

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
        self.add_argument('-x', '--hash', type=str, required=True)


    def error(self, message):
        """
        Writes an error message and the help message to stderr then exits with error.
        """
        sys.stderr.write("\nError: {}\n\n".format(message))
        self.print_help()
        sys.exit(2)

#-------------------------------------------------------------------------------------------------

def get_string_hash(target, which_hash):
    """
    Runs the target string through the desired hashing function. Ensures a hex result is returned.
    """

    # must encode Unicode objects to bytes before they can be hashed
    target = target.encode('utf-8')

    function_map = dict(zip(
        ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'adler32', 'crc32'],
        [h.md5, h.sha1, h.sha224, h.sha256, h.sha384, h.sha512, z.adler32, z.crc32]
    ))

    hash_result = function_map[which_hash](target)

    # crc32 and adler32 return a numerical result. Format as hex and return
    if which_hash in ('crc32', 'adler32'):
        return format(hash_result, 'x')

    return hash_result.hexdigest()


def get_file_hash(target, which_hash):
    """
    Runs the target file through the desired hashing function. Ensures a hex result is returned.
    """

    hashlib_flags = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
    hashlib_funcs = [h.md5, h.sha1, h.sha224, h.sha256, h.sha384, h.sha512]
    hashlib_map = dict(zip(hashlib_flags, hashlib_funcs))

    if which_hash in hashlib_flags:
        func = hashlib_map[which_hash]
        return perform_hashlib_hash(func, target)

    elif which_hash == 'adler32':
        return perform_adler32_hash(target)

    elif which_hash == 'crc32':
        return perform_crc32_hash(target)


def perform_crc32_hash(target):
    """
    Perform the CRC32 hash against the target file. Return the result in hexadecimal form.
    """

    with open(target, 'rb') as target:
        prev = 0
        for line in target:
            prev = z.crc32(line, prev)

        return format(prev & 0xFFFFFFFF, 'x')


def perform_adler32_hash(target):
    """
    Perform the Adler32 hash against the target file. Return the result in hexadecimal form.
    """

    hash_sum = 1
    with open(target, 'rb') as target:

        while True:
            data = target.read(BLOCK_SIZE)
            if not data:
                break
            hash_sum = z.adler32(data, hash_sum)
            if hash_sum < 0:
                hash_sum += 2**32

        return format(hash_sum, 'x')


def perform_hashlib_hash(hash_function, target):
    """
    Since all the hashing functions from hashlib in the sdlib work the same, this is simple
    wrapper function around them. Reads raw file contents a chunk at a time, passes them
    through the hashing algorithm, and returns the result in hexadecimal form.
    """

    hash = hash_function()
    with open(target, 'rb') as target:
        while True:
            data = target.read(BLOCK_SIZE)
            if not data:
                break
            hash.update(data)

        return hash.hexdigest()

#----------------------------------------------------------------------

if __name__ == '__main__':

    args = PyHashHelperParser().parse_args()

    if not (args.file or args.string):
        print('\nMust provide either a file or a string literal to be hashed.')
        sys.exit(2)

    desired_hashes = args.hash.split(',')
    justify_len = max(len(h) for h in desired_hashes)

    if args.string:
        target = args.string
        target_type_func = get_string_hash
    else:
        target = args.file.name
        target_type_func = get_file_hash

    print()
    for hash_func in args.hash.split(','):
        hashed = target_type_func(target, hash_func)
        print('{}: {}'.format(hash_func.rjust(justify_len), hashed))
