import sys
import zlib as zlb
import hashlib as hlb
import argparse

#----------------------------------------------------------------------

class MyParser(argparse.ArgumentParser):

    def error(self, message):
        print(); sys.stderr.write("Error: {}\n".format(message))
        print(); self.print_help()
        sys.exit(2)

#----------------------------------------------------------------------

def build_parser():

    description = "Displays the checksum of either a string literal or a file. "
    description += "Possible checksum types are md5, sha1, sha224, sha256, sha384, sha512, Adler32, or CRC32."
    parser = MyParser(description=description)

    parser.add_argument('-f', '--file', type=file, required=False)
    parser.add_argument('-s', '--string', type=str, required=False)

    hash_choices = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'adler32', 'crc32']
    parser.add_argument('-x', '--hash', type=str, choices=hash_choices, required=True)

    return parser


def get_hash(target, which_hash):

    hash_flags = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'adler32', 'crc32']
    hash_funcs = [hlb.md5, hlb.sha1, hlb.sha224, hlb.sha256, hlb.sha384, hlb.sha512, zlb.adler32, zlb.crc32]
    function_map = dict(zip(hash_flags, hash_funcs))

    hash_result = function_map[which_hash](target)

    if which_hash in ('crc32', 'adler32'):
        return format(hash_result, 'x')

    return hash_result.hexdigest()

#----------------------------------------------------------------------

if __name__ == '__main__':

    parser = build_parser()
    args = parser.parse_args()

    if not (args.file or args.string):
        print('\nMust provide either a file or a string literal to be checksummed.')
        sys.exit(2)

    if args.file:
        target = open(args.file, 'rb').read()
    else:
        target = args.string

    which_hash = args.hash

    print('\n' + get_hash(target, which_hash))
