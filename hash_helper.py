import hashlib as hlb
import zlib as zlb
import sys

#----------------------------------------------------------------------

hash_flags = ['--md5', '--sha1', '--sha224', '--sha256',
              '--sha384', '--sha512', '--adler32', '--crc32']

hash_funcs = [hlb.md5, hlb.sha1, hlb.sha224, hlb.sha256,
              hlb.sha384, hlb.sha512, zlb.adler32, zlb.crc32]

function_map = dict(zip(hash_flags, hash_funcs))

#----------------------------------------------------------------------

def get_hash(contents, which_hash):

    hash_result = function_map[which_hash](open(contents, 'rb').read())

    if which_hash in ('--crc32', '--adler32'):
        return format(hash_result, 'x')

    return hash_result.hexdigest()

#----------------------------------------------------------------------

if __name__ == '__main__':

    contents = sys.argv[1]
    which_hash = sys.argv[2]

    print()
    print(get_hash(contents, which_hash))
