import hashlib as hlb
import sys

#----------------------------------------------------------------------

hash_flags = ['--md5', '--sha1', '--sha224', '--sha256', '--sha384', '--sha512']
hash_funcs = [hlb.md5, hlb.sha1, hlb.sha224, hlb.sha256, hlb.sha384, hlb.sha512]


function_map = dict(zip(hash_flags, hash_funcs))

#----------------------------------------------------------------------

def get_hash(contents, which_hash):

    hash_func = function_map[which_hash]

    return hash_func(open(contents, 'rb').read()).hexdigest()

#----------------------------------------------------------------------

if __name__ == '__main__':

    contents = sys.argv[1]
    which_hash = sys.argv[2]

    print()
    print(get_hash(contents, which_hash))
