# PyHashHelper
A utility script which provides a wrapper around common hashing functions (MD5, SHA256, etc).

## Usage

PyHashHelper provides an easy way to hash a string literal, or the contents of a file.
Simply run the script (`hash_helper.py`), passing in the following arguments:

* `-x [name of hash function]` (possibilities are md5, sha1, sha224, sha256, sha384, sha512, Adler32, CRC32)
* `-s [string literal]`  **or**  `-f [file name/path]`


#### Example: hashing a string literal

```
$ python hash_helper.py -s hello -x md5
5d41402abc4b2a76b9719d911017c592

$ python hash_helper.py -s "hash this string" -x sha256
eedb752a1e7a2691ebd896ce86d868c5ddc795419be5925030cbee768153700b
```
