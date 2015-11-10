# PyHashHelper
A utility script which provides a wrapper around common hashing functions (MD5, SHA256, etc).

## Usage

PyHashHelper provides an easy way to hash a string literal, or the contents of a file.
Simply run the script (`hash_helper.py`), passing in the following arguments:

* `-x [name of hash function]` 
  * (options are `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, `adler32`, `crc32`)
* `-s [string literal]`  **or**  `-f [file name/path]`


## Examples
#### Hashing a string literal

```
$ python hash_helper.py -s hello -x md5

md5: 5d41402abc4b2a76b9719d911017c592

$ python hash_helper.py -s "hash this string" -x sha256

sha256: eedb752a1e7a2691ebd896ce86d868c5ddc795419be5925030cbee768153700b
```

#### Hashing a file

```
$ python hash_helper.py -f "hash_helper.py" -x crc32

crc32: a9edd8f1

$ python hash_helper.py -f "C:\Program Files\7-Zip\7z.dll" -x adler32

adler32: d1c4348c
```

#### Hashing a target with multiple algorithms

```
$ python hash_helper.py -f ".gitignore" -x sha1,sha256,sha384

  sha1: da7f06f54bf75659d1106c947f551f12fe65de59
sha256: f42341552b7e0886f8101e00ed55c757db2e1dfb656e5256eab6555450b2a8c3
sha384: b5d2415714cf5f5047403c8cfdbfe990bc272b74e7effecd897a0f7e05120c9aec457a3cc06e1ddf36e711e0f88e0e1d

$ python hash_helper.py -f "README.md" -x all

adler32: e7741d04
  crc32: 9009d78b
    md5: c72df167ccc5a8f24c3b94fa2f89347e
   sha1: a91cac2dc151f20eea8d3b44d798837ce8925b7e
 sha224: 6f4f4cbf42dda138910bdf99ee6f65cb86b98d6e75ef8ee2dd13a3ca
 sha256: 899f7bfd3ed4493e9c140b72d581758e9e2f0768b665e91cf64db0517b1d5821
 sha384: 29b9132b1d34a7a4a9a157703465934a839815a21f264f77bd655934a320ce347ca3d610739047918e9190d8ce795a99
 sha512: 7bcb83528360d00ada62be2f8c582514e4ba10b205ad8763264d765c1b3a3724b8992e22e0ed470466dc488e2cbb805753f43dd5ee7f994042bfc15126a1de5d
```

#### Uppercase vs lowercase

By default, PyHashHelper will display the hex representation of the hashes in lowercase. To display these values in uppercase, simply pass the optional `-u` flag.

```
$ python hash_helper.py -s test -x sha1,sha224 -u

  sha1: A94A8FE5CCB19BA61C4C0873D391E987982FBBD3
sha224: 90A3ED9E32B2AAF4C61C410EB925426119E1A9DC53D4286ADE99A809
```
