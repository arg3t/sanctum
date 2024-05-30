# SANCTUM

Sanctum is a kernel module with one role: create safe heavens within an unsafe
system. When you create a folder whose name starts with `sanctum_` you are that
folder's and everything within it's owner. Everything that you write into that folder
is encrypted, and everything that you read from that folder is decrypted on the go.
You can use sanctum as if it were not there. No other process but the
process that created the sanctum and its children can read the plaintext content of those
files.


To build, just run `make`. Then you can load the kernel module by running `insmod sanctum.ko`.
Once the module is loaded, you can run the `sanctum_manager` helper to create a sanctum
and get dropped into a shell that has privileges in that folder.

```
sanctum_manager create test
```
