# Chaos. Version 0.0.1a

*Lorenz attractors for cryotography.*

### Automatic Installation

```
sudo curl https://web.addr/for/install-chaos.sh | sh
```

### Manual Installation

```sh

$ git clone https://github.com/okavatti/chaos.git

$ cd chaos

$ go build

$ chmod +x ./chaos

$ sudo cp ./chaos /usr/bin/chaos

$ source /path/to/your/.shellrc # i.e ~/.bashrc, ~/.zshrc

```

### Usage

##### Options

Step 1. Asking for help :)
```
# Help Menu
$ ./chaos -h
Usage of ./chaos:

chaos [option] [argument] [string]

  --- Options ---

  -file string
    	File path to hash
  -genhardened string
    	Generate hardened hash
  -genhash string
    	Generate simple hash
  -graphics
    	Enable graphics visualization
  -verify string
    	Data to verify against hash
  -verifyfile string
    	File to verify against hash

  --- Arguments ---
  -hardenedhash string
    	Hardened hash JSON (base64 or raw)
  -hash string
    	Hash to verify against (base64)
  -input string
    	Input data to hash
```

##### Hashing

generating a hardened hash

```sh
# generating a hash for a given string
$ chaos -genhardened -input "test"
```

generating a regular hash

```sh
$ chaos -genhash -input "test"
HEX: 004d0ab2a4a842b6114cf666880ecdca40000089df564dfd1d0ce34bfd8293487461a4dcf1f6ee5d3a8907bfb69e9d2aa667a476712d727d616e592bc3957505
B64: AE0KsqSoQrYRTPZmiA7NykAAAInfVk39HQzjS/2Ck0h0YaTc8fbuXTqJB7+2np0qpmekdnEtcn1hblkrw5V1BQ== # <-- this is the hash
```

##### Verification

Verifying a hardened hash

```sh
# verifying a hardened hash
$ chaos -verify "test" -hardenedhash "ewogICJoYXNoIjogIkFBRzgxTU5WRGVGYm5IazVURkFQNnpJQlJYMWk2REhoeTUzbGpnQ1AzNnU1L0pReG1mdVdvV21iRTgyY0RQWGxhdE1JY2h5bmFKK3YraWZsSFNJR0ZBPT0iLAogICJzYWx0IjogewogICAgIm1hc3Rlcl9zYWx0IjogIkNteTgrNVNkZEorTFU3YlJBci9POW4yWWp0WGVpWTdoK0s3RHd6ZmFrUUk9IiwKICAgICJzdGFnZV9zYWx0cyI6IFsKICAgICAgIkZGY2orNThZNCtSSjVOb1VMUzE0OHc9PSIsCiAgICAgICJmWnRFUmRudzBLT2dVdzVNV0Nib1F3PT0iLAogICAgICAiNlJ5c1FOQ3JDVWNnMVdVMlhCY3B0dz09IiwKICAgICAgIkNZR25Jc04zWEJRWDBMaXkwbEJqZEE9PSIKICAgIF0sCiAgICAidGltZXN0YW1wX3NhbHQiOiAiZThBMXpsWE1XY1oreXFwQSIsCiAgICAibWV0YV9zYWx0IjogIkdMVWhNUkVyYUhnNzJHTFhzRGpHNW5OTU5NeDZRcGdCIgogIH0sCiAgImNoZWNrcG9pbnRzIjogWwogICAgewogICAgICAic3RhZ2UiOiAwLAogICAgICAiaXRlcmF0aW9uIjogMjAwMCwKICAgICAgImhhc2giOiAibDNvSzRRc1dRSU16OGRjZ1pvMVRHSUp6RWI5elJ5emxVSlVONXVEby9ZMD0iCiAgICB9LAogICAgewogICAgICAic3RhZ2UiOiAxLAogICAgICAiaXRlcmF0aW9uIjogMzAwMCwKICAgICAgImhhc2giOiAicEF5TENONzJzc0psMVhtVWcxZ2JsZnM1WnJIMW44bDRrTExKUUZmUnJqMD0iCiAgICB9LAogICAgewogICAgICAic3RhZ2UiOiAyLAogICAgICAiaXRlcmF0aW9uIjogMjUwMCwKICAgICAgImhhc2giOiAidkhMcDZCWU5peENXb0M1VWpRKy9yL3RvSDRnaC8vaTlPdDhsWFhuTHVQQT0iCiAgICB9LAogICAgewogICAgICAic3RhZ2UiOiAzLAogICAgICAiaXRlcmF0aW9uIjogMTgwMCwKICAgICAgImhhc2giOiAiTEVETTM0R0xyS2lZMXlqQzExbE9uWkhaaGdQQlRHcWo1a003MmNKV252az0iCiAgICB9CiAgXSwKICAiY29tcHV0ZV90aW1lX25zIjogMTAwNDY3MTI3LAogICJtZW1vcnlfdXNlZF9rYiI6IDMyNzUsCiAgInBhcmFtZXRlcnMiOiB7CiAgICAiYmV0YV9wZXJ0dXJiYXRpb24iOiAwLjIxMjc0NTA5ODAzOTIxNTcsCiAgICAiZHRfc2NhbGUiOiAxLjAxMzcyNTQ5MDE5NjA3ODQsCiAgICAiaXRlcmF0aW9uX211bHRpcGxpZXIiOiAwLjkwMDM5MjE1Njg2Mjc0NTEsCiAgICAibWVtb3J5X211bHRpcGxpZXIiOiAxLjUxNzY0NzA1ODgyMzUyOTMsCiAgICAicXVhbnR1bV9yZXNpc3RhbmNlX2xldmVsIjogMywKICAgICJyaG9fcGVydHVyYmF0aW9uIjogLTAuNzQxMTc2NDcwNTg4MjM1MywKICAgICJzaWdtYV9wZXJ0dXJiYXRpb24iOiAtMC4yODAzOTIxNTY4NjI3NDUxCiAgfQp9"
Hardened OK: true

```

Verifying a regular hash

```
# verifying a regular hash
$ chaos -verify "test" -hash "AMmilpDw7x++kIZg7J6002elX7+tBLI56z9+8o/GMwFoTSKuDB4bG3lqQddXQxrzgUCKeji7UySak8CP83+nCg=="
Legacy OK: false # TODO: FIX LEGACY HASH
```
