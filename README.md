# dnsMonitor
DNS monitoring made simple.

### route53
You will have to provide appropriate profile name to use for aws credentials and/or config.
```
python script.py -profile my-profile-name
# default name is `default`
```

### Logging
You can set the logging level to `info` or `debug`.
```
python script.py -v debug
# default level is `info`
```

### Configuration
You can provide a `.json` formatted file in **`CONFIG_FILE`** environment variable. **`whitelists`** field encapsulate the options to whitelist entries from DNS records.
```
{
  "whitelists": {
    "ips": ["x.x.x.x"],
    "hosts": ["example.com"],
    "txts": ["sample-txt-value"]
  }
}
```
**`ips`** are looked up in `A` or `AAAA` records, **`hosts`** are looked up in `CNAME` records and **`txts`** are looked up in `TXT` records. 

```
"ignore_records": ["MX", "SOA"]
```
**`ignore_records`** field in config allows to ignore specified record types.
