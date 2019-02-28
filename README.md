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