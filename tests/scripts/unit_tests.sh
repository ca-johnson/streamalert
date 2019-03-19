#!/bin/bash

# Export fake creds to keep moto from complaining
export AWS_ACCESS_KEY_ID=foobar_key
export AWS_SECRET_ACCESS_KEY=foobar_secret

/usr/local/opt/python@2/bin/python2.7 -m pytest tests/unit
