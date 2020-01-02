#!/bin/bash

/usr/local/sonar-scanner/bin/sonar-scanner \
    -X \
  -Dsonar.projectKey=git:master:security_api \
  -Dsonar.sources=. \
  -Dsonar.host.url=http://223.202.202.47:9000/sonar \
  -Dsonar.login=8a73a6b326ae30fe557af52566572e16e68ba046
  

if [ $? -eq 0 ]; then
    echo "sonarqube code-publish over."
fi