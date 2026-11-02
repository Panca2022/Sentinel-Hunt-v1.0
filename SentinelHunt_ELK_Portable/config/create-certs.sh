set -euo pipefail
cd /usr/share/elasticsearch
if [ ! -f config/certs/ca/ca.crt ]; then
  bin/elasticsearch-certutil ca --silent --pem --out config/certs/ca.zip
  unzip -oq config/certs/ca.zip -d config/certs
fi
if [ ! -f config/certs/elasticsearch/elasticsearch.crt ]; then
  bin/elasticsearch-certutil cert --silent --pem --name elasticsearch \
    --dns elasticsearch,localhost --ip 127.0.0.1 \
    --ca-cert config/certs/ca/ca.crt --ca-key config/certs/ca/ca.key \
    --out config/certs/elasticsearch.zip
  unzip -oq config/certs/elasticsearch.zip -d config/certs
fi
chown -R root:root config/certs
find config/certs -type d -exec chmod 755 {} \;
find config/certs -type f -exec chmod 600 {} \;
chown root:0 config/certs/elasticsearch/elasticsearch.key
chmod 640 config/certs/elasticsearch/elasticsearch.key
chmod 644 config/certs/ca/ca.crt config/certs/elasticsearch/elasticsearch.crt
echo 'PASS: certificates ready; server key readable by Elasticsearch UID:GID 1000:0.'
