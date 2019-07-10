#!/bin/sh

# Start log
/etc/init.d/rsyslog start

while ! nc -z ${RABBITMQ_HOSTNAME} ${RABBITMQ_PORT}; do
  echo "Waiting RabbitMQ to launch..."
  sleep 2
done

# Correct working directory
cd /opt/opencti-connector-misp

# Start the connector
python3 misp.py