FROM python:slim-buster	


# System upgrade and install
RUN apt-get update && apt-get install -y -f python3-dev
RUN pip install --upgrade pip
RUN apt-get install -y python3-pip default-jre libxinerama1 libdbus-1-dev libcups2-dev libx11-xcb-dev

# Copy and install LibreOffice
RUN apt-get install -y libreoffice libreoffice-script-provider-python python3-uno
RUN cp /usr/lib/python3/dist-packages/uno.py /usr/local/lib/python3.11/site-packages

# Install Python modules
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

# Copy the connector
COPY src /opt/connector
WORKDIR /opt/connector
RUN mkdir -p /opt/connector/tmp

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
