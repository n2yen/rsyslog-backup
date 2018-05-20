# Tests installation script

# back-up and install rsyslog configuration
FILE=/etc/rsyslog.conf
if [ -f $FILE ]; then
    cp $FILE $FILE.bak
fi
cp test/rsyslog.conf /etc/rsyslog.conf

# install policy file, generator script.
if [ ! -e /opt/logs ]; then
    mkdir /opt/logs
    # set the permissions to 755?
    chmod 755 /opt/logs
fi

# copy the relevant files
cp test/policy.csv /opt/logs/
cp test/generator.py /opt/logs/
if [ ! -e /opt/logs/test.log ]; then
    touch /opt/logs/test.log
fi

# 
#sudo cp .libs/imfilethrottleids.so /usr/lib64/rsyslog/
#
