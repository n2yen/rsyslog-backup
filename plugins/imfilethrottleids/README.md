
Rsyslog 'imfilethrottleid' plugin - Throttling id specific input
=====================

The throttling mechanism is a 'input module' style plugin for rsyslog. At a high level, the
design is based on the existing file-based input (imfile) module with the minor modification 
of handling ratelimiting as well as accumulating the counts of dropped messages (for at
least a minute) for later publishing.

General Design
--------------------
Throttling is implemented as an plugin, input module, mostly based on the existing
'imfile' input module and the existing ratelimiting software already implemented in
rsyslog. The exsting rsyslog ratelimit module has the capbility to handle 'ratelimiting'
on a per ratelimit instance basis, this inspired a similar module 'throttlelimiting'. 
throttlelimiting extends the ratelimiting functionality a little bit, by adding the
ability to accumulate the number of suppressed messages to a specific interval
(seconds). In this case, we accumulate suppressed message counts for 1 minute, and then
send a message downstream indicating the number of message suppressed for a particular
throttlelimit instance. A throttlelimit instance is created for each ID to throttle, as
defined in a policy file.

Building from Source
--------------------
Follow the instructions at: http://www.rsyslog.com/doc/build_from_repo.html

### Build Environment

In general, you need

* libestr
* liblogging (stdlog component)

These packages can be installed via yum.

### Build with id specific throttling
In addition to the usual build instructions as per building rsyslog, add '--enable-imfilethrottleids' 
during the 'configure' step. This will configure the throttling module as well as any other 
plugin modules and configuration settings in your build. 
An example build sequence enabling 'imfilethrottleids' is below:

configure --enable-imfilethrottleids
make
make install
cd plugins/imfilethrottledids
./install.sh      # installs: policy.csv, new rsyslog.conf, and generator.py (tests)

Testing explanation
--------------------
1. The included rsyslog.conf has a configured 'throttle' ruleset.
create /opt/logs directory and copy the generator.py python script there. 
as root run the generator.py script which generate test events into /opt/logs/test.log

2. copy the policy file to the appropriate location.

3. The rsyslog configuration is configured to read the above log file as input and throttle
events as necessary. The test events generator will generate 3 different events, 1 of
which, is not found in the policy file, and the rest are defined in the policy file with
different throttle limits

4. The included file, rsyslog.conf (line 24) defines the ruleset 'throttle' for testing. The
ruleset tests the imfilethrottleid -> omkafka pipeline.

5. The include rsyslog.conf defines a Kafka topic 'omkafka-test', which needs to be
created in kafka configuration. 

6. Adding Kafka to test pipeline<br/>
a. start the zookeeper, and kafka server<br/>
> bin/zookeeper-server-start.sh config/zookeeper.properties
> bin/kafka-server-start.sh config/server.properties

b. create 'omkafka-test' topic:<br/>
> bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partitions 1 --topic omkafka-test
> bin/kafka-topics.sh --list --zookeeper localhost:2181

c. send some test messages to 'omkafka-test' topic:<br/>
> bin/kafka-console-producer.sh --broker-list localhost:9092 --topic omkafka-test

d. start 'omkafka-test' producer:<br/>
> bin/kafka-console-consumer.sh --bootstrap-server localhost:9092 --topic test --from-beginning

7. In order to push events into rsyslog, run the generator script at 
   /opt/logs/generator.py
This script outputs events into /opt/logs/test.log, rsyslog is configured to accept
messages from test.log then push and/or throttle logs to omkafka module. The complete 
pipeline looks like the following:

generator.py -> test.log -> rsyslog [ imfilethrottleid -> omkafka ] -> kafka [omkafka-test topic]

8. The policy file (installed by install.sh, above) at /opt/logs/policy.csv has two IDs
   configured for throttling - ID1 @ 100 logs/sec, and ID2 @ 200 logs/sec.

The generator.py script will generate a burst of 250 logs/sec. At each burst, an ID is selected raondomly
from 3 different IDs (ID1, ID2, ID3) and repeated 250 times. The script then waits for 1
sec, and repeats the burst again. 

