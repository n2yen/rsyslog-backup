#!/usr/bin/python
import subprocess
import time
import random

tags = ['ID1', 'ID2', 'ID3']

def cur_time_millis():
    return int(round(time.time()*1000))

#def generate():
#    for tag in tags:
#        text = 'abcd'
#        subprocess.run([log, tag+',', str(cur_time_millis())+',', text]) 

def generatelogger(tag):
    log = 'logger'
    text = 'abcd'
    subprocess.run([log, tag+',', str(cur_time_millis())+',', text]) 

def generate_to_file(fd, n):
    for i in range(n):
        tag = random.choice(tags)
        log = 'echo'
        text = 'abcd'
        s = tag+', '+str(cur_time_millis())+', '+text+'\n'
        fd.write(s)
        print(s[:-1])
        #subprocess.run([log, '"', tag+',', str(cur_time_millis())+',', text, '"', '>> test.out']) 

def main():
    print('generator running...')

    burst = 250
    resttime = 1
    #burst = 5
    #resttime = 1 

    try:
        while True:
            with open('test.log', 'a') as fd:
                generate_to_file(fd, burst)
            time.sleep(resttime)

    except KeyboardInterrupt:
        print('\nexit')

if __name__ == "__main__":
    main()
