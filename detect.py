import os
import datetime
import requests
import time
import random
import raw_data_handle
import re
import json
import http.client
http.client.HTTPConnection._http_vsn = 10
http.client.HTTPConnection._http_vsn_str = 'HTTP/1.0'

base_url = 'https://www.internic.net/domain/root.zone'

def sleepTime():        #整五分钟睡眠的剩余秒数
    #print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    nextTime = (datetime.datetime.now() + datetime.timedelta(minutes=5)).strftime("%Y-%m-%d %H")
    minute = (datetime.datetime.now() + datetime.timedelta(minutes=5)).strftime("%M")
    real_minute = int(minute)-int(minute)%5
    time5 = datetime.datetime.strptime(str(nextTime)+":"+str(real_minute)+":00", "%Y-%m-%d %H:%M:%S")
    sec = time5 - datetime.datetime.now()
    return sec.seconds+1

def init_zone_file():       #爬取根文件并获取当前根文件的SOA号
    response = requests.get(base_url)
    s = str(response.text)[0:94]
    ss = s.split()
    with open('rootZoneFile.txt', 'w', encoding='utf-8') as fp:
        fp.write(response.content.decode('utf-8'))
    return ss[6]

def SOA_Serial_Search(filename):        #获取得到的SOA序列号
    with open("raw_data/ipv4/raw_data_"+filename.lower()+".txt", encoding='utf-8') as file:
        data = file.read().split("******")
    flag_udp = re.search(";; ANSWER SECTION:\n[^\n]*", data[1])
    flag_tcp = re.search(";; ANSWER SECTION:\n[^\n]*", data[2])
    if not flag_udp and not flag_tcp:
        return -1
    elif not flag_udp:
        return int(flag_tcp.group().split("\n")[1].split()[6])
    elif not flag_tcp:
        return int(flag_udp.group().split("\n")[1].split()[6])
    SOA_udp = int(flag_udp.group().split("\n")[1].split()[6])
    SOA_tcp = int(flag_tcp.group().split("\n")[1].split()[6])
    return min(SOA_udp, SOA_tcp)


print("running...")
old_Serial_num = init_zone_file()   #根文件SOA序列号
if raw_data_handle.get_database_SOA() != old_Serial_num:
    raw_data_handle.save_root_zone_file()   #保存获取的根文件


SOA_Latency_count = [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1]        #记录检测到SOA变化经过几个五分钟
detect_count = 0        #获取的json# 数据条数

init_sleep_time = sleepTime()  # 整五分时间睡眠
#print("睡眠",init_sleep_time,"秒")
time.sleep(init_sleep_time)

while True:
    try:
        #print(datetime.datetime.now())
        #print("start")
        bias = random.randint(0, 60)
        #print("随机等待时间：", bias)
        time.sleep(bias)
        #print("正在爬取根文件...")
        now_Serial_num = init_zone_file()
        if now_Serial_num != old_Serial_num:  # SOA版本更新
            #print("SOA更新")
            raw_data_handle.save_root_zone_file()
            old_Serial_num = now_Serial_num
            for char in "abcdefghijklm":
                SOA_Latency_count[ord(char) - ord('a')] += 1
        #print("正在监测中...")
        os.system("./get_data.sh")
    
        #print("正在解析获取到的数据...")
        raw_data_handle.data_init()  # 数据初始化为默认值
        for char in "abcdefghijklm":
            get_SOA_serial = SOA_Serial_Search(char)
            # print(get_SOA_serial)
            if str(get_SOA_serial) != str(now_Serial_num):
                if get_SOA_serial != -1 or (
                        get_SOA_serial == -1 and SOA_Latency_count[ord(char) - ord('a')] != -1):  # 如果SOA询问未超时且未检测到SOA更新过
                    SOA_Latency_count[ord(char) - ord('a')] += 1
            else:
                point = raw_data_handle.data[char.upper()]
                if SOA_Latency_count[ord(char) - ord('a')] != -1:
                    point['Publication_latency'] = SOA_Latency_count[ord(char) - ord('a')] * 5
                else:
                    point['Publication_latency'] = -1
                SOA_Latency_count[ord(char) - ord('a')] = -1
                raw_data_handle.data[char.upper()] = point
    
        _thread = []
        for root in "abcdefghijklm":
            thread = raw_data_handle.myThread(root.upper(), "raw_data_" + root + ".txt")
            _thread.append(thread)
        for t in _thread:
            t.start()
        for t in _thread:
            t.join()
        for t in _thread:
            if t._error:
                raw_data_handle.error_record(t.ID)
                #print("error")
    
        detect_count += 1
        #print("已获取" + str(detect_count) + "组数据")
    
        with open("result/" + str(raw_data_handle.data['TimeStamp']) + ".json", "w") as write_f:
            write_f.write(json.dumps(raw_data_handle.data, ensure_ascii=False))
        time5 = sleepTime()
        #print("睡眠")
        time.sleep(time5)
    except:
        time5 = sleepTime()
        print("睡眠")
        time.sleep(time5)
