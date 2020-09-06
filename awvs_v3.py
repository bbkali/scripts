import requests
import hashlib
import json
import argparse
import sys
import random
import datetime
from time import sleep
import io
from requests.packages.urllib3.exceptions import InsecureRequestWarning
sys.stdout=io.TextIOWrapper(sys.stdout.buffer,encoding='utf-8')

username = 'xxxxxxxxx'
password = 'xxxx'
awvs_url = 'https://x.x.x.x:13443/'
# 需要扫描的目标文件
filename = 'awvslist.txt'
# 已经扫描完的目标文件
alfilename = 'awvs_csv.txt'
# 扫描并发数
b_num = 6
# 每轮休息时间s
one_sleep = 120

class Awvs():
    awvs = ''
    headers = {
        'Content-Type': 'application/json;charset=UTF-8',
    }

    def __init__(self, awvs_url, username, password):
        self.awvs_url = awvs_url
        password = hashlib.sha256(password.encode()).hexdigest()
        info = {
            "email": username,
            "password": password,
            "remember_me": "false",
            "logout_previous": "true"
        }
        info = json.dumps(info)
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        r = requests.session()
        try:
            X_Auth = r.post(self.awvs_url + 'api/v1/me/login', data=info,
                            verify=False, headers=self.headers, timeout=5).headers['X-Auth']
        except Exception as e:
            print(e,'[-]requests Erro')
            exit('awvs Login failed')
        self.headers['X-Auth'] = X_Auth
        self.awvs = r
        # self.stat = self.scanstat()

    def addTarget(self, target_url):
        info = {
            "address": target_url,
            "description": '',
            'criticality': "10"
        }
        info = json.dumps(info)
        ret = self.awvs.post(self.awvs_url + 'api/v1/targets',
                             data=info, verify=False, headers=self.headers).text
        ret = json.loads(ret)
        return ret.get('target_id')

    def scanTarget(self, target_id):
        info = '{"target_id":"xxxxxxxxxxxx","profile_id":"11111111-1111-1111-1111-111111111111","schedule":{"disable":false,"start_date":null,"time_sensitive":false},"ui_session_id":"81ae275a0a97d1a09880801a533a0ff1"}'
        info = info.replace('xxxxxxxxxxxx', target_id)
        self.awvs.post(self.awvs_url+'/api/v1/scans', data=info,
                       verify=False, headers=self.headers).text

    def scanstat(self):
        while True:
            # 获取当前状态
            result_stat = self.awvs.get(
                self.awvs_url + "/api/v1/me/stats", verify=False, headers=self.headers).json()
            if result_stat.get('targets_count'):
                return result_stat
            else:
                print('[-]获取状态失败！',result_stat)
                sleep(3)
            

    def main_print(self):
        # 打印当前参数
        result = self.scanstat()
        all_target_num = result.get('targets_count')
        alreadnum = result.get('scans_conducted_count')
        pro_num = result.get('scans_running_count')
        vuln_dang = result.get('vuln_count')
        if vuln_dang:
            vuln_dang = vuln_dang.get('high')
        else:
            vuln_dang = ''
        timecode = datetime.datetime.now().strftime("%Y-%m-%d %H:%M ")
        print('[+]{}共有目标{}个,已经完成{}个,正在扫描{}个,高危漏洞{}个'.format(timecode,all_target_num,alreadnum,pro_num,vuln_dang))
        # if not all_target_num:
            # self.main_print()
        if pro_num:
            return int(pro_num)
        else:
            return 0

def opens(file):
    results = []
    with open(file, 'r') as f:
        for i in list(f):
            url = i.strip()
            results.append(url)
    return list(set(results))

def main():
    awvs = Awvs(awvs_url, username, password)
    ids = []
    lists = [x for x in opens(filename) if x not in opens(alfilename)]
    code = 0
    for url in lists:
        target_id = awvs.addTarget(url)
        if target_id:
            ids.append(target_id)
            code += 1
    print('[+]添加新扫描目标{}个'.format(code))
    num = 0
    while num < len(ids):
        if awvs.main_print() < b_num:
            target_id = ids[num]
            num +=1
            awvs.scanTarget(target_id)
        else:
            print('[-]{0} 座位满了，休息一会会'.format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M ")),num)
        sleep(one_sleep)
if __name__ == "__main__":
    # awvs = Awvs(awvs_url, username, password)
    # awvs.main_print()
    main()
    # main_print(self)

