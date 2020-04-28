# encoding:utf-8
import json
def dict2json(dic):
    js = json.dumps(dic)
    file = open("alert.json",mode='a')# 追加模式 ,encoding='utf-8'
    file.write(js+'\n')
    file.close()
