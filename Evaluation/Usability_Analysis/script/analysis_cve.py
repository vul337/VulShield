import re
import sys,getopt
import os,glob
import json
import binascii
from bisect import bisect_left

cve_dict={}
collect_dict={}
load_dict={}
cwe_list=[]
count=0

sanitizer_list=["CWE-787","CWE-476","CWE-369","CWE-121","CWE-122","CWE-124","CWE-125","CWE-129","CWE-119","CWE-120","CWE-190","CWE-416","CWE-415","CWE-362"]
def collect_info(DebugInfo):
    global cve_dict
    global load_dict
    global count
    global collect_dict
    with open(DebugInfo) as f1:
        f11=f1.readlines()
    for x in f11:
        x=x.split(".")[0].strip()
        cve_file="../cve_cwe_analysis.json"
        with open(cve_file,'r') as load_f:
            load_dict = json.load(load_f)
            for cve in load_dict:
                if str(cve)!=x: continue
                if str(x) in cve_dict: continue
                cve_dict[str(x)]={}
                cwe=load_dict[x]['cwe']
                cve_dict[str(x)]['cwe']=load_dict[x]['cwe']
                if cwe not in cwe_list and cwe not in sanitizer_list:
                    cwe_list.append(cwe)
                    collect_dict[str(cwe)]=[]
                if cwe not in sanitizer_list:
                    collect_dict[str(cwe)].append(str(x))
                    count=count+1

def main():
    global cve_dict
    global collect_dict
    collect_info("../log/cleaned_patch.log")
    print(cwe_list)
    print(len(cwe_list))
    print(count)
    sorted_collect_dict = dict(sorted(collect_dict.items(), key=lambda x:(-len(x[1]),x[0])))
    for i in sorted_collect_dict:
        print(i)
        print(len(sorted_collect_dict[i]))
    print(sorted_collect_dict)
    json_str = json.dumps(cve_dict, sort_keys=True, indent=4, separators=(',', ':'))
    OutputFile="cleaned_cve_analysis.json"
    with open(OutputFile, 'w') as json_file:
        json_file.write(json_str)

if __name__ == "__main__":
   main()
