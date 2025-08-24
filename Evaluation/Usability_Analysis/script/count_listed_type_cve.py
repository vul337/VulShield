import re
import sys,getopt
import os,glob
import json
import binascii
from bisect import bisect_left

cve_dict={}
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
                if cwe in sanitizer_list:
                    count=count+1

def main():
    global cve_dict
    collect_info("../log/all_patch.log")
    print(count)

if __name__ == "__main__":
   main()
