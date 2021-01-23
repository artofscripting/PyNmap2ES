from elasticsearch import Elasticsearch
from datetime import datetime, date, timezone
import time
import socket
import json
import xmltodict    
import os
import uuid
import sys, os.path
sys.path.append(os.path.abspath('../esconfig'))
from esconfig import *

class esLog:
    indexName = str()
    i_d = str()
    type_of_doc = str()
    js = str()

    def __init__(self, indexName, type_of_doc, i_d, js):
        self.indexName = indexName
        self.i_d = i_d
        self.type_of_doc = type_of_doc
        self.js = js

def sendToES(esllog):
    es.index(index=esllog.indexName, doc_type=esllog.type_of_doc,
             id=esllog.i_d, body=json.loads(esllog.js))

es  = Elasticsearch([{'host': es_host, 'port': 9200}])
def checkhosts(namespace):
    query_body = {
      "aggs": {
        "2": {
          "terms": {
            "field": "ip.keyword",
            "order": {
              "_count": "desc"
            },
            "size": 500
          },
          "aggs": {
            "3": {
              "terms": {
                "field": "ports.port",
                "order": {
                  "_count": "desc"
                },
                "size": 5
              }
            }
          }
        }
      },
      "size": 0,
      "stored_fields": [
        "*"
      ],
      "script_fields": {},
      "docvalue_fields": [
        {
          "field": "timestamp",
          "format": "date_time"
        }
      ],
      "_source": {
        "excludes": []
      },
      "query": {
        "bool": {
          "must": [],
          "filter": [
            {
              "bool": {
                "should": [
                  {
                    "match_phrase": {
                      "namespace.keyword": namespace
                    }
                  }
                ],
                "minimum_should_match": 1
              }
            },
            {
              "range": {
                "timestamp": {
                  "gte": "now-1d",
                  "lte": "now",
                  "format": "strict_date_optional_time"
                }
              }
            }
          ],
          "should": [],
          "must_not": []
        }
      }
    }
    res = es.search(index="masscantopports", body=query_body)

    

    for bucket in res["aggregations"]["2"]["buckets"]:
        try:
            command = 'nmap -p22,443,8443,1434,2001,80,990,21,179,25 -Pn -sS ' + bucket["key"] + ' --script "(http* and safe),(ssl*),(discovery),(vuln)" --script-timeout 5 -oX /tmp/nmapoutput.xml'
            print(command)
            os.system(command)
            f = open("/tmp/nmapoutput.xml")
            xml_content = f.read()
            f.close()
            os.system('rm /tmp/nmapoutput.xml')
            data = xmltodict.parse(xml_content)

            host = data["nmaprun"]["host"]["address"]['@addr']
            
            for portdata in data["nmaprun"]["host"]['ports']['port']:
                
                if "script" in portdata:
                    for script in portdata["script"]:
                        if "@output" in script and "@id" in script:
                            print(script)
                            print(json.dumps(script))
                            scr = dict()
                            scr["timestamp"]= datetime.now(timezone.utc).isoformat()
                            scr["host"] = str(host)
                            scr["port"] = portdata["@portid"]
                            scr["protocol"] = portdata["@protocol"]
                            scr["name"] =  script["@id"]
                            scr["output"] =  script["@output"]
                            scr["namespace"] =  namespace
                            scr["script"] = json.dumps(script)
                            id = uuid.uuid1() 
                            es_log = esLog("nmapscripts", 'log', id , json.dumps(scr, default=str))
                            sendToES(es_log)
        except:
            donothing = ""


for namespace in namespaces:
    checkhosts(namespace)  
