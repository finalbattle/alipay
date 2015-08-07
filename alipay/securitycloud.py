#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created: zhangpeng <zhangpeng1@infohold.com.cn>

from hashlib import md5
import logging
import hashlib
import urllib
import datetime
import simplejson
from lxml.etree import fromstring
from tornado.httpclient import HTTPRequest, HTTPClient

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
import base64

logging.basicConfig(
    format='%(asctime)s %(module)s %(levelname)s: %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p',
    level=logging.DEBUG,
    disable_existing_loggers=False
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.NOTSET)

from os.path import abspath, dirname, join
base_path = abspath(dirname(__file__))
from code import interact

# 添加系统路径
from payutils.configure import CONFIG as CONFIGURATION
config_path = join(base_path, 'config', 'settings.yaml')
CONFIG = CONFIGURATION(config_path)
DEBUG = CONFIG("DEBUG")

from submit import RequestBuilder

CREATE_SECURITYCLOUD_ID = "alipay.security.risk.detect"

class SecurityCloudBuilder(RequestBuilder):
    def __init__(self):
        super(SecurityCloudBuilder, self).__init__()
        self.auth_params = {}
        if DEBUG == True:
            self.pay_gate_way = "https://mapi.alipay.com/gateway.do"
        else:
            self.pay_gate_way = "https://mapi.alipay.com/gateway.do"

    def create_securitycloud_url(self,
                              order_no,
                              order_create_time,
                              order_item_name,
                              order_category,
                              order_amount,
                              buyer_account_no,
                              buyer_reg_date,
                              scene_code="PAYMENT",
                              terminal_type="WEB",
                              return_url="",
                              notify_url="",
                              sign_type="MD5",
                              _input_charset="gbk"
                             ):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.params["service"] = CREATE_SECURITYCLOUD_ID
        self.params["partner"] = self.partner_id
        #self.params["sign_type"] = sign_type
        self.params["_input_charset"] = _input_charset
        self.params["timestamp"] = timestamp
        self.params["terminal_type"] = terminal_type
        self.params["order_no"] = order_no
        self.params["order_credate_time"] = order_create_time
        self.params["order_item_name"] = order_item_name
        self.params["order_category"] = order_category
        self.params["order_amount"] = order_amount
        self.params["scene_code"] = scene_code
        self.params["buyer_account_no"] = buyer_account_no
        self.params["buyer_reg_date"] = buyer_reg_date
        if return_url != "":
            self.params["return_url"] = return_url
        if notify_url != "":
            self.params["notify_url"] = notify_url
        data = self.build_data(self.params, sign_type)
        #return data
        response = self.send_request(self.pay_gate_way, forms=data, method="POST")
        print response
        return response
        #result = simplejson.loads(self.parse_response(response))
        #return result

    def send_request(self, url, args="", forms="", method="POST"):
        #forms = forms.encode("gb2312")
        headers = {"Connection":"Keep-alive"}
        request = HTTPRequest(url=url+"?"+args, method=method, body=forms, connect_timeout=10, request_timeout=30, headers=headers)
        logger.debug("request_url: %s" % request.url)
        logger.debug("args:%s" % args)
        logger.debug("forms:%s" % forms)
        httpclient = HTTPClient()
        response = httpclient.fetch(request)
        resData = response.body
        return resData
    def parse_response(self, body):
        risk_dict = {
            "100001": "传输的信息含风险名单",
            "100002": "传输的信息存在批量嫌疑",
            "100003": "传输的设备信息存在风险",
            "100004": "传输的交易信息存在风险",
            "000000": "传输的信息无风险",
            "000001": "本次服务无法识别,风险不确定",
        }
        import urllib2
        import re
        from lxml.etree import fromstring
        doc = fromstring(body)
        result = doc.find("is_success").text.strip()
        return_code = True if result == "T" else False
        if return_code == True:
            risk_code = doc.find("response/alipay.security.risk.detect/risk_code").text.strip()
            risk_level = doc.find("response/alipay.security.risk.detect/risk_level").text.strip()
            risk_message = risk_dict.get(risk_code, "")
            return simplejson.dumps({"return_code":0,
                                 "return_message":"success",
                                 "data":{"risk_message":risk_message,
                                         "risk_code":risk_code,
                                         "risk_level":risk_level}})
        else:
            error_message = doc.find("error").text.strip()
            return simplejson.dumps({"return_code":-1, "return_message":error_message, "data":{}})

    def build_data(self, params, sign_type='MD5', urlencode=False): 
        unsigned_data = '&'.join(["%s=%s" % (k,v) for k, v in sorted(params.items())])     #参数按照字母顺序排序
        unsigned_data += self.security_code
        print "unsigned_data:", unsigned_data
        print
        sign = self.sign(unsigned_data, sign_type)
        params['sign'] = sign
        #self.params['sign_type'] = sign_type
        if urlencode == True:
            request_data = urllib.urlencode(params)
        else:
            request_data = "&".join(["%s=%s" % (k, v) for k, v in sorted(params.items())])
            import urllib2
            request_data = urllib2.quote(request_data, "@=&")
        return request_data
    def verifySign(self, urlstr, sign_type="MD5", sign=""):
        urlstr = urlstr + self.security_code
        sign_str = hashlib.md5(urlstr).hexdigest()
        return sign_str == sign
    def parseXML(self, notify_xml):
        result = {}
        xml_doc = fromstring(str(notify_xml))
        for doc in xml_doc.getchildren():
            result[doc.tag] = doc.text
        return result


if __name__ == "__main__":
    builder = SecurityCloudBuilder()
    print builder.create_securitycloud_url("20140926000001", "2014-09-26 10:30:00", "smallpay", "数码^手机^iphone", 0.01, "10003", "2014-09-01", notify_url="http://10.13.63.172:8080/alipay.security.risk.detect/notify_url.php", sign_type="MD5")
    print
