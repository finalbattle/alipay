#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created: zhangpeng <zhangpeng1@infohold.com.cn>

from hashlib import md5
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

from os.path import abspath, dirname, join
base_path = abspath(dirname(__file__))
from code import interact

# 添加系统路径
from payutils.configure import CONFIG as CONFIGURATION
config_path = join(base_path, 'config', 'settings.yaml')
CONFIG = CONFIGURATION(config_path)
DEBUG = CONFIG("DEBUG")

from submit import RequestBuilder

CREATE_WAP_URL = "alipay.wap.trade.create.direct"

class WapBuilder(RequestBuilder):
    def __init__(self):
        super(WapBuilder, self).__init__()
        self.auth_params = {}
        self.pay_gate_way = "http://wappaygw.alipay.com/service/rest.htm"
    def get_sign_type(self, sign_type):
        return {
          "RSA": "0001",
          "MD5": "MD5"
        }[sign_type]
    def format_xml(self, payment_sn, price, subject, return_url, merchant_url, notify_url):
        xml = [
            """<direct_trade_create_req>""",
                """<subject>%s</subject>"""                         % subject,
                """<out_trade_no>%s</out_trade_no>"""               % payment_sn,
                """<total_fee>%s</total_fee>"""                     % price,
                """<seller_account_name>%s</seller_account_name>""" % self.seller_email,
                """<call_back_url>%s</call_back_url>"""             % return_url,
                """<notify_url>%s</notify_url>"""                   % notify_url,
                """<merchant_url>%s</merchant_url>"""               % merchant_url,
                """<pay_expire>3600</pay_expire>""",
            """</direct_trade_create_req>"""
        ]
        return "".join(xml)

    def create_wap_direct_url(self, payment_sn, price, subject, return_url="", merchant_url="", notify_url="", sign_type="RSA"):
        if notify_url == "":
            raise Exception(u"回调地址不能为空")
        req_data = self.format_xml(payment_sn, price, subject, return_url, merchant_url, notify_url)
        self.params["req_data"] = req_data
        self.params["service"] = "alipay.wap.trade.create.direct"
        self.params["sec_id"] = self.get_sign_type(sign_type)
        self.params["partner"] = self.partner_id
        self.params["format"] = "xml"
        self.params["v"] = "2.0"
        data = self.build_data(self.params, sign_type)
        return data

    def create_auth_url(self, payment_sn, price, subject, return_url="", merchant_url="", notify_url="", sign_type="MD5"):
        #return_url = CONFIG("ENV.RETURN_URL") % {"payment_sn":payment_sn, "myapp":return_url}
        try:
            print "alipay paystatus url:%s" % return_url
            data = self.create_wap_direct_url(payment_sn, price, subject, return_url, merchant_url, notify_url, sign_type)
            if DEBUG:
                pay_gate_way = "http://192.168.2.75:50011/service/rest.htm"
                response = self.send_request(pay_gate_way, forms=data, method="POST")
            else:
                response = self.send_request(self.pay_gate_way, forms=data, method="POST")
            result = simplejson.loads(self.parse_response(response))
            if result["return_code"] == 0:
                token = result["data"]["token"]
                print "token:%s" % token
                xml = "<auth_and_execute_req><request_token>%s</request_token></auth_and_execute_req>" % token
                self.auth_params["service"] = "alipay.wap.auth.authAndExecute"
                self.auth_params["partner"] = self.partner_id
                self.auth_params["sec_id"] = self.get_sign_type(sign_type)
                self.auth_params["req_data"] = xml
                #self.auth_params["request_token"] = token
                self.auth_params["format"] = "xml"
                self.auth_params["v"] = "2.0"
                request_data = self.build_data(self.auth_params, sign_type, urlencode=True)
                request_url = self.pay_gate_way + '?'+ request_data
                return simplejson.dumps({"return_code":0, "return_message":"success", "data":request_url})
                #return token
            return result
        except Exception as e:
            return simplejson.dumps({"return_code":-1, "return_message": e.__unicode__()})

    def send_request(self, url, args="", forms="", method="POST"):
        #forms = forms.encode("gb2312")
        headers = {"Connection":"Keep-alive"}
        request = HTTPRequest(url=url+"?"+args, method=method, body=forms, connect_timeout=10, request_timeout=30, headers=headers)
        print "request_url: %s" % request.url
        print "forms:%s" % forms
        httpclient = HTTPClient()
        response = httpclient.fetch(request)
        resData = response.body
        return resData
    def parse_response(self, body):
        import urllib2
        args = self.get_args(body)
        import re
        from lxml.etree import fromstring
        if "res_data" in args:
            res_data = urllib2.unquote(args.get("res_data", ""))
            xml = re.compile("<direct.*>$").search(res_data).group()
            doc = fromstring(xml)
            token = doc.find("request_token").text
            return simplejson.dumps({"return_code":0, "return_message":"success", "data":{"token":token}})
        if "res_error" in args:
            error_data = urllib2.unquote(args.get("res_error", ""))
            xml = re.compile("<err.*>$").search(error_data).group()
            doc = fromstring(xml)
            error_code = doc.find("code").text
            error_detail = doc.find("detail").text
            return simplejson.dumps({"return_code":error_code, "return_message":error_detail})
        return body

    def get_args(self, body):
        kwargs = dict()
        result = []
        querys = body.split('&')
        for query_str in querys:
            if not query_str:continue
            if '=' in query_str:
                key, value = query_str.split('=')
            else:
                key = query_str; value = u''
            kwargs[key] = value.decode("utf-8")
            #result.append((key, value.decode('utf-8', 'ignore')))
        return kwargs


    def build_data(self, params, sign_type='MD5', urlencode=False): 
        unsigned_data = '&'.join(["%s=%s" % (k,v) for k, v in sorted(params.items())])     #参数按照字母顺序排序
        unsigned_data += self.security_code
        sign = self.sign(unsigned_data, sign_type)
        params['sign'] = sign
        #self.params['sign_type'] = sign_type
        if urlencode == True:
            request_data = urllib.urlencode(params)
        else:
            request_data = "&".join(["%s=%s" % (k, v) for k, v in params.items()])
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

