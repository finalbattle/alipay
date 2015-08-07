#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created: zhangpeng <zhangpeng1@infohold.com.cn>

from hashlib import md5
import hashlib
import urllib
import datetime
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

#print CONFIG("RSA.ALIPAY.PUBLIC_KEY")

class RequestBuilder(object):
    def __init__(self):
        self.partner_id = "2088411976138217"
        self.params = {}
        self.pay_gate_way = 'https://www.alipay.com/cooperate/gateway.do'
        self.security_code = "f3pw1wx04l8tj607ph58d43mc9fgxr3z"         #支付宝安全码
        self.payment_type = 1
        self.seller_email = "payment@infohold.com.cn"
        #self.notify_url = "http://182.48.115.38/alipay/notify"
  
    def create_url(self,
                  payment_sn,
                  price,
                  quantity,
                  subject,
                  body="",
                  return_url="",
                  discount=0,
                  service="trade_create_by_buyer",
                  input_charset="utf-8",
                  sign_type="MD5",
                  logistics_type="EMS",
                  logistics_fee=0,
                  logistics_payment="BUYER_PAY",
                  pay_timeout="",
                  notify_url="",
                 ):
        if notify_url == "":
            raise Exception(u"回调地址不能为空")
        self.params['service'] = service
        self.params['out_trade_no'] = payment_sn
        self.params['partner'] = self.partner_id
        self.params['notify_url'] = notify_url
        if discount != 0:
            self.params['discount'] = discount
        self.params['quantity'] = quantity
        self.params['payment_type'] = self.payment_type 
        if body != "":
            self.params['body'] = body
        self.params['price'] = price
        self.params['seller_email'] = self.seller_email
        self.params['return_url'] = return_url
        self.params['logistics_type'] = logistics_type
        self.params['logistics_fee'] = logistics_fee
        self.params['subject'] = subject
        self.params['logistics_payment'] = logistics_payment
        self.params['_input_charset'] = input_charset
        if pay_timeout != "":
            self.params['it_b_pay'] = pay_timeout
        return self.build_url(self.params, sign_type)

    def create_direct_url(self,
                  payment_sn,
                  price,
                  quantity,
                  subject,
                  body="",
                  return_url="",
                  discount=0,
                  service="create_direct_pay_by_user",
                  input_charset="utf-8",
                  sign_type="MD5",
                  logistics_type="EMS",
                  logistics_fee=0,
                  logistics_payment="BUYER_PAY",
                  pay_timeout="",
                  notify_url="",
                 ):
        if notify_url == "":
            raise Exception(u"回调地址不能为空")
        self.params['service'] = service
        self.params['out_trade_no'] = payment_sn
        self.params['partner'] = self.partner_id
        self.params['notify_url'] = notify_url
        if discount != 0:
            self.params['discount'] = discount
        self.params['quantity'] = quantity
        self.params['payment_type'] = self.payment_type 
        if body != "":
            self.params['body'] = body
        self.params['total_fee'] = price
        self.params['seller_email'] = self.seller_email
        self.params['return_url'] = return_url
        self.params['logistics_type'] = logistics_type
        self.params['logistics_fee'] = logistics_fee
        self.params['subject'] = subject
        self.params['logistics_payment'] = logistics_payment
        self.params['_input_charset'] = input_charset
        return self.build_url(self.params, sign_type)

    def create_securitypay_string(self,
                  payment_sn,
                  price,
                  quantity,
                  subject="smallpay",
                  body="smallpay",
                  show_url="",
                  discount=0,
                  input_charset="utf-8",
                  pay_timeout="30m",
                  sign_type="RSA",
                  logistics_type="EMS",
                  logistics_fee=0,
                  logistics_payment="BUYER_PAY",
                  notify_url="",
                 ):
        if notify_url == "":
            raise Exception(u"回调地址不能为空")
        self.params['partner'] = self.partner_id
        self.params['service'] = "mobile.securitypay.pay"
        self.params['seller_id'] = self.seller_email
        self.params['out_trade_no'] = payment_sn
        self.params['subject'] = subject
        self.params['body'] = body
        self.params['total_fee'] = "%.2f" % price
        self.params['notify_url'] = notify_url
        if show_url != "":
            self.params['show_url'] = show_url
        self.params['payment_type'] = self.payment_type 
        self.params['_input_charset'] = input_charset
        self.params['it_b_pay'] = pay_timeout
        import urllib2
        request_data = '&'.join(['%s="%s"' % (k,urllib2.quote(str(v).encode('utf-8'), "@")) for k, v in sorted(self.params.items())])    #参数按照字母顺序排序
        unsigned_data = request_data# + self.security_code
        sign = self.sign(unsigned_data, sign_type)
        self.params['sign'] = sign
        self.params['sign_type'] = sign_type
        request_data = request_data + '&sign="%s"&sign_type="%s"' % (urllib2.quote(sign, ""), sign_type)
        return request_data
        #return self.build_data(self.params, sign_type)


    def build_data(self, params, sign_type='MD5'): 
        unsigned_data = '&'.join(["%s=%s" % (k,v) for k, v in sorted(params.items())])     #参数按照字母顺序排序
        unsigned_data += self.security_code
        sign = self.sign(unsigned_data, sign_type)
        self.params['sign'] = sign
        self.params['sign_type'] = sign_type
        request_data = urllib.urlencode(self.params)
        return request_data

    def build_url(self, params, sign_type='MD5'): 
        request_data = self.build_data(params, sign_type)
        request_url = self.pay_gate_way + '?'+ request_data
        return request_url

    def sign(self,urlstr,sign_type="MD5"):
        if sign_type == 'MD5':
            m = hashlib.md5()
            m.update(urlstr)
            sign =  m.hexdigest()
        if sign_type == 'RSA':
            private_key = CONFIG("RSA.SERVICE.PRIVATE_KEY")
            public_key = CONFIG("RSA.SERVICE.PUBLIC_KEY")
            key = RSA.importKey(private_key)
            h = SHA.new(urlstr)
            signer = PKCS1_v1_5.new(key)
            signature = signer.sign(h)
            sign = base64.b64encode(signature)
        if sign_type == "":
            sign = ''
        return sign
    def verifySign(self, urlstr, sign_type="MD5", sign=""):
        if sign_type == "MD5":
            body = urlstr + "f3pw1wx04l8tj607ph58d43mc9fgxr3z"
            sign_str = hashlib.md5(body.encode("utf-8")).hexdigest()
            return sign_str == sign
        else:
            public_key = CONFIG("RSA.ALIPAY.PUBLIC_KEY")
            key = RSA.importKey(public_key)
            h = SHA.new(urlstr)
            verifier = PKCS1_v1_5.new(key)
            verify_sign = verifier.verify(h, base64.b64decode(sign))
            return verify_sign
