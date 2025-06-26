package com.beemo.demos.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.MessageDigest;
import java.util.Arrays;

@RestController
public class TestController {

  @Value("${beemo.token}")
  private String token;
  @Value("${beemo.encoding-aes-key}")
  private String encodingAesKey;

  private static final Logger LOGGER = LoggerFactory.getLogger(TestController.class);

  @GetMapping("/hello")
  public String hello(@RequestParam("msg_signature") String signature,
      @RequestParam("timestamp") String timestamp,
      @RequestParam("nonce") String nonce,
      @RequestParam("echostr") String echostr) throws Exception {
    LOGGER.info("signature: {}, timeStamp: {}, nonce: {}, echoStr: {}", signature, timestamp, nonce,
        echostr);

    String[] params = { token, timestamp, nonce, echostr };
    Arrays.sort(params);
    StringBuilder sb = new StringBuilder();
    for (String param : params) {
      sb.append(param);
    }
    String strToSign = sb.toString();

    LOGGER.info("拼接后的字符串3:{}", strToSign);

    // 3. 计算 SHA1 签名
    String sha1Signature = sha1(strToSign);
    LOGGER.info("签名:{}", sha1Signature);

    String decrypt = new WXBizMsgCrypt(encodingAesKey).decrypt(echostr);
    LOGGER.info("解密后的结果：{}", decrypt);
//    8095792507794521981
    return decrypt;
  }
//
//  @GetMapping("/demo")
//  public String demo(@RequestParam("msg_signature") String signature,
//      @RequestParam("timestamp") String timestamp,
//      @RequestParam("nonce") String nonce,
//      @RequestParam("echostr") String echostr) throws Exception {
//    LOGGER.info("signature: {}, timeStamp: {}, nonce: {}, echoStr: {}", signature, timestamp, nonce,
//        echostr);
//
//    String s = new WxBizMsgCrypt2(token, aesKey,
//        token)
//        .decryptMsg(signature, timestamp, nonce, echostr);
//    LOGGER.info("解密结果：{}", s);
//    return s;
//  }

  // SHA1 加密工具方法
  private String sha1(String str) throws Exception {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-1");
      byte[] hash = digest.digest(str.getBytes("UTF-8"));
      StringBuilder hexString = new StringBuilder();
      for (byte b : hash) {
        String hex = Integer.toHexString(0xff & b);
        if (hex.length() == 1) hexString.append('0');
        hexString.append(hex);
      }
      return hexString.toString();
    } catch (Exception e) {
      e.printStackTrace();
      return "";
    }
  }
}
