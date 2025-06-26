/**
 * 对公众平台发送给公众账号的消息加解密示例代码.
 *
 * @copyright Copyright (c) 1998-2014 Tencent Inc.
 */

// ------------------------------------------------------------------------

/**
 * 针对org.apache.commons.codec.binary.Base64，
 * 需要导入架包commons-codec-1.9（或commons-codec-1.8等其他版本）
 * 官方下载地址：http://commons.apache.org/proper/commons-codec/download_codec.cgi
 */
package com.beemo.demos.controller;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Base64;


/**
 * 提供接收和推送给公众平台消息的加解密接口(UTF8编码的字符串).
 * <ol>
 * 	<li>第三方回复加密消息给公众平台</li>
 * 	<li>第三方收到公众平台发送的消息，验证消息的安全性，并对消息进行解密。</li>
 * </ol>
 * 说明：异常java.security.InvalidKeyException:illegal Key Size的解决方案
 * <ol>
 * 	<li>在官方网站下载JCE无限制权限策略文件（JDK7的下载地址：
 *      http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html</li>
 * 	<li>下载后解压，可以看到local_policy.jar和US_export_policy.jar以及readme.txt</li>
 * 	<li>如果安装了JRE，将两个jar文件放到%JRE_HOME%\lib\security目录下覆盖原来的文件</li>
 * 	<li>如果安装了JDK，将两个jar文件放到%JDK_HOME%\jre\lib\security目录下覆盖原来文件</li>
 * </ol>
 */
public class WXBizMsgCrypt {

  static Charset CHARSET = Charset.forName("utf-8");
  private final byte[] aesKey;

  public WXBizMsgCrypt(String aesKey) {
    this.aesKey = Base64.getDecoder().decode(aesKey + "=");
  }

  public

    // 还原4个字节的网络字节序
  int recoverNetworkBytesOrder(byte[] orderBytes) {
    int sourceNumber = 0;
    for (int i = 0; i < 4; i++) {
      sourceNumber <<= 8;
      sourceNumber |= orderBytes[i] & 0xff;
    }
    return sourceNumber;
  }

  /**
   * 对密文进行解密.
   *
   * @param text 需要解密的密文
   * @return 解密得到的明文
   */
  public String decrypt(String text) {
    byte[] original;
    try {
      // 设置解密模式为AES的CBC模式
      Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
      SecretKeySpec key_spec = new SecretKeySpec(aesKey, "AES");
      IvParameterSpec iv = new IvParameterSpec(Arrays.copyOfRange(aesKey, 0, 16));
      cipher.init(Cipher.DECRYPT_MODE, key_spec, iv);

      // 使用BASE64对密文进行解码

      byte[] encrypted = Base64.getDecoder().decode(text);

      // 解密
      original = cipher.doFinal(encrypted);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RuntimeException();
    }

    String xmlContent, from_appid;
    try {
      // 去除补位字符
      byte[] bytes = PKCS7Encoder.decode(original);

      // 分离16位随机字符串,网络字节序和AppId
      byte[] networkOrder = Arrays.copyOfRange(bytes, 16, 20);

      int xmlLength = recoverNetworkBytesOrder(networkOrder);

      xmlContent = new String(Arrays.copyOfRange(bytes, 20, 20 + xmlLength), CHARSET);
      from_appid = new String(Arrays.copyOfRange(bytes, 20 + xmlLength, bytes.length),
          CHARSET);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RuntimeException(e);
    }

    return xmlContent;
  }
}