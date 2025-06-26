package com.beemo.demos.controller;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

public class WxBizMsgCrypt2 {
  private final byte[] aesKey;
  private final String token;
  private final String appId;

  public WxBizMsgCrypt2(String token, String encodingAesKey, String appId) throws Exception {
    if (encodingAesKey == null || encodingAesKey.length() != 43) {
      throw new IllegalArgumentException("EncodingAESKey长度需要为43位");
    }
    this.aesKey = Base64.getDecoder().decode(encodingAesKey + "=");
    this.token = token;
    this.appId = appId;
  }

  public String decryptMsg(String msgSignature, String timeStamp, String nonce, String encryptedMsg) throws Exception {
    if (!checkSignature(msgSignature, token, timeStamp, nonce, encryptedMsg)) {
      throw new Exception("签名验证失败");
    }

    Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
    SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
    IvParameterSpec iv = new IvParameterSpec(Arrays.copyOfRange(aesKey, 0, 16));
    cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);

    byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMsg);
    byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

    return parseDecryptedBytes(decryptedBytes);
  }

  private boolean checkSignature(String signature, String token, String timestamp, String nonce, String encrypt) {
    try {
      String[] arr = new String[]{token, timestamp, nonce, encrypt};
      Arrays.sort(arr);
      StringBuilder content = new StringBuilder();
      for (String s : arr) {
        content.append(s);
      }
      MessageDigest md = MessageDigest.getInstance("SHA-1");
      byte[] digest = md.digest(content.toString().getBytes(StandardCharsets.UTF_8));
      return byteToHex(digest).equals(signature);
    } catch (Exception e) {
      return false;
    }
  }

  private String byteToHex(final byte[] hash) {
    StringBuilder hexString = new StringBuilder();
    for (byte b : hash) {
      String hex = String.format("%02x", b);
      hexString.append(hex);
    }
    return hexString.toString();
  }

  private String parseDecryptedBytes(byte[] decrypted) {
    int pad = decrypted[decrypted.length - 1];
    byte[] bytes = Arrays.copyOfRange(decrypted, 16, decrypted.length - pad);

    byte[] lengthBytes = Arrays.copyOfRange(bytes, 0, 4);
    int msgLength = ((lengthBytes[0] & 0xFF) << 24) |
        ((lengthBytes[1] & 0xFF) << 16) |
        ((lengthBytes[2] & 0xFF) << 8) |
        (lengthBytes[3] & 0xFF);

    String message = new String(Arrays.copyOfRange(bytes, 4, 4 + msgLength), StandardCharsets.UTF_8);
    String fromAppId = new String(Arrays.copyOfRange(bytes, 4 + msgLength, bytes.length), StandardCharsets.UTF_8);

    if (!fromAppId.equals(appId)) {
      throw new RuntimeException("AppID不匹配: " + fromAppId + " != " + appId);
    }

    return message;
  }

  public String encryptMsg(String replyMsg, String timeStamp, String nonce) throws Exception {
    byte[] encrypted = encrypt(replyMsg, appId);
    String encryptedBase64 = Base64.getEncoder().encodeToString(encrypted);

    String signature = generateSignature(token, timeStamp, nonce, encryptedBase64);

    return String.format("<xml>" +
        "<Encrypt><![CDATA[%s]]></Encrypt>" +
        "<MsgSignature><![CDATA[%s]]></MsgSignature>" +
        "<TimeStamp>%s</TimeStamp>" +
        "<Nonce><![CDATA[%s]]></Nonce>" +
        "</xml>", encryptedBase64, signature, timeStamp, nonce);
  }

  private byte[] encrypt(String content, String appId) throws Exception {
    byte[] randomBytes = getRandomStr().getBytes(StandardCharsets.UTF_8);
    byte[] msgBytes = content.getBytes(StandardCharsets.UTF_8);
    byte[] appIdBytes = appId.getBytes(StandardCharsets.UTF_8);

    byte[] msgLength = intToBytes(msgBytes.length);

    int totalLength = randomBytes.length + msgLength.length + msgBytes.length + appIdBytes.length;
    byte[] padBytes = PKCS7Padding(totalLength);

    byte[] unencrypted = new byte[totalLength + padBytes.length];
    System.arraycopy(randomBytes, 0, unencrypted, 0, randomBytes.length);
    System.arraycopy(msgLength, 0, unencrypted, randomBytes.length, msgLength.length);
    System.arraycopy(msgBytes, 0, unencrypted, randomBytes.length + msgLength.length, msgBytes.length);
    System.arraycopy(appIdBytes, 0, unencrypted, randomBytes.length + msgLength.length + msgBytes.length, appIdBytes.length);
    System.arraycopy(padBytes, 0, unencrypted, totalLength, padBytes.length);

    Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
    SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
    IvParameterSpec iv = new IvParameterSpec(Arrays.copyOfRange(aesKey, 0, 16));
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);

    return cipher.doFinal(unencrypted);
  }

  private String generateSignature(String token, String timestamp, String nonce, String encrypt) {
    try {
      String[] arr = new String[]{token, timestamp, nonce, encrypt};
      Arrays.sort(arr);
      StringBuilder content = new StringBuilder();
      for (String s : arr) {
        content.append(s);
      }
      MessageDigest md = MessageDigest.getInstance("SHA-1");
      byte[] digest = md.digest(content.toString().getBytes(StandardCharsets.UTF_8));
      return byteToHex(digest);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private byte[] intToBytes(int value) {
    byte[] bytes = new byte[4];
    bytes[0] = (byte) ((value >> 24) & 0xFF);
    bytes[1] = (byte) ((value >> 16) & 0xFF);
    bytes[2] = (byte) ((value >> 8) & 0xFF);
    bytes[3] = (byte) (value & 0xFF);
    return bytes;
  }

  private byte[] PKCS7Padding(int sourceLength) {
    int blockSize = 32;
    int paddingSize = blockSize - (sourceLength % blockSize);
    byte padChr = (byte) paddingSize;
    byte[] paddingBytes = new byte[paddingSize];
    for (int i = 0; i < paddingSize; i++) {
      paddingBytes[i] = padChr;
    }
    return paddingBytes;
  }

  private String getRandomStr() {
    String base = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < 16; i++) {
      int randomInt = (int) (Math.random() * base.length());
      sb.append(base.charAt(randomInt));
    }
    return sb.toString();
  }

  public static void main(String[] args) {
    try {
      // http://118.196.24.18:8080/hello
      String token = "<TOKEN>";
      String encodingAesKey = "<ENCODING_AES_KEY>";
      String appId = "<APP_ID>";

      WxBizMsgCrypt2 crypt = new WxBizMsgCrypt2(token, encodingAesKey, appId);

      // 解密示例
      String encryptedMsg = "It6GP4u6K8cUaslou//oVr5p8f6u5dUeIeZivO3sDLVicaTnwAKodeq0tuIeql/gXpTtqqpv3WxC2V9P/6nsIw==";
      String msgSignature = "c844616df755bce677ae8750256aa4300b990a9f";
      String timeStamp = "1750873717";
      String nonce = "1750236075";

      String decryptedMsg = crypt.decryptMsg(msgSignature, timeStamp, nonce, encryptedMsg);
      System.out.println("解密后的消息: " + decryptedMsg);

      // 加密示例
      String replyMsg = "这是要回复的消息";
      String encryptedResult = crypt.encryptMsg(replyMsg, timeStamp, nonce);
      System.out.println("加密后的消息: " + encryptedResult);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
