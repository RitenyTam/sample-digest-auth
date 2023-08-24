package com.riteny;

import org.apache.commons.codec.digest.DigestUtils;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class Sample {

    public static void main(String[] args) throws IOException {

        String requestMethod = "<RequestMethod>";
        String username = "<username>";
        String password = "<password>";
        String requestUri = "<Request uri : sample /api/login >";

        URL authRequest = new URL("<Request url>");
        HttpURLConnection conn = (HttpURLConnection) authRequest.openConnection();
        conn.setRequestMethod(requestMethod);

        //直接調用一次讓接口生成摘要認證需要使用的認證信息
        String wwwAuthenticate = conn.getHeaderField("WWW-Authenticate");
        String[] wwwAuthenticateTemp = wwwAuthenticate.split(",");
        Map<String, String> wwwAuthenticateMap = new HashMap<>();
        for (String s : wwwAuthenticateTemp) {
            String[] temp = s.split("=");
            wwwAuthenticateMap.put(temp[0].trim().replace("\"", ""), temp[1].trim().replace("\"", ""));
        }

        String qop = wwwAuthenticateMap.get("qop");
        String digestRealm = wwwAuthenticateMap.get("Digest realm");
        String nonce = wwwAuthenticateMap.get("nonce");
        String algorithm = wwwAuthenticateMap.get("algorithm");

        String clientNonce = UUID.randomUUID().toString().replace("-", "");
        String ha1 = DigestUtils.md5Hex(username + ":" + digestRealm + ":" + password);

        /*
         * 如果 qop 值为auth或未指定，ha2 = MD5(method : digestURI）
         * 如果 qop 值为auth-int，ha2 = MD5(method : digestURI :MD5(entityBody))
         *
         * 如果 qop 值为auth或auth-int，那么 response = MD5(ha1 : nonce : nonceCount : clientNonce : qop :ha2)
         * 如果 qop 末指定，那么 response = MD5(HA1 :nonce : HA2)
         *
         * 我所測試的接口qop為auth，并未能測試其他情況，所以下面就以qop=auth來開發測試
         */
        String ha2 = DigestUtils.md5Hex(requestMethod + ":" + requestUri);
        String response = DigestUtils.md5Hex(ha1 + ":" + nonce + ":00000001:" + clientNonce + ":" + qop + ":" + ha2);


        String authorization = "Digest username=\"" + username + "\", realm=\"" + digestRealm
                + "\", nonce=\"" + nonce + "\", uri=\"" + requestUri + "\", algorithm=\"" + algorithm + "\""
                + ", qop=" + qop + ",nc=00000001, cnonce=\"" + clientNonce + "\", response=\"" + response + "\", opaque=\"";

        /*
         * 計算好驗證數據后，使用這側驗證數據重新調用接口
         */
        URL request = new URL("<Request url>");
        HttpURLConnection conn2 = (HttpURLConnection) request.openConnection();
        conn2.setRequestMethod(requestMethod);
        conn2.setRequestProperty("Authorization", authorization);

        InputStream inputStream;
        if (conn2.getResponseCode() == 200) {
            /*
             * 假如你需要用到長連接，在這裏動一下手脚就行
             * 寫個while循環，不斷讀取流裏面的内容
             */
            inputStream = conn2.getInputStream();
        } else {
            inputStream = conn2.getErrorStream();
        }

        byte[] b = new byte[inputStream.available()];
        inputStream.read(b);

        System.out.println(new String(b));
    }
}
