package com.kript;

import java.security.*;
import org.bouncycastle.util.encoders.Hex;
import java.util.Scanner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;

public class Main {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main(String[] args) throws Exception {
        System.out.println("RSA");
        Scanner in=new Scanner(System.in);
        Cipher cipher = Cipher.getInstance("RSA", "BC");
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(512, random);
        KeyPair pair = generator.generateKeyPair();
        Key pubKey = pair.getPublic();
        Key privKey = pair.getPrivate();
        System.out.println("Введите сообщение:");
        String sInput = in.nextLine();
        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
        byte[] cipherText = cipher.doFinal(sInput.getBytes());
        System.out.println("Зашифрованное сообщение - 0x" + new String(Hex.encode(cipherText)));
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("Расшифрованное сообщение - " + new
                String(plainText));
    }
}