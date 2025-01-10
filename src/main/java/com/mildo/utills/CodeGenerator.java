package com.mildo.utills;

import java.util.Random;

public class CodeGenerator {

    private static final Random RANDOM = new Random();
    private static final String[] password = {
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
            "A", "B", "C", "D", "E", "F", "G", "H", "I", "J",
            "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T",
            "U", "V", "W", "X", "Y", "Z"
    };

    public static String generatestudyId(int codeLength) {
        //01 배열은 0~9 와 알파벳으로 구성되어있고, 랜덤으로 배열을 뽑아 5자리로 구성됩니다
        StringBuilder codeBuilder = new StringBuilder();
        for (int i = 0; i < codeLength; i++) {
            int index = RANDOM.nextInt(password.length);
            codeBuilder.append(password[index]);
        }
        return codeBuilder.toString();
    }

    public static String generatestudyId() {
        return generatestudyId(5);
    }

    public static String generateUserId() {

        //01 배열은 알파벳으로 구성되어있고, 랜덤으로 배열을 뽑아 6자리로 구성됩니다
        StringBuilder studyIdBuilder = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            int index = RANDOM.nextInt(10, password.length);
            studyIdBuilder.append(password[index]);
        }
        return studyIdBuilder.toString();
    }
}
