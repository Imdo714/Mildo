package com.mildo.user.Vo;

import lombok.Data;

import java.sql.Date;

@Data
public class UserVO {

    private String userId;              // 회원 아이디 ex) #G090
    private String studyId;             // 스터디 아이디
    private int userNo;             // 사용자 번호
    private String userName;            // 사용자 이름
    private String userGoogleId;        // 구글 아이디
    private String userEmail;           // 이메일
    private String userParticipant;     // 스터디 참가여부
    private String userLeader;          // 리더 여부
    private int userSolvedProblem;      // 해결 문제 수
    private String userTheme;           // 유저 테마
    private Date userDate;              // 회원가입 날짜

    public UserVO(){}

    public UserVO(String userId, String studyId, int userNo, String userName, String userGoogleId, String userEmail, String userParticipant, String userLeader, int userSolvedProblem, String userTheme, Date userDate) {
        this.userId = userId;
        this.studyId = studyId;
        this.userNo = userNo;
        this.userName = userName;
        this.userGoogleId = userGoogleId;
        this.userEmail = userEmail;
        this.userParticipant = userParticipant;
        this.userLeader = userLeader;
        this.userSolvedProblem = userSolvedProblem;
        this.userTheme = userTheme;
        this.userDate = userDate;
    }
}
