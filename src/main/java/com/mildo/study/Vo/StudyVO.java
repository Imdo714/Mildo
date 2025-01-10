package com.mildo.study.Vo;

import lombok.Data;

import java.sql.Date;

@Data
public class StudyVO {
    private String studyId;            // 스터디 아이디
    private String studyName;       // 스터디 이름
    private String studyPassword;   // 스터디 비밀번호
    private Date studyStart;        // 스터디 시작일
    private Date studyEnd;          // 스터디 끝 나는 일

    public StudyVO(){}

}
