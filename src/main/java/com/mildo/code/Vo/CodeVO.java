package com.mildo.code.Vo;

import lombok.Data;

import java.time.LocalDateTime;

@Data
public class CodeVO {

    private int codeId;             // 코드 아이디
    private String userId;          // 회원 아이디 ex) #G090
    private String codeTitle;       // 코드 제목
    private String codeReadme;      // 코드 설명
    private String codeSource;      // 코드 소스
    private String codeLikes;       // 코드 즐겨찾기
    private String codeLevel;       // 코드 레벨
    private int codeProblemId;      // 코드 번호
    private int codeSolvedTime;     // 코드 푼 시간
    private LocalDateTime codeSolveDate;

    public CodeVO(){}

    public CodeVO(int codeId, String userId, String codeTitle, String codeReadme, String codeSource, String codeLikes, String codeLevel, int codeProblemId, int codeSolvedTime, LocalDateTime codeSolveDate) {
        this.codeId = codeId;
        this.userId = userId;
        this.codeTitle = codeTitle;
        this.codeReadme = codeReadme;
        this.codeSource = codeSource;
        this.codeLikes = codeLikes;
        this.codeLevel = codeLevel;
        this.codeProblemId = codeProblemId;
        this.codeSolvedTime = codeSolvedTime;
        this.codeSolveDate = codeSolveDate;
    }

    public CodeVO(String userId, String codeTitle, String codeReadme, String codeSource, String codeLikes, String codeLevel, int codeProblemId, int codeSolvedTime, LocalDateTime codeSolveDate) {
        this.userId = userId;
        this.codeTitle = codeTitle;
        this.codeReadme = codeReadme;
        this.codeSource = codeSource;
        this.codeLikes = codeLikes;
        this.codeLevel = codeLevel;
        this.codeProblemId = codeProblemId;
        this.codeSolvedTime = codeSolvedTime;
        this.codeSolveDate = codeSolveDate;
    }
}
