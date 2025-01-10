package com.mildo.code.Vo;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;

import java.sql.Timestamp;

@Data
public class RecentVO {

    private String userName;
    private String userId;
    private String codeTitle;
    private int codeProblemid;
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
    private Timestamp codeSolveDate;
    private Long minutesAgo;

    public RecentVO(){}
}
