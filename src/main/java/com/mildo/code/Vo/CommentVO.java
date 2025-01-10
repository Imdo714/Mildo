package com.mildo.code.Vo;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;

import java.sql.Date;
import java.sql.Timestamp;

@Data
public class CommentVO {

    private int commentId;          // 댓글 아이디
    private int codeId;             // 코드 아이디
    private String userId;          // 회원 아이디 ex) #G090
    private String commentContent;  // 댓글 내용
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
    private Timestamp commentDate;     // 댓글 작성 날짜
    private String userName;

    public CommentVO(){}

    public CommentVO(int commentId, int codeId, String userId, String commentContent, Timestamp commentDate, String userName) {
        this.commentId = commentId;
        this.codeId = codeId;
        this.userId = userId;
        this.commentContent = commentContent;
        this.commentDate = commentDate;
        this.userName = userName;
    }
}
