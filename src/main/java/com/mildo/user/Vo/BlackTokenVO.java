package com.mildo.user.Vo;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;

import java.sql.Timestamp;

@Data
public class BlackTokenVO {

    private String blackToken;
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
    private Timestamp expirationTime;

    public BlackTokenVO(){}

    public BlackTokenVO(String blackToken, Timestamp expirationTime) {
        this.blackToken = blackToken;
        this.expirationTime = expirationTime;
    }
}
