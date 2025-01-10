package com.mildo.user.Vo;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;

import java.sql.Timestamp;

@Data
public class AccessVO {

    private String accessToken;
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
    private Timestamp expirationTime;

    public AccessVO(String accessToken, Timestamp expirationTime) {
        this.accessToken = accessToken;
        this.expirationTime = expirationTime;
    }

}
