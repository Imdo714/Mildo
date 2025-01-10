package com.mildo.db;

import org.apache.ibatis.io.Resources;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;

import java.io.InputStream;

public class DBManger {

    public static SqlSessionFactory sqlSessionFactory;

    static {
        try {
            String resource = "mapper/sqlMapConfig.xml";
            InputStream inputStream = Resources.getResourceAsStream(resource);
            sqlSessionFactory = new SqlSessionFactoryBuilder().build(inputStream);
            inputStream.close();
        } catch (Exception e) {
            System.out.println("예외발생 DBManager :"+e.getMessage());
        }
    }

}
