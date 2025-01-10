package com.mildo.user;

import com.mildo.db.DBManger;
import com.mildo.study.Vo.EnterStudy;
import com.mildo.user.Vo.*;
import lombok.extern.slf4j.Slf4j;
import org.apache.ibatis.session.SqlSession;

import java.sql.Date;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
public class UserDBManger extends DBManger {

    public static UserVO findUser(String number) {
        log.info("AAA");
        SqlSession session = sqlSessionFactory.openSession();
        UserVO re = session.selectOne("User.findUser", number);
        session.commit();
        session.close();
        return re;
    }

    public static String findNullUserId() {
        SqlSession session = sqlSessionFactory.openSession();
        String userId = session.selectOne("User.findNullUserId");
        session.commit();
        session.close();
        return userId;
    }

    public static void saveUpdateUser(UserVO users) {
        SqlSession session = sqlSessionFactory.openSession();
        try{
            session.update("User.saveUpdateUser", users);
            session.commit();
        } catch (Exception e){
            e.printStackTrace();
            session.rollback();
        } finally {
            session.close();
        }
    }

    public static UserVO finduserId(String userId) {
        SqlSession session = sqlSessionFactory.openSession();
        UserVO user = session.selectOne("User.finduserId", userId);
        session.commit();
        session.close();
        return user;
    }

    public static TokenVO findToken(String userId) {
        SqlSession session = sqlSessionFactory.openSession();
        TokenVO findToken = session.selectOne("User.findToken", userId);
        session.commit();
        session.close();
        return findToken;
    }

    public static AccessVO findAccessToken(String userId) {
        SqlSession session = sqlSessionFactory.openSession();
        AccessVO findToken = session.selectOne("User.findAccessToken", userId);
        session.commit();
        session.close();
        return findToken;
    }

    public static void saveToken(TokenVO token) {
        SqlSession session = sqlSessionFactory.openSession();
        try{
            session.insert("User.saveToken", token);
            session.commit();
        } catch (Exception e){
            e.printStackTrace();
            session.rollback();
        } finally {
            session.close();
        }
    }

    public static void saveUpdateToken(TokenVO token) {
        SqlSession session = sqlSessionFactory.openSession();
        try{
            session.update("User.saveUpdateToken", token);
            session.commit();
        } catch (Exception e){
            e.printStackTrace();
            session.rollback();
        } finally {
            session.close();
        }
    }

    public static void updateNewToken (TokenVO token) {
        SqlSession session = sqlSessionFactory.openSession();
        session.update("User.updateNewToken", token);
        session.commit();
        session.close();
    }

    public static TokenVO findRefreshTokenByUserId (String RefreshToken) {
        SqlSession session = sqlSessionFactory.openSession();
        TokenVO Refresh = session.selectOne("User.findRefreshTokenByUserId", RefreshToken);
        session.commit();
        session.close();
        return Refresh;
    }

    public static List<LevelCountDTO> solvedLevelsList(String userId) {
        SqlSession session = sqlSessionFactory.openSession();
        List<LevelCountDTO> solvedLevels = session.selectList("User.solvedLevelsList", userId);
        session.commit();
        session.close();
        return solvedLevels;
    }

    public static void updateStudyId(EnterStudy enteStudy) {
        SqlSession session = sqlSessionFactory.openSession();
        try {
            session.update("User.updateStudyId", enteStudy);
            session.commit();
        } catch (Exception e) {
            e.printStackTrace();
            session.rollback();
        } finally {
            session.close();
        }
    }

    public static boolean checkExtensionSync(String userId, String studyId) {
        boolean isValid = false;
        SqlSession session = sqlSessionFactory.openSession();

        try {
            Map<String, Object> params = new HashMap<>();
            params.put("userId", userId);
            params.put("studyId", studyId);

            Integer count = session.selectOne("User.checkExtensionSync", params);

            if (count != null && count > 0) {
                isValid = true;
            }
        } finally {
            session.close();
        }
        return isValid;
    }

    public static int userIdDeleteCode(String userId) {
        SqlSession session = sqlSessionFactory.openSession();
        int res = session.update("User.userIdDeleteCode", userId);
        session.commit();
        session.close();
        return res;
    }

    public static int userIdDeleteComment(String userId) {
        SqlSession session = sqlSessionFactory.openSession();
        int res = session.update("User.userIdDeleteComment", userId);
        session.commit();
        session.close();
        return res;
    }

    public static int userIdChangNull(String userId) {
        SqlSession session = sqlSessionFactory.openSession();
        int res = session.update("User.userIdChangNull", userId);
        session.commit();
        session.close();
        return res;
    }

    public static int createStudy(String userId, String studyId, Date date) {
        SqlSession session = sqlSessionFactory.openSession();
        Map<String, Object> params = new HashMap<>();
        params.put("userId", userId);
        params.put("studyId", studyId);

        int res = session.update("User.createStudy", params);
        session.commit();
        session.close();
        return res;
    }

    public static int userServiceOut(String userId) {
        SqlSession session = sqlSessionFactory.openSession();
        int res = session.delete("User.userServiceOut", userId);
        session.commit();
        session.close();
        return res;
    }

    public static void saveBlackToken(BlackTokenVO black) {
        SqlSession session = sqlSessionFactory.openSession();
        session.insert("User.saveBlackToken", black);
        session.commit();
        session.close();
    }

    public static void tokenNull(String userId) {
        SqlSession session = sqlSessionFactory.openSession();
        session.update("User.tokenNull", userId);
        session.commit();
        session.close();
    }

    public static void blackrest(Timestamp timestamp) {
        SqlSession session = sqlSessionFactory.openSession();
        session.delete("User.blackrest", timestamp);
        session.commit();
        session.close();
    }

    public static BlackTokenVO checkBlackList(String token) {
        SqlSession session = sqlSessionFactory.openSession();
        BlackTokenVO res = session.selectOne("User.checkBlackList", token);
        session.commit();
        session.close();
        return res;
    }

    public static int changUserInfo(String userId, UserVO vo) {
        SqlSession session = sqlSessionFactory.openSession();
        Map<String, Object> params = new HashMap<>();
        params.put("userId", userId);
        params.put("userName", vo.getUserName());
        params.put("userTheme", vo.getUserTheme());
        int res = session.update("User.changUserInfo", params);
        session.commit();
        session.close();
        return res;
    }

    public static int changUserTheme(String userId, String userTheme) {
        SqlSession session = sqlSessionFactory.openSession();
        Map<String, Object> params = new HashMap<>();
        params.put("userId", userId);
        params.put("userTheme", userTheme);
        int res = session.update("User.changUserTheme", params);
        session.commit();
        session.close();
        return res;
    }

    public static int changUserName(String userId, String userName) {
        SqlSession session = sqlSessionFactory.openSession();
        Map<String, Object> params = new HashMap<>();
        params.put("userId", userId);
        params.put("userName", userName);
        int res = session.update("User.changUserName", params);
        session.commit();
        session.close();
        return res;
    }

    public static void solvedIncrement(String userId) {
        SqlSession session = sqlSessionFactory.openSession();
        session.update("User.solvedIncrement", userId);
        session.commit();
        session.close();
    }

    public static int createUserId(String userId) {
        int re = -1;
        SqlSession session = sqlSessionFactory.openSession();
        re = session.insert("User.createUserId",userId);
        session.commit();
        session.close();

        return re;
    }

}
