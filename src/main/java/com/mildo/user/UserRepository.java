package com.mildo.user;


import com.mildo.study.Vo.EnterStudy;
import com.mildo.user.Vo.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Date;
import java.sql.Timestamp;
import java.util.List;

@Slf4j
@Repository
@RequiredArgsConstructor
public class UserRepository {

    public UserVO findUser(String number) {return UserDBManger.findUser(number);}

    public String findNullUserId(){
        return UserDBManger.findNullUserId();
    }

    public void saveUpdateUser(UserVO users) {
        UserDBManger.saveUpdateUser(users);
    }

    public UserVO finduserId(String userId){
        return UserDBManger.finduserId(userId);
    }

    public TokenVO findToken(String userId){
        return UserDBManger.findToken(userId);
    }

    public AccessVO findAccessToken(String userId){return UserDBManger.findAccessToken(userId);}

    public void saveToken(TokenVO token){UserDBManger.saveToken(token);}

    public void saveUpdateToken(TokenVO token){
        UserDBManger.saveUpdateToken(token);
    }

    public void updateNewToken(TokenVO token){UserDBManger.updateNewToken(token);}

    public TokenVO findRefreshTokenByUserId(String RefreshToken){
        return UserDBManger.findRefreshTokenByUserId(RefreshToken);
    }

    public List<LevelCountDTO> solvedLevelsList(String userId){
         return UserDBManger.solvedLevelsList(userId);
    }

    public void updateStudyId(EnterStudy enteStudy) {
        UserDBManger.updateStudyId(enteStudy);
    }

    public boolean checkExtensionSync(String userId, String studyId) {
        return UserDBManger.checkExtensionSync(userId,studyId);
    }

    @Transactional(rollbackFor = Exception.class)
    public int studyGetOut(String userId) {
        int result = 0;
        try {
            int result2 = UserDBManger.userIdDeleteComment(userId);
            int result3 = UserDBManger.userIdDeleteCode(userId);
            result = UserDBManger.userIdChangNull(userId);
        } catch (Exception e) {
            return 0;
        }
        return result;
    }

    public void createStudy(String userId, String studyId, Date date) {UserDBManger.createStudy(userId, studyId, date);}

    public int serviceOut(String userId) {
        return UserDBManger.userServiceOut(userId);
    }

    public void saveBlackToken(BlackTokenVO black) {
         UserDBManger.saveBlackToken(black);
    }

    public void tokenNull(String userId) {
        UserDBManger.tokenNull(userId);
    }

    public void blackrest(Timestamp timestamp) {
        UserDBManger.blackrest(timestamp);
    }

    public BlackTokenVO checkBlackList(String token) {
        return  UserDBManger.checkBlackList(token);
    }

    public int changUserInfo(String userId, UserVO vo) {
        return UserDBManger.changUserInfo(userId, vo);
    }

    public int changUserTheme(String userId, String userTheme) {return UserDBManger.changUserTheme(userId, userTheme);}

    public int changUserName(String userId, String userName) {
        return UserDBManger.changUserName(userId, userName);
    }

    public int createUserId(String userId) {
        return UserDBManger.createUserId(userId);
    }

}
