package com.mildo.study;

import com.mildo.study.Vo.EnterStudy;
import com.mildo.study.Vo.RemainingDaysDTO;
import com.mildo.study.Vo.StudyVO;
import lombok.extern.slf4j.Slf4j;
import org.apache.ibatis.session.SqlSession;

import com.mildo.db.DBManger;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
public class StudyDBManger extends DBManger {

    public static int create(StudyVO s) {
        int re = -1;
        SqlSession session = sqlSessionFactory.openSession();
        re = session.update("Study.create", s);
        session.commit();
        session.close();
        return re;
    }

    public static List<StudyVO> studyList(String studyId) {
        SqlSession session = sqlSessionFactory.openSession();
        List<StudyVO> list = session.selectList("Study.studyList", studyId);
        session.commit();
        session.close();

        return list;
    }

    public static int totalMembers(String studyId) {
        SqlSession session = sqlSessionFactory.openSession();
        int totalMembers = session.selectOne("Study.totalMembers", studyId);
        session.commit();
        session.close();

        return totalMembers;
    }

    public static RemainingDaysDTO studyDays(String studyId) {
        SqlSession session = sqlSessionFactory.openSession();
        RemainingDaysDTO studyDays = session.selectOne("Study.studyDays", studyId);
        session.commit();
        session.close();

        return studyDays;
    }

    public static RemainingDaysDTO studyDaysRe(String studyId) {
        SqlSession session = sqlSessionFactory.openSession();
        RemainingDaysDTO studyDaysRe = session.selectOne("Study.studyDaysRe", studyId);
        session.commit();
        session.close();

        return studyDaysRe;
    }

    public static List<StudyVO> totalrank(String studyId) {
        SqlSession session = sqlSessionFactory.openSession();
        List<StudyVO> totalrank = session.selectList("Study.totalrank", studyId);
        session.commit();
        session.close();

        return totalrank;
    }

    public static String getStartMonth(String studyId){
        SqlSession session = sqlSessionFactory.openSession();
        String getStartMonth = session.selectOne("Study.getStartMonth", studyId);
        session.commit();
        session.close();
        return getStartMonth;

    }


    public static List<String> getStudyMemberByMonth(String studyId, String month, String subDate) {
        List<String> names;
        SqlSession session = sqlSessionFactory.openSession();

        try {
            Map<String, Object> params = new HashMap<>();
            params.put("study_Id", studyId);
            params.put("month", month);
            params.put("subDate", subDate);

            names = session.selectList("Study.getStudyMemberByMonth", params);
        } finally {
            session.close();
        }
        return names;
    }

    public static List<String> getStudyMemberIdByMonth(String studyId, String month, String subDate) {
        List<String> names;

        SqlSession session = sqlSessionFactory.openSession();
        try {
            Map<String, Object> params = new HashMap<>();
            params.put("study_Id", studyId);
            params.put("month", month);
            params.put("subDate", subDate);

            names = session.selectList("Study.getStudyMemberIdByMonth", params);
        } finally {
            session.close();
        }

        log.info(names + " : 가지고 나오는 names");

        return names;
    }

    public static boolean checkstudyIdPassword(EnterStudy enteStudy) {
        boolean isValid = false;
        SqlSession session = sqlSessionFactory.openSession();

        try {
            Integer count = session.selectOne("Study.checkstudyIdPassword", enteStudy);

            if (count != null && count > 0) {
                isValid = true;
            }
        } finally {
            session.close(); // 세션 닫기
        }
        return isValid; // 유효 여부 반환
    }

    public static int  updateStudyName(String studyId, String studyName) {
        SqlSession session = sqlSessionFactory.openSession();
        Map<String, Object> params = new HashMap<>();
        params.put("study_Id", studyId);
        params.put("study_Name", studyName);
        int rowsAffected = session.update("Study.updateStudyName", params);
        session.commit();
        session.close();
        return rowsAffected;
    }

    public static int updateLeader(String studyId, String newLeaderId) {
        SqlSession session = sqlSessionFactory.openSession();
        Map<String, Object> params = new HashMap<>();
        params.put("new_Leader_Id", newLeaderId);
        params.put("study_Id", studyId);
        int rowsAffected = session.update("Study.updateLeader", params);
        session.commit();
        session.close();
        return rowsAffected;
    }

    public static int deleteStudy(String studyId) {
        SqlSession session = sqlSessionFactory.openSession();

        int rowsAffected = session.update("Study.deleteStudy", studyId);
        if(rowsAffected == 0)   // 해당 스터디가 존재하지 않을 경우 삭제되지 않음
            return rowsAffected;

        session.commit();
        session.close();
        return rowsAffected;
    }

    public static int deleteStudyUser(String studyId) {
        SqlSession session = sqlSessionFactory.openSession();
        int rowsAffected = session.update("Study.deleteStudyUser", studyId);
        session.commit();
        session.close();
        return rowsAffected;
    }

    public static int deleteStudyCode(String studyId) {
        SqlSession session = sqlSessionFactory.openSession();
        int rowsAffected = session.delete("Study.deleteStudyCode", studyId);
        session.commit();
        session.close();
        return rowsAffected;
    }

    public static int deleteStudyComment(String studyId) {
        SqlSession session = sqlSessionFactory.openSession();
        int rowsAffected = session.delete("Study.deleteStudyComment", studyId);
        session.commit();
        session.close();
        return rowsAffected;
    }

    public static StudyVO findStudyNo(int studyNo) {
        SqlSession session = sqlSessionFactory.openSession();
        StudyVO study = session.selectOne("Study.findStudyNo", studyNo);
        session.commit();
        session.close();

        return study;
    }

    public static int findStudyNextNo() {
        SqlSession session = sqlSessionFactory.openSession();
        int studyNo = session.selectOne("Study.findStudyNextNo");
        session.commit();
        session.close();
        return studyNo;
    }

    public static int createStudyId(String studyId) {
        int re = -1;
        SqlSession session = sqlSessionFactory.openSession();
        re = session.insert("Study.createStudyId",studyId);
        session.commit();
        session.close();

        return re;
    }

    public static String findNullStudyId() {
        SqlSession session = sqlSessionFactory.openSession();
        String studyId = session.selectOne("Study.findNullStudyId");
        session.commit();
        session.close();
        return studyId;
    }

    public static void saveStudy(StudyVO studyVo) {
        SqlSession session = sqlSessionFactory.openSession();
        session.update("Study.saveStudy", studyVo);
        session.commit();
        session.close();
    }

    public static String getStudyName(String studyId) {
        SqlSession session = sqlSessionFactory.openSession();
        String studyName = session.selectOne("Study.getStudyName", studyId);
        session.commit();
        session.close();

        return studyName;
    }

    public static String subDate(String studyId) {
        SqlSession session = sqlSessionFactory.openSession();
        String studyName = session.selectOne("Study.subDate", studyId);
        session.commit();
        session.close();

        return studyName;
    }

}
