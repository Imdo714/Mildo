package com.mildo.code;

import com.mildo.code.Vo.CodeVO;
import com.mildo.code.Vo.CommentVO;
import com.mildo.code.Vo.RecentVO;
import com.mildo.common.Page.PageInfo;
import com.mildo.db.DBManger;
import lombok.extern.slf4j.Slf4j;
import org.apache.ibatis.session.RowBounds;
import org.apache.ibatis.session.SqlSession;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
public class CodeDBManger extends DBManger {

    public static ArrayList<Map<String, String>> getSolvedByDaySelectedMonth(String userId, String month) {
        ArrayList<Map<String, String>> results = new ArrayList<>();
        SqlSession session = sqlSessionFactory.openSession();

        try {
            Map<String, Object> params = new HashMap<>();
            params.put("user_id", userId);
            params.put("month", month);

            List<Map<String, String>> rows = session.selectList("code.getSolvedByDaySelectedMonth", params);
            session.close();
            for (Map<String, String> row : rows) {
                results.add(row);
            }
        } finally {
            session.close();
        }

        return results;
    }

    public static int saveComment(CommentVO comment) {
        SqlSession session = sqlSessionFactory.openSession();
        int re = session.insert("code.saveComment", comment);
        session.commit();
        session.close();

        return re;
    }

    // 문제 푼 총 수량
    public static Integer totalSolved(String userId) {
        SqlSession session = sqlSessionFactory.openSession();
        Integer totalSolved = session.selectOne("code.totalSolved", userId);
        session.commit();
        session.close();
        return totalSolved;
    }

    // 문재 리스트
    public static List<CodeVO> solvedList(PageInfo pi, String userId) {
        SqlSession session = sqlSessionFactory.openSession();

        int offset = (pi.getCurrentPage() - 1) * pi.getBoardLimit();
        int limit = pi.getBoardLimit();
        RowBounds rowBounds = new RowBounds(offset, limit);

        List<CodeVO> solvedList = session.selectList("code.solvedList", userId, rowBounds);

        session.commit();
        session.close();
        return solvedList;
    }

    // 문재 리스트
    public static List<CodeVO> solvedListCategory(PageInfo pi, String userId) {
        SqlSession session = sqlSessionFactory.openSession();
        int offset = (pi.getCurrentPage() - 1) * pi.getBoardLimit();
        int limit = pi.getBoardLimit();
        RowBounds rowBounds = new RowBounds(offset, limit);
        List<CodeVO> solvedList = session.selectList("code.solvedListCategory", userId, rowBounds);

        session.commit();
        session.close();
        return solvedList;
    }

    // codeId로 코드 조회
    public static CodeVO detailCode(int codeId, String userId) {
        SqlSession session = sqlSessionFactory.openSession();
        Map<String, Object> params = new HashMap<>();
        params.put("userId", userId);
        params.put("codeId", codeId);
        CodeVO code = session.selectOne("code.detailCode", params);
        session.commit();
        session.close();
        return code;
    }

    public static int commentCount(int codeId) {
        SqlSession session = sqlSessionFactory.openSession();
        int res = session.selectOne("code.commentCount", codeId);
        session.commit();
        session.close();
        return res;
    }

    public static List<CommentVO> CommentList(int codeId, PageInfo pi) {
        SqlSession session = sqlSessionFactory.openSession();

        int offset = (pi.getCurrentPage() - 1) * pi.getBoardLimit();
        int limit = pi.getBoardLimit();
        RowBounds rowBounds = new RowBounds(offset, limit);

        List<CommentVO> code = session.selectList("code.CommentList", codeId, rowBounds);
        session.commit();
        session.close();
        return code;
    }

    public static List<RecentVO> getRecent(String studyId) {
        SqlSession session = sqlSessionFactory.openSession();
        List<RecentVO> list = session.selectList("code.getRecent", studyId);
        session.commit();
        session.close();
        return list;
    }

    public static int updateComment(CommentVO comment) {
        SqlSession session = sqlSessionFactory.openSession();
        int res = session.update("code.updateComment", comment);
        session.commit();
        session.close();
        return res;
    }

    public static int deleteComment(int commentId) {
        SqlSession session = sqlSessionFactory.openSession();
        int res = session.delete("code.deleteComment", commentId);
        session.commit();
        session.close();
        return res;
    }


    public static void upload(CodeVO vo) {
        SqlSession session = sqlSessionFactory.openSession();
        int res = session.insert("code.upload", vo);
        session.commit();
        session.close();
    }

    // 문재 리스트
    public static List<CodeVO> solvedSerachList(PageInfo pi, String userId, String codeTitle) {
        SqlSession session = sqlSessionFactory.openSession();

        Map<String, Object> params = new HashMap<>();
        params.put("userId", userId);
        params.put("codeTitle", codeTitle);

        int offset = (pi.getCurrentPage() - 1) * pi.getBoardLimit();
        int limit = pi.getBoardLimit();
        RowBounds rowBounds = new RowBounds(offset, limit);

        List<CodeVO> solvedList = session.selectList("code.solvedSerachList", params, rowBounds);

        session.commit();
        session.close();
        return solvedList;
    }

    // 문재 리스트
    public static List<CodeVO> solvedSearchCategory(PageInfo pi, String userId, String codeTitle) {
        SqlSession session = sqlSessionFactory.openSession();
        Map<String, Object> params = new HashMap<>();
        params.put("userId", userId);
        params.put("codeTitle", codeTitle);

        int offset = (pi.getCurrentPage() - 1) * pi.getBoardLimit();
        int limit = pi.getBoardLimit();
        RowBounds rowBounds = new RowBounds(offset, limit);
        List<CodeVO> solvedList = session.selectList("code.solvedSearchCategory", params, rowBounds);
        log.info("solvedList = {}", solvedList);
        session.commit();
        session.close();
        return solvedList;
    }
}
