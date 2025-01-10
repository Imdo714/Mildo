package com.mildo.code;

import com.mildo.code.Vo.CodeVO;
import com.mildo.code.Vo.CommentVO;
import com.mildo.code.Vo.RecentVO;
import com.mildo.common.Page.PageInfo;
import com.mildo.common.Page.Pagenation;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class CodeService {

    private final CodeRepository codeRepository;

    public ArrayList<Map<String, String>> getSolvedByDaySelectedMonth(String userId, String month) {
        return codeRepository.getSolvedByDaySelectedMonth(userId, month);
    }

    public void codeUpload(UploadDTO request) throws ParseException {

        String id = request.getId();
        String filename = request.getFilename();
        filename = filename.substring(0, filename.length() - 5);
        String sourceText = request.getSourceText();
        String readmeText = request.getReadmeText();
        String dateInfo = request.getDateInfo();
        int problemId = Integer.parseInt(request.getProblemId());
        // "lv2" -> "2"로 변경 (자료형 유지를 위해 charAt 등과 같은 것을 사용하지 않음)
        String level = request.getLevel();

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        LocalDateTime date = LocalDateTime.parse(dateInfo, formatter);

        // TODO: 추가 로직 작성 필요(코드 아이디에 대한 의견 필요)
        // codeLikes 의 값이 Y / N 임.
        CodeVO vo = new CodeVO(id, filename, readmeText, sourceText, "N", level, problemId, 0, date);

        codeRepository.upload(vo);

    }

    public List<CommentVO> saveComment(int codeId, CommentVO comment) {
        int res = codeRepository.saveComment(comment);
        PageInfo pi = Pagenation.getPageInfo(codeRepository.commentCount(codeId), 1, 5, 5);
        return codeRepository.CommentList(codeId, pi);
    }

    public List<CodeVO> solvedListSearchTrue(String userId, String title, int currentPage, String category) {
        // userId가 존재하지 않는 아이디일 경우
        Integer listCount = codeRepository.totalSolved(userId);
        if(listCount == null)
            return null;

        // 리스트 페이지 별로 주는 메서드
        PageInfo pi = Pagenation.getPageInfo(listCount, currentPage, 5, 9);

        // 검색조건이 없고 레벨 순으로 주는 메서드
        if (title == null && "level".equals(category))
            return codeRepository.solvedListCategory(pi, userId);

        // 검색조건이 있고 레벨 순으로 주는 메서드
        if (title != null && "level".equals(category))
            return codeRepository.solvedSearchCategory(pi, userId, title);

        // 검색조건이 있고 최신 순으로 주는 메서드
        if (title != null)
            return codeRepository.solvedSerachList(pi, userId, title);

        return null;
    }

    public List<CodeVO> solvedListSearchFail(String userId, int currentPage, String category) {
        // userId가 존재하지 않는 아이디일 경우
        Integer listCount = codeRepository.totalSolved(userId);
        if(listCount == null)
            return null;
        // 리스트 페이지 별로 주는 메서드
        PageInfo pi = Pagenation.getPageInfo(listCount, currentPage, 5, 9);

        if ("level".equals(category))
            return codeRepository.solvedListCategory(pi, userId);

        return codeRepository.solvedList(pi, userId);
    }

    // codeId로 코드 조회
    public CodeVO detailCode(int codeId, String userId) {
        return codeRepository.detailCode(codeId, userId);
    }

    // 댓글 리스트
    public List<CommentVO> CommentList(int codeId, int currentPage) {
        PageInfo pi = Pagenation.getPageInfo(codeRepository.commentCount(codeId), currentPage, 5, 5);

        return codeRepository.CommentList(codeId, pi);
    }

    // 최근 활동 가져오기
    public List<RecentVO> getRecent(String studyId) {
        return codeRepository.getRecent(studyId);
    }

    // 댓글 수정
    public List<CommentVO> updateComment(CommentVO comment) {
        codeRepository.updateComment(comment);
        PageInfo pi = Pagenation.getPageInfo(codeRepository.commentCount(comment.getCodeId()), 1, 5, 5);
        return codeRepository.CommentList(comment.getCodeId(), pi);
    }

    // 댓글 삭제
    public List<CommentVO> deleteComment(int commentId, int codeId) {
        codeRepository.deleteComment(commentId);
        PageInfo pi = Pagenation.getPageInfo(codeRepository.commentCount(codeId), 1, 5, 5);
        return codeRepository.CommentList(codeId, pi);
    }

    public List<CodeVO> searchCode(String userId, CodeVO vo, int currentPage, String category) {
        PageInfo pi = Pagenation.getPageInfo(codeRepository.totalSolved(userId), currentPage, 5, 9);

        if ("level".equals(category))
            return codeRepository.solvedSearchCategory(pi, userId, vo.getCodeTitle());

        return codeRepository.solvedSerachList(pi, userId, vo.getCodeTitle());
    }

}
