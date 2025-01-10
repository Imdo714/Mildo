package com.mildo.code;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mildo.code.Vo.CodeVO;
import com.mildo.code.Vo.CommentVO;
import com.mildo.code.Vo.RecentVO;
import com.mildo.user.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.text.ParseException;
import java.util.List;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/code")
public class CodeController {

    private final CodeService codeService;
    private final UserService userService;

    //연동하기 버튼으로 스터디와 아이디 확인
    // ResponseEntity로 서로 응답 상호작용
    @CrossOrigin(origins = "chrome-extension://kmleenknngfkjncchnbfenfamoighddf")
    @PostMapping("/receive-sync")
    public ResponseEntity<String> receiveSync(@RequestBody String data) {
        try {
            /* 연동하기 눌렀을 때 ID, 와 STUDYCODE 확인 후, 연동하는 작업 */
            ObjectMapper sync = new ObjectMapper();
            JsonNode convertSync = sync.readTree(data);
            if (validateUserStudySync(convertSync)) {
                return ResponseEntity.ok("success");
            } else {
                return ResponseEntity.ok("fail");
            }
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error occurred while processing the request");
        }
    }

    @CrossOrigin(origins = {"chrome-extension://kmleenknngfkjncchnbfenfamoighddf", "https://school.programmers.co.kr"})
    @PostMapping("/receive-data")
    public ResponseEntity<String> receiveData(@RequestBody String data) {
        try {

            /* 파싱된 데이터를 옮기는 작업*/
            ObjectMapper Data = new ObjectMapper();
            JsonNode convertData = Data.readTree(data);

            if (validateUserStudySync(convertData)) {
                return ResponseEntity.ok("success");
            } else {
                return ResponseEntity.ok("fail");
            }
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error occurred while processing the request");
        }
    }

    private boolean validateUserStudySync(JsonNode convertData) {
        // 필요한 정보 추출
        String userId = convertData.get("id").asText();
        String studyId = convertData.get("studyId").asText();

        System.out.println("id" + userId);
        System.out.println("studyId" + studyId);

        return userService.checkExtensionSync(userId, studyId);
    }

    @CrossOrigin(origins = "chrome-extension://kmleenknngfkjncchnbfenfamoighddf")
    @RequestMapping(method = RequestMethod.POST, value = "/upload")
    public ResponseEntity<String> upload(@RequestBody UploadDTO request) throws ParseException {

        codeService.codeUpload(request);
        return ResponseEntity.ok("Upload successful");
    }

    // userId로 푼 문제 리스트 조회 | 요청 방법:/api/%23G909/solvedList
    @ResponseBody
    @GetMapping(value = "/{userId}/solvedList", produces = "application/json; charset=UTF-8")
    public ResponseEntity<?> solvedListId(@PathVariable String userId,
                                          @RequestParam(value = "title", required = false) String title,
                                          @RequestParam(value = "cpage", defaultValue = "1") int currentPage,
                                          @RequestParam(value = "category", defaultValue = "recent") String category) {

        if (title != null) { // 검색 조건이 있을 때
            List<CodeVO> res = codeService.solvedListSearchTrue(userId, title, currentPage, category);
            return res != null ? ResponseEntity.ok(res) : ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("검색 실패");
        } else {
            List<CodeVO> res = codeService.solvedListSearchFail(userId, currentPage, category);
            return res != null ? ResponseEntity.ok(res) : ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("검색 실패");
        }
    }

    @ResponseBody // 상세 코드 페이지
    @GetMapping(value = "/{userId}/{codeId}/getCodeByProblemId", produces = "application/json; charset=UTF-8")
    public ResponseEntity<CodeVO> getCodeByProblemId(@PathVariable int codeId, @PathVariable String userId) {
        return ResponseEntity.ok(codeService.detailCode(codeId, userId));
    }

    @ResponseBody
    @GetMapping(value = "/{studyId}/getRecent", produces = "application/json; charset=UTF-8")
    public ResponseEntity<List<RecentVO>> recent(@PathVariable String studyId) {
        List<RecentVO> list = codeService.getRecent(studyId);
        return ResponseEntity.ok(list);
    }

    // FIXME: PathVariable 부분의 값들을 활용하지 않음
    // 따라서 경로상에서도 지우거나, VO 객체의 값을 null 로 입력받아, 해당 데이터를 활용하는 방향은 어떨지 고민이 필요

    @ResponseBody // 댓글 리스트
    @GetMapping(value = "/{userId}/{codeId}/getCommentList", produces = "application/json; charset=UTF-8")
    public ResponseEntity<List<CommentVO>> getCommentList(@PathVariable int codeId, @PathVariable String userId,
                                                          @RequestParam(value = "cpage", defaultValue = "1") int currentPage) {
        List<CommentVO> list = codeService.CommentList(codeId, currentPage);
        return ResponseEntity.ok(list);
    }

    @ResponseBody // 댓글 작성
    @PostMapping(value = "/{codeId}/comment", produces = "application/json; charset=UTF-8")
    public ResponseEntity<List<CommentVO>> comment(@PathVariable int codeId, @RequestBody CommentVO comment) {
        List<CommentVO> res = codeService.saveComment(codeId, comment);
        return ResponseEntity.ok(res);
    }

    @ResponseBody // 댓글 수정
    @PutMapping(value = "/{commentId}/commentUpdate", produces = "application/json; charset=UTF-8")
    public ResponseEntity<List<CommentVO>> commentUpdate(@PathVariable int commentId, @RequestBody CommentVO comment) {
        List<CommentVO> res = codeService.updateComment(comment);
        return ResponseEntity.ok(res);
    }

    @ResponseBody // 댓글 삭제
    @DeleteMapping(value = "/{codeId}/commentDelete", produces = "application/json; charset=UTF-8")
    public ResponseEntity<List<CommentVO>> commentDelete(@PathVariable int codeId,
                                                         @RequestParam(value = "comment", required = false) int commentId) {
        List<CommentVO> res = codeService.deleteComment(commentId, codeId);
        return ResponseEntity.ok(res);
    }

}